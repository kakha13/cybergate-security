<?php
/**
 * Early upload guard: installation, configuration, status and spool import.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * The guard (guard/guard.php) runs through PHP's auto_prepend_file before any
 * other code, so it also holds uploads sent to scripts outside WordPress. This
 * class writes its bootstrap and config, explains how to switch it on for the
 * server type, and imports what it held (the spool) into pending items.
 *
 * Files:
 *   ABSPATH/wpcybersec-guard.php      bootstrap that auto_prepend_file points to
 *   <data>/guard/config.php           config (Guard_Config)
 *   <data>/guard/allow.php            approved hashes (Allowlist::export_guard_file)
 *   <data>/quarantine/guard/YYYY/MM/  held copies (named by content)
 *   <data>/spool/guard-uploads.jsonl  one JSON line per held upload
 *   <data>/spool/guard-uploads.work.jsonl + .pos  lines taken out of the spool
 *                                     and the import position, so a request
 *                                     that dies while importing loses nothing
 */
class Guard_Manager {

	const INSTALLED_OPTION = 'wpcybersec_guard_installed';
	const CHAIN_OPTION     = 'wpcybersec_guard_chain';
	const BOOTSTRAP_FILE   = 'wpcybersec-guard.php';
	const IMPORT_HOOK      = 'wpcybersec_guard_import';
	const SCHEDULE         = 'wpcybersec_ten_minutes';
	const MARKER           = 'WP Cyber Security Guard';

	/** Lines imported per cron run, and its time budget (seconds); the rest waits for the next run. */
	const IMPORT_BATCH   = 200;
	const IMPORT_SECONDS = 20;

	/** Lines imported on an administrator's admin page load, and its time budget. */
	const ADMIN_BATCH   = 5;
	const ADMIN_SECONDS = 3;

	/** Unfinished tries of one line after which it is imported without the signature scan. */
	const SCAN_TRIES = 2;

	/** Tries of one line before it is given up (database errors, or imports that keep dying). */
	const MAX_ATTEMPTS = 6;

	/**
	 * Nothing heavy here; see register().
	 */
	public function __construct() {}

	/**
	 * Hooks.
	 */
	public function register() {
		add_filter( 'cron_schedules', array( $this, 'cron_schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval
		add_action( self::IMPORT_HOOK, array( $this, 'cron_import' ) );
		add_action( 'admin_init', array( $this, 'admin_init' ) );
		add_action( 'wpcybersec_settings_updated', array( $this, 'on_settings_updated' ), 10, 0 );
		add_action( 'wpcybersec_allowlist_changed', array( $this, 'on_allowlist_changed' ), 10, 0 );

		// Uploads the guard held are imported by cron and on administrators' admin
		// pages only, never in the uploader's own (possibly anonymous) request, so
		// nobody can make the site scan files on demand.

		// Re-enable (or keep disabled) the config on boot, in admin and cron requests only.
		if ( is_admin() || wp_doing_cron() ) {
			$this->maintain();
		}
	}

	/**
	 * @param array $schedules Schedules.
	 * @return array
	 */
	public function cron_schedules( $schedules ) {
		if ( is_array( $schedules ) && ! isset( $schedules[ self::SCHEDULE ] ) ) {
			$schedules[ self::SCHEDULE ] = array(
				'interval' => 10 * MINUTE_IN_SECONDS,
				'display'  => __( 'Every 10 minutes (WP Cyber Security)', 'wp-cyber-security' ),
			);
		}
		return $schedules;
	}

	/**
	 * admin_init: small bounded import for administrators (so held uploads show
	 * up on the Reports page right away) and self-healing of the bootstrap.
	 * admin_init also runs for anonymous admin-ajax.php requests, which must not
	 * be able to trigger signature scans.
	 */
	public function admin_init() {
		if ( current_user_can( 'manage_options' ) && $this->has_pending() ) {
			$this->import_spool( self::ADMIN_BATCH, self::ADMIN_SECONDS, true );
		}
		if ( $this->is_installed() ) {
			$this->ensure_cron();
			$this->heal_bootstrap();
		}
	}

	/**
	 * Settings changed: rewrite the config when the guard is in use.
	 */
	public function on_settings_updated() {
		if ( $this->is_installed() || is_file( Guard_Config::file() ) ) {
			$this->sync_config();
		}
	}

	/**
	 * Allowlist changed: Allowlist already re-exported allow.php; make sure a
	 * config exists for an installed guard.
	 */
	public function on_allowlist_changed() {
		if ( $this->is_installed() && ! is_file( Guard_Config::file() ) ) {
			$this->sync_config();
		}
	}

	/**
	 * Keeps the config's enabled flag equal to "installed" and the paths current.
	 */
	private function maintain() {
		$installed = $this->is_installed();
		$current   = Guard_Config::read();
		if ( ! $installed ) {
			// Plugin activation re-enables any existing config; an uninstalled guard stays off.
			if ( $current && ! empty( $current['enabled'] ) ) {
				Guard_Config::set_enabled( false );
			}
			return;
		}
		$wanted = $this->config_array();
		$keys   = array( 'enabled', 'action', 'quarantine_dir', 'spool_file', 'allow_file', 'exempt', 'max_bytes', 'max_spool_bytes', 'max_quarantine_files', 'max_quarantine_bytes', 'min_free_bytes', 'exec_extensions', 'exec_filenames', 'home_path', 'login_cookie', 'root' );
		foreach ( $keys as $key ) {
			if ( ! array_key_exists( $key, $current ) || $current[ $key ] !== $wanted[ $key ] ) {
				$this->sync_config();
				break;
			}
		}
		if ( ! is_file( Guard_Config::allow_file() ) ) {
			wpcybersec()->allowlist->export_guard_file();
		}
	}

	/* ------------------------------------------------------------------ */
	/* Install / uninstall                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * @return string Absolute path of the bootstrap file.
	 */
	public function bootstrap_path() {
		return wp_normalize_path( ABSPATH . self::BOOTSTRAP_FILE );
	}

	/**
	 * @return string Absolute path of guard/guard.php.
	 */
	public function guard_file() {
		return wp_normalize_path( WPCYBERSEC_DIR . 'guard/guard.php' );
	}

	/**
	 * @return string Spool file.
	 */
	public function spool_file() {
		return wpcybersec()->storage->spool_dir() . '/guard-uploads.jsonl';
	}

	/**
	 * @return string Folder for copies held by the guard.
	 */
	public function quarantine_dir() {
		return wpcybersec()->storage->quarantine_dir() . '/guard';
	}

	/**
	 * @return bool
	 */
	public function is_installed() {
		return (bool) get_option( self::INSTALLED_OPTION, false );
	}

	/**
	 * Config written for the guard, from the settings.
	 *
	 * @return array
	 */
	public function config_array() {
		$settings = wpcybersec()->settings;
		$root     = realpath( ABSPATH );
		$exempt   = array_values( array_filter( array_map( 'strval', (array) $settings->get( 'guard_exempt', array() ) ), 'strlen' ) );

		/**
		 * Filters the largest upload the guard keeps a copy of (bytes).
		 *
		 * @param int $bytes Default 256 MB.
		 */
		$max_bytes = (int) apply_filters( 'wpcybersec_guard_max_bytes', 256 * MB_IN_BYTES );

		/**
		 * Filters how many held copies the guard quarantine may contain. Uploads
		 * beyond it are refused without a copy until held items are reviewed.
		 *
		 * @param int $files Default 500.
		 */
		$max_files = (int) apply_filters( 'wpcybersec_guard_max_quarantine_files', 500 );

		/**
		 * Filters the total size of the guard quarantine (bytes).
		 *
		 * @param int $bytes Default 512 MB.
		 */
		$max_total = (int) apply_filters( 'wpcybersec_guard_max_quarantine_bytes', 512 * MB_IN_BYTES );

		/**
		 * Filters the free disk space the guard leaves untouched (bytes).
		 *
		 * @param int $bytes Default 64 MB.
		 */
		$min_free = (int) apply_filters( 'wpcybersec_guard_min_free_bytes', 64 * MB_IN_BYTES );

		$home_path = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );

		return array(
			'enabled'              => $this->is_installed(),
			'action'               => 'strip' === $settings->get( 'guard_action', 'block' ) ? 'strip' : 'block',
			'quarantine_dir'       => $this->quarantine_dir(),
			'spool_file'           => $this->spool_file(),
			'allow_file'           => Guard_Config::allow_file(),
			'exempt'               => $exempt,
			'max_bytes'            => max( MB_IN_BYTES, $max_bytes ),
			'max_spool_bytes'      => 20 * MB_IN_BYTES,
			'max_quarantine_files' => max( 10, $max_files ),
			'max_quarantine_bytes' => max( 16 * MB_IN_BYTES, $max_total ),
			'min_free_bytes'       => max( 1, $min_free ),
			// Same lists as Paths::is_executable(), so approvals mean the same in the guard.
			'exec_extensions'      => self::lower_list( $settings->get( 'exec_extensions', array() ) ),
			'exec_filenames'       => self::lower_list( $settings->get( 'exec_filenames', array() ) ),
			'home_path'            => untrailingslashit( wp_normalize_path( $home_path ) ),
			'login_cookie'         => defined( 'LOGGED_IN_COOKIE' ) ? (string) LOGGED_IN_COOKIE : '',
			'message'              => __( 'This upload is waiting for administrator approval (WP Cyber Security). After approval, send it again and it will go through.', 'wp-cyber-security' ),
			'message_refused'      => __( 'This upload was refused because it could not be checked (WP Cyber Security). Please contact the site administrator.', 'wp-cyber-security' ),
			'root'                 => trailingslashit( wp_normalize_path( $root ? $root : ABSPATH ) ),
		);
	}

	/**
	 * @param mixed $list List setting.
	 * @return string[] Lowercase, unique, non-empty.
	 */
	private static function lower_list( $list ) {
		$out = array();
		foreach ( (array) $list as $value ) {
			if ( is_scalar( $value ) && '' !== trim( (string) $value ) ) {
				$out[] = strtolower( trim( (string) $value ) );
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Writes the config from the current settings.
	 *
	 * @return bool
	 */
	public function sync_config() {
		$this->ensure_dirs();
		return Guard_Config::write( $this->config_array() );
	}

	/**
	 * PHP code of the bootstrap file.
	 *
	 * @param string|null $guard_file  guard.php path (default: this plugin's).
	 * @param string|null $config_file Config path (default: Guard_Config::file()).
	 * @param string|null $chain       Another prepend file to include first ('' for none, null for the saved one).
	 * @return string
	 */
	public function bootstrap_code( $guard_file = null, $config_file = null, $chain = null ) {
		$guard_file  = null === $guard_file ? $this->guard_file() : (string) $guard_file;
		$config_file = null === $config_file ? Guard_Config::file() : (string) $config_file;
		$chain       = null === $chain ? (string) get_option( self::CHAIN_OPTION, '' ) : (string) $chain;
		return self::build_bootstrap( $guard_file, $config_file, $chain );
	}

	/**
	 * Builds the bootstrap source. Pure function (no WordPress calls), PHP 5.6 syntax.
	 *
	 * @param string $guard_file  guard.php path.
	 * @param string $config_file Config path.
	 * @param string $chain       Other prepend file to include as well, or ''.
	 * @return string
	 */
	public static function build_bootstrap( $guard_file, $config_file, $chain = '' ) {
		$guard  = var_export( (string) $guard_file, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		$config = var_export( (string) $config_file, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions

		$code  = "<?php\n";
		$code .= "/**\n";
		$code .= " * WP Cyber Security - early upload guard bootstrap.\n";
		$code .= " *\n";
		$code .= " * PHP runs this file before every request because auto_prepend_file points to it\n";
		$code .= " * (set in .user.ini, .htaccess, the PHP-FPM pool, the nginx config or php.ini).\n";
		$code .= " * It loads the guard that holds uploaded files until an administrator approves\n";
		$code .= " * them under Cyber Security > Reports in WordPress.\n";
		$code .= " *\n";
		$code .= " * To remove the guard safely:\n";
		$code .= " *   1. Remove the auto_prepend_file line from where it was added.\n";
		$code .= " *   2. Wait until PHP no longer uses it (.user.ini changes can take up to\n";
		$code .= " *      user_ini.cache_ttl seconds, 5 minutes by default) or reload PHP.\n";
		$code .= " *   3. Delete this file.\n";
		$code .= " * Deleting this file while auto_prepend_file still points to it breaks every\n";
		$code .= " * PHP request on the site. If the plugin is removed, this file does nothing.\n";
		$code .= " *\n";
		$code .= " * Generated by WP Cyber Security. Changes are overwritten.\n";
		$code .= " */\n";
		$code .= "if ( ! defined( 'WPCYBERSEC_GUARD_BOOTSTRAPPED' ) ) {\n";
		$code .= "\tdefine( 'WPCYBERSEC_GUARD_BOOTSTRAPPED', true );\n";
		if ( '' !== $chain ) {
			$other = var_export( (string) $chain, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
			$code .= "\t// Another prepend file that was in place before; keeps it running.\n";
			$code .= "\tif ( @file_exists( {$other} ) ) {\n";
			$code .= "\t\tinclude_once {$other};\n";
			$code .= "\t}\n";
		}
		$code .= "\tif ( @file_exists( {$guard} ) && @file_exists( {$config} ) ) {\n";
		$code .= "\t\tif ( ! defined( 'WPCYBERSEC_GUARD_CONFIG' ) ) {\n";
		$code .= "\t\t\tdefine( 'WPCYBERSEC_GUARD_CONFIG', {$config} );\n";
		$code .= "\t\t}\n";
		$code .= "\t\tinclude_once {$guard};\n";
		$code .= "\t}\n";
		$code .= "}\n";
		return $code;
	}

	/**
	 * Writes the config, the allow file and the bootstrap, and marks the guard installed.
	 * The administrator still has to point auto_prepend_file at the bootstrap (see snippets()).
	 *
	 * @return true|\WP_Error
	 */
	public function install() {
		$plugin  = wpcybersec();
		$ensured = $plugin->storage->ensure();
		if ( is_wp_error( $ensured ) ) {
			return $ensured;
		}
		$this->ensure_dirs();

		// Remember another prepend file (for example a firewall) so the bootstrap keeps it running.
		$conflict = $this->detect_conflict();
		if ( $conflict ) {
			update_option( self::CHAIN_OPTION, $conflict, false );
		}

		update_option( self::INSTALLED_OPTION, time(), false );
		if ( ! $this->sync_config() ) {
			delete_option( self::INSTALLED_OPTION );
			return new \WP_Error(
				'wpcybersec_guard_config',
				/* translators: %s: file path */
				sprintf( __( 'Could not write the guard config file %s. Check that the data folder is writable.', 'wp-cyber-security' ), Guard_Config::file() )
			);
		}
		$plugin->allowlist->export_guard_file();
		$this->ensure_cron();

		$written = $this->write_bootstrap();
		if ( is_wp_error( $written ) ) {
			$this->log( 'guard_install_failed', $written->get_error_message() );
			return $written;
		}

		$this->log(
			'guard_installed',
			/* translators: %s: file path */
			sprintf( __( 'Early upload guard installed. Point auto_prepend_file to %s to switch it on.', 'wp-cyber-security' ), $this->bootstrap_path() )
		);
		return true;
	}

	/**
	 * Switches the guard off. The bootstrap file is removed only when nothing
	 * points auto_prepend_file at it any more; otherwise it stays (it is harmless
	 * without a config) so PHP does not fail on every request.
	 *
	 * @param bool $keep_bootstrap Never delete the bootstrap (used right after an
	 *                             auto_prepend_file line was removed: PHP can keep
	 *                             a cached .user.ini for minutes).
	 * @return true
	 */
	public function uninstall( $keep_bootstrap = false ) {
		Guard_Config::set_enabled( false );
		delete_option( self::INSTALLED_OPTION );
		wp_clear_scheduled_hook( self::IMPORT_HOOK );

		// Import whatever is still waiting so nothing held is lost.
		$this->import_spool();

		$config = Guard_Config::file();
		if ( is_file( $config ) ) {
			@unlink( $config ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		$bootstrap = $this->bootstrap_path();
		if ( $keep_bootstrap && is_file( $bootstrap ) ) {
			$this->log(
				'guard_uninstalled',
				/* translators: %s: file path */
				sprintf( __( 'Early upload guard switched off. %s was kept because PHP can still load it for a few minutes; without the guard config it does nothing.', 'wp-cyber-security' ), $bootstrap )
			);
		} elseif ( is_file( $bootstrap ) && ! $this->bootstrap_referenced() ) {
			@unlink( $bootstrap ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$this->forget_file( $bootstrap );
			delete_option( self::CHAIN_OPTION );
			$this->log( 'guard_uninstalled', __( 'Early upload guard removed.', 'wp-cyber-security' ) );
		} else {
			$this->log(
				'guard_uninstalled',
				/* translators: %s: file path */
				sprintf( __( 'Early upload guard switched off. auto_prepend_file still points to %s, so the file was kept. Remove the auto_prepend_file line first, then delete the file.', 'wp-cyber-security' ), $bootstrap )
			);
		}
		return true;
	}

	/**
	 * Writes the bootstrap file atomically when its content changed.
	 *
	 * @return true|\WP_Error
	 */
	private function write_bootstrap() {
		$path = $this->bootstrap_path();
		$code = $this->bootstrap_code();
		if ( is_file( $path ) && (string) @file_get_contents( $path ) === $code ) { // phpcs:ignore
			return true;
		}
		if ( ! Guard_Config::atomic_write( $path, $code ) ) {
			return new \WP_Error(
				'wpcybersec_guard_bootstrap',
				/* translators: %s: file path */
				sprintf( __( 'Could not write %s. Create this file yourself with the content shown on the Advanced settings tab, then install the guard again.', 'wp-cyber-security' ), $path )
			);
		}
		@chmod( $path, 0644 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$this->trust_file( $path );
		return true;
	}

	/**
	 * Rewrites the bootstrap when the plugin moved or the file was damaged.
	 */
	private function heal_bootstrap() {
		$path = $this->bootstrap_path();
		if ( ! is_file( $path ) ) {
			return; // Not created yet or removed on purpose; install() recreates it.
		}
		if ( (string) @file_get_contents( $path ) !== $this->bootstrap_code() ) { // phpcs:ignore
			$this->write_bootstrap();
		}
	}

	/**
	 * Creates the guard's folders.
	 */
	private function ensure_dirs() {
		$storage = wpcybersec()->storage;
		foreach ( array( $this->quarantine_dir(), $storage->spool_dir(), $storage->guard_dir() ) as $dir ) {
			if ( ! is_dir( $dir ) ) {
				wp_mkdir_p( $dir );
			}
			if ( is_dir( $dir ) ) {
				$storage->protect( $dir );
			}
		}
	}

	/**
	 * Schedules (or removes) the periodic spool import.
	 */
	private function ensure_cron() {
		$next = wp_next_scheduled( self::IMPORT_HOOK );
		if ( $this->is_installed() ) {
			if ( ! $next ) {
				wp_schedule_event( time() + 10 * MINUTE_IN_SECONDS, self::SCHEDULE, self::IMPORT_HOOK );
			}
		} elseif ( $next ) {
			wp_clear_scheduled_hook( self::IMPORT_HOOK );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Status and snippets                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * @return array {
	 *     installed, active, enabled, bootstrap_path, bootstrap_exists, prepend,
	 *     points_to_bootstrap, conflict (other prepend file or null), conflict_help,
	 *     conflict_snippet, chain, sapi, recommended (snippet id), pending_spool,
	 *     config_file, config_exists, user_ini (array)
	 * }
	 */
	public function status() {
		$config    = Guard_Config::read();
		$prepend   = (string) ini_get( 'auto_prepend_file' );
		$conflict  = $this->detect_conflict();
		$bootstrap = $this->bootstrap_path();
		$ini_name  = ini_get( 'user_ini.filename' );
		$ini_name  = false === $ini_name ? '.user.ini' : (string) $ini_name;
		$ini_path  = '' !== $ini_name ? wp_normalize_path( ABSPATH . $ini_name ) : '';

		$help    = '';
		$snippet = '';
		if ( $conflict ) {
			$help = sprintf(
				/* translators: 1: other prepend file, 2: bootstrap file */
				__( 'PHP already runs %1$s through auto_prepend_file, and only one prepend file can be set. Either add the line below at the top of that file so it also loads the guard, or point auto_prepend_file to %2$s instead: the guard bootstrap includes the other file automatically, so both keep working.', 'wp-cyber-security' ),
				$conflict,
				$bootstrap
			);
			$snippet = $this->include_snippet();
		}

		return array(
			'installed'           => $this->is_installed(),
			'active'              => defined( 'WPCYBERSEC_GUARD_ACTIVE' ),
			'enabled'             => ! empty( $config['enabled'] ),
			'bootstrap_path'      => $bootstrap,
			'bootstrap_exists'    => is_file( $bootstrap ),
			'prepend'             => $prepend,
			'points_to_bootstrap' => $this->points_to_bootstrap( $prepend ),
			'conflict'            => $conflict ? $conflict : null,
			'conflict_help'       => $help,
			'conflict_snippet'    => $snippet,
			'chain'               => (string) get_option( self::CHAIN_OPTION, '' ),
			'sapi'                => PHP_SAPI,
			'recommended'         => $this->recommended_snippet(),
			'pending_spool'       => $this->spool_count(),
			'config_file'         => Guard_Config::file(),
			'config_exists'       => is_file( Guard_Config::file() ),
			'user_ini'            => array(
				'filename'  => $ini_name,
				'path'      => $ini_path,
				'exists'    => '' !== $ini_path && is_file( $ini_path ),
				'has_line'  => '' !== $ini_path && is_file( $ini_path ) && false !== strpos( (string) @file_get_contents( $ini_path ), self::BOOTSTRAP_FILE ), // phpcs:ignore
				'cache_ttl' => (int) ini_get( 'user_ini.cache_ttl' ),
			),
		);
	}

	/**
	 * Ways to set auto_prepend_file, one per server type.
	 *
	 * @return array[] { id, label, file, code, help, recommended }
	 */
	public function snippets() {
		$bootstrap   = $this->bootstrap_path();
		$recommended = $this->recommended_snippet();
		$ini_name    = ini_get( 'user_ini.filename' );
		$ini_name    = false === $ini_name || '' === $ini_name ? '.user.ini' : (string) $ini_name;
		$php_ini     = php_ini_loaded_file();
		$ver         = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

		$htaccess = array( '# BEGIN ' . self::MARKER );
		foreach ( array( 'php_module', 'php7_module', 'php5_module', 'mod_php.c', 'mod_php8.c', 'mod_php7.c', 'mod_php5.c' ) as $module ) {
			$htaccess[] = '<IfModule ' . $module . '>';
			$htaccess[] = "\tphp_value auto_prepend_file \"" . $bootstrap . '"';
			$htaccess[] = '</IfModule>';
		}
		$htaccess[] = '# END ' . self::MARKER;

		$snippets = array(
			array(
				'id'   => 'user_ini',
				'label' => __( '.user.ini (PHP-FPM, FastCGI, LiteSpeed)', 'wp-cyber-security' ),
				'file' => wp_normalize_path( ABSPATH . $ini_name ),
				'code' => '; BEGIN ' . self::MARKER . "\nauto_prepend_file = \"" . $bootstrap . "\"\n; END " . self::MARKER,
				/* translators: %d: seconds */
				'help' => sprintf( __( 'Add this to the .user.ini file in the WordPress folder (or use the button that writes it for you). PHP reads it again every %d seconds, so the guard starts within a few minutes. Apache with mod_php ignores .user.ini; use the .htaccess snippet there.', 'wp-cyber-security' ), max( 0, (int) ini_get( 'user_ini.cache_ttl' ) ) ),
			),
			array(
				'id'   => 'htaccess',
				'label' => __( '.htaccess (Apache with mod_php)', 'wp-cyber-security' ),
				'file' => wp_normalize_path( ABSPATH . '.htaccess' ),
				'code' => implode( "\n", $htaccess ),
				'help' => __( 'For Apache running PHP as a module (mod_php, PHP 5 to 8). Every line is wrapped in IfModule, so the snippet is ignored on servers without mod_php instead of causing a 500 error. Takes effect on the next request.', 'wp-cyber-security' ),
			),
			array(
				'id'   => 'fpm',
				'label' => __( 'PHP-FPM pool', 'wp-cyber-security' ),
				/* translators: %s: PHP version */
				'file' => sprintf( __( 'The pool file of this site, for example /etc/php/%s/fpm/pool.d/www.conf', 'wp-cyber-security' ), $ver ),
				'code' => 'php_admin_value[auto_prepend_file] = ' . $bootstrap,
				'help' => __( 'The strongest option: php_admin_value cannot be changed by .user.ini or by PHP code. Reload PHP-FPM afterwards (for example: systemctl reload php-fpm).', 'wp-cyber-security' ),
			),
			array(
				'id'   => 'nginx',
				'label' => __( 'nginx (fastcgi_param)', 'wp-cyber-security' ),
				'file' => __( 'The location ~ \.php$ block of this site', 'wp-cyber-security' ),
				'code' => 'fastcgi_param PHP_VALUE "auto_prepend_file=' . $bootstrap . '";',
				'help' => __( 'Add it next to the other fastcgi_param lines and reload nginx. PHP_VALUE replaces any other PHP_VALUE set in the same block, and PHP-FPM may keep it for other sites served by the same pool, so prefer the pool setting when the pool is shared.', 'wp-cyber-security' ),
			),
			array(
				'id'   => 'php_ini',
				'label' => __( 'php.ini', 'wp-cyber-security' ),
				'file' => $php_ini ? wp_normalize_path( $php_ini ) : __( 'The php.ini used by the web server', 'wp-cyber-security' ),
				'code' => 'auto_prepend_file = "' . $bootstrap . '"',
				'help' => __( 'Applies to every site that uses this PHP installation, so only use it on a server dedicated to this site. Restart PHP (or the web server) afterwards.', 'wp-cyber-security' ),
			),
		);

		foreach ( $snippets as &$snippet ) {
			$snippet['recommended'] = $snippet['id'] === $recommended;
		}
		unset( $snippet );
		return $snippets;
	}

	/**
	 * Snippet id that fits the running PHP SAPI.
	 *
	 * @return string
	 */
	public function recommended_snippet() {
		switch ( PHP_SAPI ) {
			case 'apache2handler':
				return 'htaccess';
			case 'litespeed':
				return 'htaccess';
			case 'fpm-fcgi':
			case 'cgi-fcgi':
			case 'cgi':
				return 'user_ini';
			default:
				return 'php_ini';
		}
	}

	/**
	 * Adds or updates auto_prepend_file in ABSPATH/.user.ini.
	 *
	 * @return true|\WP_Error
	 */
	public function write_user_ini() {
		$name = ini_get( 'user_ini.filename' );
		$name = false === $name ? '.user.ini' : (string) $name;
		if ( '' === $name ) {
			return new \WP_Error( 'wpcybersec_user_ini_off', __( 'This server has .user.ini files turned off (user_ini.filename is empty). Use one of the other snippets.', 'wp-cyber-security' ) );
		}
		$file      = wp_normalize_path( ABSPATH . $name );
		$bootstrap = $this->bootstrap_path();
		$content   = is_file( $file ) ? (string) @file_get_contents( $file ) : ''; // phpcs:ignore
		$lines     = '' === $content ? array() : preg_split( '/\r\n|\n|\r/', $content );
		$ours      = 'auto_prepend_file = "' . $bootstrap . '"';
		$found     = false;

		foreach ( $lines as $i => $line ) {
			if ( ! preg_match( '/^\s*auto_prepend_file\s*=\s*(.*)$/i', $line, $match ) ) {
				continue;
			}
			$value = trim( trim( $match[1] ), "\"'" );
			if ( false !== strpos( $value, self::BOOTSTRAP_FILE ) ) {
				$lines[ $i ] = $ours;
				$found       = true;
				continue;
			}
			if ( '' !== $value ) {
				return new \WP_Error(
					'wpcybersec_user_ini_conflict',
					sprintf(
						/* translators: 1: file, 2: other prepend file, 3: php line */
						__( '%1$s already sets auto_prepend_file to %2$s, and only one prepend file can be set. Add this line at the top of that file instead: %3$s', 'wp-cyber-security' ),
						$file,
						$value,
						$this->include_snippet()
					)
				);
			}
		}

		if ( ! $found ) {
			while ( $lines && '' === trim( (string) end( $lines ) ) ) {
				array_pop( $lines );
			}
			$lines[] = '; BEGIN ' . self::MARKER;
			$lines[] = $ours;
			$lines[] = '; END ' . self::MARKER;
		}
		$new = implode( "\n", $lines ) . "\n";
		if ( $new === $content ) {
			return true;
		}
		// Plain write keeps the file's owner and permissions.
		if ( false === @file_put_contents( $file, $new, LOCK_EX ) ) { // phpcs:ignore
			return new \WP_Error(
				'wpcybersec_user_ini_write',
				/* translators: %s: file path */
				sprintf( __( 'Could not write %s. Add the line yourself.', 'wp-cyber-security' ), $file )
			);
		}
		$this->trust_file( $file );
		$this->log(
			'guard_user_ini',
			/* translators: %s: file path */
			sprintf( __( 'Added the guard to %s. PHP picks it up within a few minutes.', 'wp-cyber-security' ), $file )
		);
		return true;
	}

	/**
	 * Removes the guard lines from ABSPATH/.user.ini.
	 *
	 * @return true|\WP_Error
	 */
	public function remove_user_ini() {
		$name = ini_get( 'user_ini.filename' );
		$name = false === $name || '' === $name ? '.user.ini' : (string) $name;
		$file = wp_normalize_path( ABSPATH . $name );
		if ( ! is_file( $file ) ) {
			return true;
		}
		$content = (string) @file_get_contents( $file ); // phpcs:ignore
		$kept    = array();
		foreach ( preg_split( '/\r\n|\n|\r/', $content ) as $line ) {
			$trimmed = trim( $line );
			if ( '; BEGIN ' . self::MARKER === $trimmed || '; END ' . self::MARKER === $trimmed ) {
				continue;
			}
			if ( preg_match( '/^\s*auto_prepend_file\s*=/i', $line ) && false !== strpos( $line, self::BOOTSTRAP_FILE ) ) {
				continue;
			}
			$kept[] = $line;
		}
		$new = rtrim( implode( "\n", $kept ) ) . "\n";
		if ( "\n" === $new ) {
			$new = '';
		}
		if ( $new !== $content && false === @file_put_contents( $file, $new, LOCK_EX ) ) { // phpcs:ignore
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_user_ini_write', sprintf( __( 'Could not write %s. Remove the auto_prepend_file line yourself.', 'wp-cyber-security' ), $file ) );
		}
		$this->trust_file( $file );
		return true;
	}

	/**
	 * Adds the mod_php snippet to ABSPATH/.htaccess between markers.
	 *
	 * @return true|\WP_Error
	 */
	public function write_htaccess() {
		$file = wp_normalize_path( ABSPATH . '.htaccess' );
		if ( is_file( $file ) ) {
			$content = (string) @file_get_contents( $file ); // phpcs:ignore
			$outside = preg_replace( '/# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '/s', '', $content );
			if ( preg_match( '/^\s*php_value\s+auto_prepend_file\s+["\']?([^"\'\r\n]+)/im', (string) $outside, $match ) && false === strpos( $match[1], self::BOOTSTRAP_FILE ) ) {
				return new \WP_Error(
					'wpcybersec_htaccess_conflict',
					sprintf(
						/* translators: 1: other prepend file, 2: php line */
						__( '.htaccess already sets auto_prepend_file to %1$s, and only one prepend file can be set. Add this line at the top of that file instead: %2$s', 'wp-cyber-security' ),
						trim( $match[1] ),
						$this->include_snippet()
					)
				);
			}
		}
		$snippet = null;
		foreach ( $this->snippets() as $candidate ) {
			if ( 'htaccess' === $candidate['id'] ) {
				$snippet = $candidate;
			}
		}
		$lines = explode( "\n", $snippet['code'] );
		// insert_with_markers adds its own BEGIN/END lines.
		$lines = array_values( array_filter( $lines, static function ( $line ) {
			return 0 !== strpos( $line, '# BEGIN ' ) && 0 !== strpos( $line, '# END ' );
		} ) );

		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		if ( ! insert_with_markers( $file, self::MARKER, $lines ) ) {
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_htaccess_write', sprintf( __( 'Could not write %s. Add the snippet yourself.', 'wp-cyber-security' ), $file ) );
		}
		$this->trust_file( $file );
		$this->log(
			'guard_htaccess',
			/* translators: %s: file path */
			sprintf( __( 'Added the guard to %s.', 'wp-cyber-security' ), $file )
		);
		return true;
	}

	/**
	 * Removes the guard block from ABSPATH/.htaccess.
	 *
	 * @return true|\WP_Error
	 */
	public function remove_htaccess() {
		$file = wp_normalize_path( ABSPATH . '.htaccess' );
		if ( ! is_file( $file ) ) {
			return true;
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		if ( ! insert_with_markers( $file, self::MARKER, array() ) ) {
			/* translators: %s: file path */
			return new \WP_Error( 'wpcybersec_htaccess_write', sprintf( __( 'Could not write %s. Remove the guard block yourself.', 'wp-cyber-security' ), $file ) );
		}
		$this->trust_file( $file );
		return true;
	}

	/**
	 * One line that loads the guard from another prepend file.
	 *
	 * @return string
	 */
	public function include_snippet() {
		$bootstrap = var_export( $this->bootstrap_path(), true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		return "if ( file_exists( {$bootstrap} ) ) { include_once {$bootstrap}; }";
	}

	/**
	 * Another prepend file in effect for this request (for example Wordfence's
	 * wordfence-waf.php) that does not load the guard.
	 *
	 * @return string Its path, or '' when there is no conflict.
	 */
	private function detect_conflict() {
		$prepend = trim( (string) ini_get( 'auto_prepend_file' ) );
		if ( '' === $prepend || $this->points_to_bootstrap( $prepend ) ) {
			return '';
		}
		// An old bootstrap of this plugin (site moved): not another firewall, never chain it.
		if ( self::BOOTSTRAP_FILE === basename( wp_normalize_path( $prepend ) ) ) {
			return '';
		}
		// Already loads the guard itself?
		if ( @is_readable( $prepend ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$head = (string) @file_get_contents( $prepend, false, null, 0, 65536 ); // phpcs:ignore
			if ( false !== strpos( $head, self::BOOTSTRAP_FILE ) ) {
				return '';
			}
		}
		return wp_normalize_path( $prepend );
	}

	/**
	 * @param string $prepend auto_prepend_file value.
	 * @return bool
	 */
	private function points_to_bootstrap( $prepend ) {
		$prepend = trim( (string) $prepend );
		if ( '' === $prepend ) {
			return false;
		}
		$bootstrap = $this->bootstrap_path();
		$real_a    = realpath( $prepend );
		$real_b    = realpath( $bootstrap );
		if ( $real_a && $real_b ) {
			return wp_normalize_path( $real_a ) === wp_normalize_path( $real_b );
		}
		return wp_normalize_path( $prepend ) === $bootstrap;
	}

	/**
	 * Whether anything known still points auto_prepend_file at the bootstrap:
	 * the running PHP, or .user.ini / .htaccess in the WordPress folder (checked
	 * too because WP-CLI does not see web server settings).
	 *
	 * @return bool
	 */
	private function bootstrap_referenced() {
		if ( $this->points_to_bootstrap( (string) ini_get( 'auto_prepend_file' ) ) ) {
			return true;
		}
		$ini_name = ini_get( 'user_ini.filename' );
		$ini_name = false === $ini_name || '' === $ini_name ? '.user.ini' : (string) $ini_name;
		foreach ( array( ABSPATH . $ini_name, ABSPATH . '.htaccess', dirname( ABSPATH ) . '/' . $ini_name, dirname( ABSPATH ) . '/.htaccess' ) as $file ) {
			if ( ! @is_readable( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			foreach ( preg_split( '/\r\n|\n|\r/', (string) @file_get_contents( $file ) ) as $line ) { // phpcs:ignore
				$line = ltrim( $line );
				if ( '' === $line || ';' === $line[0] || '#' === $line[0] ) {
					continue;
				}
				if ( false !== stripos( $line, 'auto_prepend_file' ) && false !== strpos( $line, self::BOOTSTRAP_FILE ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* Spool import                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * @return string Lines taken out of the spool and being imported.
	 */
	private function work_file() {
		return wpcybersec()->storage->spool_dir() . '/guard-uploads.work.jsonl';
	}

	/**
	 * @return string Import position in the work file: { offset, tries }.
	 */
	private function pos_file() {
		return wpcybersec()->storage->spool_dir() . '/guard-uploads.work.pos';
	}

	/**
	 * @return string Lock file that keeps two imports from running at once.
	 */
	private function lock_file() {
		return wpcybersec()->storage->spool_dir() . '/guard-import.lock';
	}

	/**
	 * Whether anything waits to be imported (cheap).
	 *
	 * @return bool
	 */
	public function has_pending() {
		$spool = $this->spool_file();
		$work  = $this->work_file();
		clearstatcache( true, $spool );
		clearstatcache( true, $work );
		return ( @is_file( $spool ) && (int) @filesize( $spool ) > 0 ) || @is_file( $work ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Cron callback: full-size import plus housekeeping of the guard quarantine.
	 */
	public function cron_import() {
		$this->cleanup_partial_copies();
		$this->import_spool();
	}

	/**
	 * Turns uploads held by the guard into pending upload items.
	 *
	 * Lines are moved from the spool into a work file under the guard's own lock
	 * and imported one by one. The position in the work file is saved before
	 * and after every line, so a request that dies (time limit, fatal error)
	 * loses nothing: the next run continues with the same line. A line whose
	 * import never finished twice is imported without the signature scan, so one
	 * file that makes the scanner hang cannot block the queue.
	 *
	 * @param int  $max_lines   Lines to import in this call (0: IMPORT_BATCH).
	 * @param int  $max_seconds Time budget in seconds (0: IMPORT_SECONDS).
	 * @param bool $fresh_only  Stop at a line whose earlier try never finished
	 *                          (admin page loads leave those to cron).
	 * @return int Items created.
	 */
	public function import_spool( $max_lines = 0, $max_seconds = 0, $fresh_only = false ) {
		$max_lines   = (int) $max_lines > 0 ? (int) $max_lines : self::IMPORT_BATCH;
		$max_seconds = (int) $max_seconds > 0 ? (int) $max_seconds : self::IMPORT_SECONDS;
		if ( ! $this->has_pending() ) {
			return 0;
		}
		$lock = $this->acquire_import_lock();
		if ( ! $lock ) {
			return 0; // Another request is importing right now.
		}

		$imported = 0;
		try {
			$deadline = microtime( true ) + $max_seconds;
			$done     = 0;
			while ( $done < $max_lines && microtime( true ) < $deadline ) {
				$next = $this->next_work_line();
				if ( false === $next ) {
					break; // The work file cannot be read or the position cannot be saved.
				}
				if ( null === $next ) {
					if ( ! $this->claim_spool() ) {
						break; // Nothing waiting.
					}
					continue;
				}

				if ( $fresh_only && $next['tries'] > 0 ) {
					break;
				}

				// Record the try before anything that can hang or die.
				$tries = $next['tries'] + 1;
				if ( $tries > self::MAX_ATTEMPTS ) {
					// Even the import without a scan keeps dying: give this line up.
					$this->log( 'guard_import_error', __( 'Skipped a line of the early guard spool that could not be imported after several tries.', 'wp-cyber-security' ) );
					if ( ! $this->write_pos( $next['end'], 0 ) ) {
						break;
					}
					continue;
				}
				if ( ! $this->write_pos( $next['offset'], $tries ) ) {
					break;
				}
				++$done;

				$result = 'skipped';
				$entry  = json_decode( $next['line'], true );
				if ( is_array( $entry ) ) {
					$attempts = ( isset( $entry['attempts'] ) ? max( 0, (int) $entry['attempts'] ) : 0 ) + 1;
					try {
						$result = $this->import_entry( $entry, $tries <= self::SCAN_TRIES );
					} catch ( \Throwable $e ) {
						$result = 'retry';
						$this->log(
							'guard_import_error',
							/* translators: %s: error message */
							sprintf( __( 'Could not import an upload held by the early guard: %s', 'wp-cyber-security' ), $e->getMessage() )
						);
					}
					if ( 'retry' === $result ) {
						if ( $attempts < self::MAX_ATTEMPTS ) {
							$entry['attempts'] = $attempts;
							$this->append_spool( array( wp_json_encode( $entry ) ) );
						} else {
							$this->log(
								'guard_import_error',
								sprintf(
									/* translators: 1: file name, 2: SHA-256 */
									__( 'Gave up importing the held upload "%1$s" (SHA-256 %2$s) after several failed tries. Its copy stays in the guard quarantine folder.', 'wp-cyber-security' ),
									Upload_Gate::safe_name( isset( $entry['name'] ) ? (string) $entry['name'] : '' ),
									isset( $entry['sha256'] ) ? sanitize_key( (string) $entry['sha256'] ) : ''
								)
							);
						}
					}
				}

				if ( ! $this->write_pos( $next['end'], 0 ) ) {
					break;
				}
				if ( 'imported' === $result ) {
					++$imported;
				} elseif ( 'retry' === $result ) {
					break; // Most likely the database; try again on the next run.
				}
			}
		} finally {
			$this->release_import_lock( $lock );
		}
		return $imported;
	}

	/**
	 * @return resource|null Lock handle, or null when another import holds it.
	 */
	private function acquire_import_lock() {
		$dir = wpcybersec()->storage->spool_dir();
		if ( ! is_dir( $dir ) ) {
			return null;
		}
		$handle = @fopen( $this->lock_file(), 'c' ); // phpcs:ignore
		if ( ! $handle ) {
			return null;
		}
		if ( ! @flock( $handle, LOCK_EX | LOCK_NB ) ) { // phpcs:ignore
			@fclose( $handle ); // phpcs:ignore
			return null;
		}
		return $handle;
	}

	/**
	 * @param resource $handle Lock handle.
	 */
	private function release_import_lock( $handle ) {
		@flock( $handle, LOCK_UN ); // phpcs:ignore
		@fclose( $handle ); // phpcs:ignore
	}

	/**
	 * Moves everything waiting in the spool into a new work file. Runs under the
	 * guard's own spool lock, and the spool file keeps its identity (it is
	 * emptied, never renamed), so a guard writing at the same time loses nothing.
	 *
	 * @return bool Whether a work file was created.
	 */
	private function claim_spool() {
		$spool = $this->spool_file();
		$work  = $this->work_file();
		clearstatcache( true, $spool );
		if ( ! is_file( $spool ) || 0 === (int) @filesize( $spool ) || @is_file( $work ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$handle = @fopen( $spool, 'c+' ); // phpcs:ignore
		if ( ! $handle ) {
			return false;
		}
		if ( ! @flock( $handle, LOCK_EX ) ) { // phpcs:ignore
			@fclose( $handle ); // phpcs:ignore
			return false;
		}
		$ok   = false;
		$tmp  = $work . '.' . wp_generate_password( 12, false ) . '.tmp';
		$stat = fstat( $handle );
		$size = is_array( $stat ) ? (int) $stat['size'] : 0;
		if ( $size > 0 ) {
			$out = @fopen( $tmp, 'xb' ); // phpcs:ignore
			if ( $out ) {
				rewind( $handle );
				$copied = stream_copy_to_stream( $handle, $out );
				$ok     = false !== $copied && (int) $copied === $size && @fflush( $out ); // phpcs:ignore
				@fclose( $out ); // phpcs:ignore
				// The position file belongs to the work file; start the new one at 0.
				if ( $ok && is_file( $this->pos_file() ) ) {
					$ok = @unlink( $this->pos_file() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				}
				$ok = $ok && @rename( $tmp, $work ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( $ok ) {
					// Only now that every line is safe in the work file.
					ftruncate( $handle, 0 );
					fflush( $handle );
				} else {
					@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				}
			}
		}
		@flock( $handle, LOCK_UN ); // phpcs:ignore
		@fclose( $handle ); // phpcs:ignore
		return $ok;
	}

	/**
	 * Next line of the work file.
	 *
	 * @return array|null|false { line, offset, end, tries }, null when there is no
	 *                          work left, false when the work file cannot be used.
	 */
	private function next_work_line() {
		$work = $this->work_file();
		clearstatcache( true, $work );
		if ( ! is_file( $work ) ) {
			if ( is_file( $this->pos_file() ) ) {
				@unlink( $this->pos_file() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
			return null;
		}
		$pos    = $this->read_pos();
		$handle = @fopen( $work, 'rb' ); // phpcs:ignore
		if ( ! $handle ) {
			return false;
		}
		$offset = $pos['offset'];
		$tries  = $pos['tries'];
		$result = null;
		while ( true ) {
			if ( 0 !== fseek( $handle, $offset ) ) {
				break;
			}
			$line = fgets( $handle );
			if ( false === $line ) {
				break; // End of the work file.
			}
			$end = ftell( $handle );
			if ( '' !== trim( $line ) ) {
				$result = array(
					'line'   => trim( $line ),
					'offset' => $offset,
					'end'    => (int) $end,
					'tries'  => $tries,
				);
				break;
			}
			$offset = (int) $end;
			$tries  = 0;
		}
		@fclose( $handle ); // phpcs:ignore

		if ( null === $result ) {
			// Everything in the work file is imported.
			@unlink( $work ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			@unlink( $this->pos_file() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			clearstatcache( true, $work );
			return is_file( $work ) ? false : null;
		}
		return $result;
	}

	/**
	 * @return array { offset, tries }
	 */
	private function read_pos() {
		$pos  = array(
			'offset' => 0,
			'tries'  => 0,
		);
		$file = $this->pos_file();
		if ( ! is_file( $file ) ) {
			return $pos;
		}
		$data = json_decode( (string) @file_get_contents( $file ), true ); // phpcs:ignore
		if ( is_array( $data ) ) {
			$pos['offset'] = isset( $data['offset'] ) ? max( 0, (int) $data['offset'] ) : 0;
			$pos['tries']  = isset( $data['tries'] ) ? max( 0, (int) $data['tries'] ) : 0;
		}
		return $pos;
	}

	/**
	 * @param int $offset Byte offset of the next line to import.
	 * @param int $tries  Unfinished tries of that line.
	 * @return bool
	 */
	private function write_pos( $offset, $tries ) {
		$json = wp_json_encode(
			array(
				'offset' => (int) $offset,
				'tries'  => (int) $tries,
			)
		);
		return Guard_Config::atomic_write( $this->pos_file(), (string) $json );
	}

	/**
	 * Removes copies the guard left half-written (the request died while copying).
	 */
	private function cleanup_partial_copies() {
		$list = @glob( $this->quarantine_dir() . '/*/*/*.part', GLOB_NOSORT ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $list ) ) {
			return;
		}
		$cutoff = time() - DAY_IN_SECONDS;
		foreach ( array_slice( $list, 0, 1000 ) as $path ) {
			$mtime = @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false !== $mtime && $mtime < $cutoff ) {
				@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
		}
	}

	/**
	 * @param array $entry Spool line.
	 * @param bool  $scan  Run the signature scan on the held copy.
	 * @return string imported | skipped | retry
	 */
	private function import_entry( array $entry, $scan = true ) {
		$plugin = wpcybersec();
		$sha256 = isset( $entry['sha256'] ) ? strtolower( (string) $entry['sha256'] ) : '';
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $sha256 ) ) {
			return 'skipped';
		}

		// Never trust a path from the spool unless it is inside the guard quarantine.
		$held_path = isset( $entry['quarantine_path'] ) ? wp_normalize_path( (string) $entry['quarantine_path'] ) : '';
		if ( '' !== $held_path && ( ! is_file( $held_path ) || ! Storage::is_within( $held_path, $this->quarantine_dir() ) ) ) {
			$held_path = '';
		}
		$stub       = array( 'quarantine_path' => $held_path );
		$raw_name   = isset( $entry['name'] ) ? (string) $entry['name'] : '';
		$name       = Upload_Gate::safe_name( $raw_name, $sha256 );
		$executable = ! empty( $entry['exec'] ) || Upload_Gate::name_is_executable( $raw_name ) || Upload_Gate::name_is_executable( $name );

		// Approved in the meantime (an approval under a harmless name does not cover an executable one).
		if ( $plugin->allowlist->is_allowed_hash( $sha256, $executable ) ) {
			if ( '' !== $held_path ) {
				$plugin->quarantine->purge( $stub );
			}
			return 'skipped';
		}

		// Same content under the same kind of name already waiting: keep one item.
		$existing = $this->find_open_upload( $sha256, $executable );
		if ( $existing ) {
			$update = array(
				'details' => array(
					'repeat_count' => ( isset( $existing['details']['repeat_count'] ) ? (int) $existing['details']['repeat_count'] : 0 ) + 1,
					'last_attempt' => Store::now(),
				),
			);
			// Copies are named by content, so the new copy may be the item's own copy: never purge that one.
			$existing_path = '' !== (string) $existing['quarantine_path'] ? wp_normalize_path( (string) $existing['quarantine_path'] ) : '';
			if ( '' !== $held_path && $existing_path !== $held_path ) {
				if ( $plugin->quarantine->exists( $existing ) ) {
					$plugin->quarantine->purge( $stub );
				} else {
					$update['quarantine_path'] = $held_path;
				}
			}
			$plugin->store->item_update( $existing['id'], $update );
			return 'skipped';
		}

		$note = isset( $entry['note'] ) ? sanitize_key( (string) $entry['note'] ) : '';

		$hits = array();
		if ( '' !== $held_path && ! $scan ) {
			// Earlier tries never finished (the scan probably hung): import without it.
			$hits[] = array(
				'sig'      => 'scan_incomplete',
				'title'    => __( 'The malware check of this file did not finish, so it was not checked. Treat it as unknown.', 'wp-cyber-security' ),
				'severity' => Store::SEV_MEDIUM,
				'line'     => 0,
				'snippet'  => '',
			);
		} elseif ( '' !== $held_path && $plugin->scanner && method_exists( $plugin->scanner, 'scan_upload' ) ) {
			try {
				$hits = $plugin->scanner->scan_upload( $held_path, $name );
				$hits = is_array( $hits ) ? array_values( array_filter( $hits, 'is_array' ) ) : array();
			} catch ( \Throwable $e ) {
				$hits = array();
			}
		}
		$severity = 0;
		if ( $plugin->scanner && method_exists( $plugin->scanner, 'max_severity' ) ) {
			$severity = (int) $plugin->scanner->max_severity( $hits );
		} else {
			foreach ( $hits as $hit ) {
				$severity = max( $severity, isset( $hit['severity'] ) ? (int) $hit['severity'] : 0 );
			}
		}

		$ip      = isset( $entry['ip'] ) && filter_var( (string) $entry['ip'], FILTER_VALIDATE_IP ) ? (string) $entry['ip'] : '';
		$time    = isset( $entry['time'] ) ? (int) $entry['time'] : 0;
		$created = $time > 0 && $time <= time() + HOUR_IN_SECONDS ? gmdate( 'Y-m-d H:i:s', $time ) : Store::now();
		$script  = isset( $entry['script'] ) ? Upload_Gate::cut( sanitize_text_field( (string) $entry['script'] ), 255 ) : '';

		$id = $plugin->store->item_insert(
			array(
				'type'            => Store::TYPE_UPLOAD,
				'status'          => Store::STATUS_PENDING,
				'severity'        => $severity,
				'path'            => $name,
				'original_path'   => '',
				'quarantine_path' => $held_path,
				'sha256'          => $sha256,
				'size'            => isset( $entry['size'] ) ? max( 0, (int) $entry['size'] ) : 0,
				'mime'            => $this->mime_for( $held_path, $name, isset( $entry['type'] ) ? (string) $entry['type'] : '' ),
				'source'          => 'guard',
				'user_id'         => 0,
				'ip'              => $ip,
				'created_at'      => $created,
				'details'         => array(
					'context'         => 'guard',
					'script'          => $script,
					'request_uri'     => isset( $entry['uri'] ) ? Upload_Gate::cut( sanitize_text_field( (string) $entry['uri'] ), 1000 ) : '',
					'method'          => isset( $entry['method'] ) ? substr( sanitize_key( (string) $entry['method'] ), 0, 10 ) : '',
					'field'           => isset( $entry['field'] ) ? Upload_Gate::cut( sanitize_text_field( (string) $entry['field'] ), 255 ) : '',
					'user_agent'      => isset( $entry['ua'] ) ? Upload_Gate::cut( sanitize_text_field( (string) $entry['ua'] ), 255 ) : '',
					'guard_action'    => isset( $entry['action'] ) && 'strip' === $entry['action'] ? 'strip' : 'block',
					'held'            => '' !== $held_path,
					'note'            => $note,
					'executable'      => $executable,
					'scan_incomplete' => '' !== $held_path && ! $scan,
					'hits'            => array_slice( $hits, 0, 50 ),
				),
			)
		);
		if ( ! $id ) {
			return 'retry';
		}

		if ( 'too_large' === $note ) {
			/* translators: 1: file name, 2: script */
			$message = sprintf( __( 'Early guard refused "%1$s" sent to %2$s (too large to keep a copy). Approving it allows the file next time.', 'wp-cyber-security' ), $name, $script );
		} elseif ( in_array( $note, array( 'quota_full', 'no_space', 'copy_failed' ), true ) ) {
			/* translators: 1: file name, 2: script */
			$message = sprintf( __( 'Early guard refused "%1$s" sent to %2$s without keeping a copy, because the guard quarantine is full or could not be written. Review the held uploads to free space. Approving it allows the file next time.', 'wp-cyber-security' ), $name, $script );
		} else {
			/* translators: 1: file name, 2: script */
			$message = sprintf( __( 'Early guard held "%1$s" sent to %2$s.', 'wp-cyber-security' ), $name, $script );
		}
		$this->log(
			'guard_upload_held',
			$message,
			array(
				'item_id'  => $id,
				'sha256'   => $sha256,
				'severity' => $severity,
			)
		);

		if ( $plugin->notifier && method_exists( $plugin->notifier, 'item_created' ) ) {
			try {
				$plugin->notifier->item_created( $id );
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}
		return 'imported';
	}

	/**
	 * @param string[] $lines JSON lines to put back.
	 */
	private function append_spool( array $lines ) {
		$handle = @fopen( $this->spool_file(), 'ab' ); // phpcs:ignore
		if ( ! $handle ) {
			return;
		}
		if ( @flock( $handle, LOCK_EX ) ) { // phpcs:ignore
			@fwrite( $handle, implode( "\n", $lines ) . "\n" ); // phpcs:ignore
			@fflush( $handle ); // phpcs:ignore
			@flock( $handle, LOCK_UN ); // phpcs:ignore
		}
		@fclose( $handle ); // phpcs:ignore
	}

	/**
	 * @return int Lines waiting in the spool and in the unfinished part of the work file.
	 */
	private function spool_count() {
		$count = $this->count_lines( $this->spool_file(), 0 );
		if ( is_file( $this->work_file() ) ) {
			$pos    = $this->read_pos();
			$count += $this->count_lines( $this->work_file(), $pos['offset'] );
		}
		return $count;
	}

	/**
	 * @param string $file   File.
	 * @param int    $offset Start offset.
	 * @return int Newlines after $offset.
	 */
	private function count_lines( $file, $offset ) {
		if ( ! is_file( $file ) || (int) @filesize( $file ) <= $offset ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return 0;
		}
		$count  = 0;
		$handle = @fopen( $file, 'rb' ); // phpcs:ignore
		if ( ! $handle ) {
			return 0;
		}
		if ( $offset > 0 ) {
			fseek( $handle, $offset );
		}
		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, 65536 ); // phpcs:ignore
			if ( false === $chunk ) {
				break;
			}
			$count += substr_count( $chunk, "\n" );
		}
		fclose( $handle ); // phpcs:ignore
		return $count;
	}

	/**
	 * @param string $sha256     Hash.
	 * @param bool   $executable Whether the new upload has an executable name.
	 * @return array|null Open upload item with this content and the same kind of name.
	 */
	private function find_open_upload( $sha256, $executable = false ) {
		$result = wpcybersec()->store->items_query(
			array(
				'type'     => Store::TYPE_UPLOAD,
				'status'   => Store::STATUS_PENDING,
				'search'   => $sha256,
				'per_page' => 5,
			)
		);
		foreach ( $result['rows'] as $row ) {
			if ( $row['sha256'] === $sha256 && Upload_Gate::item_is_executable( $row ) === (bool) $executable ) {
				return $row;
			}
		}
		return null;
	}

	/**
	 * @param string $path        Held copy ('' when none).
	 * @param string $name        File name.
	 * @param string $client_type Browser supplied type.
	 * @return string
	 */
	private function mime_for( $path, $name, $client_type ) {
		if ( '' !== $path ) {
			$check = wp_check_filetype_and_ext( $path, $name );
			if ( ! empty( $check['type'] ) ) {
				return (string) $check['type'];
			}
			if ( function_exists( 'finfo_open' ) ) {
				$finfo = @finfo_open( FILEINFO_MIME_TYPE ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( $finfo ) {
					$mime = @finfo_file( $finfo, $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
					finfo_close( $finfo );
					if ( $mime ) {
						return substr( sanitize_mime_type( $mime ), 0, 100 );
					}
				}
			}
		}
		$client_type = sanitize_mime_type( $client_type );
		return $client_type ? substr( $client_type, 0, 100 ) : 'application/octet-stream';
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Tells the file monitor that a file this plugin wrote is expected.
	 *
	 * @param string $path File.
	 */
	private function trust_file( $path ) {
		$monitor = wpcybersec()->file_monitor;
		if ( $monitor && method_exists( $monitor, 'trust_file' ) && is_file( $path ) ) {
			try {
				$monitor->trust_file( $path );
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}
	}

	/**
	 * @param string $path File that no longer exists.
	 */
	private function forget_file( $path ) {
		$monitor = wpcybersec()->file_monitor;
		if ( $monitor && method_exists( $monitor, 'forget_file' ) ) {
			try {
				$monitor->forget_file( $path );
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}
	}

	/**
	 * @param string $event   Event.
	 * @param string $message Message.
	 * @param array  $context Context.
	 */
	private function log( $event, $message, array $context = array() ) {
		$logger = wpcybersec()->logger;
		if ( $logger ) {
			$logger->log( $event, $message, $context );
		}
	}
}
