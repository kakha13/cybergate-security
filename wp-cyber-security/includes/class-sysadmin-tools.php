<?php
/**
 * System administrator tools: environment diagnostics, server snippets and the
 * admin-post handlers used by the setup wizard and the settings page.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * The setup module hooks into WordPress only through register(). Everything
 * else is plain methods that the wizard, the settings page and WP-CLI call.
 */
class Sysadmin_Tools {

	/** Marker used for the uploads .htaccess block. */
	const MARKER = 'WP Cyber Security';

	/** Admin page slugs owned by the setup module. */
	const WIZARD_PAGE   = 'wpcybersec-wizard';
	const SETTINGS_PAGE = 'wpcybersec-settings';

	/** Transient holding the results of the live web probes. */
	const PROBE_TRANSIENT = 'wpcybersec_probes';

	/** Per-user transient prefix for one-time notices shown after a redirect. */
	const FLASH_PREFIX = 'wpcybersec_flash_';

	/** PHP versions below this one no longer receive security fixes. */
	const PHP_SUPPORTED = '8.2';

	/**
	 * Preset keys that do not decide the protection level: changing how alerts
	 * are delivered does not turn a level into "custom".
	 */
	const LEVEL_IGNORE = array( 'notify_mode' );

	/** Wizard quick actions that may be posted with wpcs_do. */
	const WIZARD_ACTIONS = array( 'write_htaccess', 'probe', 'send_test' );

	/**
	 * Hooks: assets for the wizard and settings page, admin-post handlers and
	 * the test email AJAX endpoint.
	 */
	public function register() {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ), 20 );
		add_action( 'in_admin_header', array( $this, 'quiet_wizard_notices' ), 1 );
		add_filter( 'admin_body_class', array( $this, 'body_class' ) );

		$handlers = array( 'wizard', 'save_settings', 'guard', 'export', 'import', 'write_htaccess', 'test_email', 'snapshots_clear' );
		foreach ( $handlers as $handler ) {
			add_action( 'admin_post_wpcybersec_' . $handler, array( $this, 'handle_' . $handler ) );
		}
		add_action( 'wp_ajax_wpcybersec_test_email', array( $this, 'ajax_test_email' ) );
		add_action( 'wpcybersec_settings_updated', array( $this, 'forget_baseline_on_root_change' ), 10, 2 );
	}

	/**
	 * Fingerprints are stored relative to the scan folder, so after the folder
	 * changes (settings page, import, WP-CLI) the old baseline matches nothing.
	 * Forgetting it makes the next whole-site scan record a new baseline instead
	 * of reporting (or, in strict mode, quarantining) every file as new.
	 *
	 * @param array $new New settings.
	 * @param array $old Previous settings.
	 */
	public function forget_baseline_on_root_change( $new, $old ) {
		$new = (array) $new;
		$old = (array) $old;
		foreach ( array( 'scan_root', 'scan_root_custom' ) as $key ) {
			$before = isset( $old[ $key ] ) ? (string) $old[ $key ] : '';
			$after  = isset( $new[ $key ] ) ? (string) $new[ $key ] : '';
			if ( $before !== $after ) {
				delete_option( 'wpcybersec_baseline_at' );
				return;
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/* Assets and screen tweaks                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * @return string The current ?page= value.
	 */
	public static function current_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read only.
		return isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
	}

	/**
	 * @param string $hook_suffix Admin page hook.
	 * @return bool Whether this is the wizard or the settings page.
	 */
	private static function is_setup_screen( $hook_suffix ) {
		$page = self::current_page();
		if ( in_array( $page, array( self::WIZARD_PAGE, self::SETTINGS_PAGE ), true ) ) {
			return true;
		}
		$hook_suffix = (string) $hook_suffix;
		return false !== strpos( $hook_suffix, self::WIZARD_PAGE ) || false !== strpos( $hook_suffix, self::SETTINGS_PAGE );
	}

	/**
	 * Enqueues setup.css and setup.js on the wizard and the settings page.
	 *
	 * @param string $hook_suffix Admin page hook.
	 */
	public function enqueue( $hook_suffix ) {
		if ( ! self::is_setup_screen( $hook_suffix ) ) {
			return;
		}

		if ( class_exists( '\WPCyberSecurity\Admin\Assets' ) ) {
			if ( ! wp_script_is( 'wpcybersec-core', 'registered' ) ) {
				Admin\Assets::register();
			}
			Admin\Assets::enqueue();
		}

		$css_deps = wp_style_is( 'wpcybersec-base', 'registered' ) ? array( 'wpcybersec-base' ) : array( 'dashicons' );
		$js_deps  = wp_script_is( 'wpcybersec-core', 'registered' ) ? array( 'wpcybersec-core' ) : array();

		wp_enqueue_style( 'wpcybersec-setup', WPCYBERSEC_URL . 'assets/css/setup.css', $css_deps, \WPCyberSecurity\Admin\Assets::ver( 'assets/css/setup.css' ) );
		wp_enqueue_script( 'wpcybersec-setup', WPCYBERSEC_URL . 'assets/js/setup.js', $js_deps, \WPCyberSecurity\Admin\Assets::ver( 'assets/js/setup.js' ), true );
		wp_localize_script(
			'wpcybersec-setup',
			'wpcybersecSetup',
			array(
				'presets'    => Settings::presets(),
				'levels'     => array(
					'strict'   => __( 'Strict', 'wp-cyber-security' ),
					'balanced' => __( 'Balanced', 'wp-cyber-security' ),
					'relaxed'  => __( 'Relaxed', 'wp-cyber-security' ),
				),
				'threatsUrl' => admin_url( 'admin.php?page=wpcybersec-reports&tab=threats' ),
				'i18n'       => array(
					'starting'       => __( 'Starting the scan...', 'wp-cyber-security' ),
					'waitOther'      => __( 'Another scan is running. The baseline scan starts as soon as it finishes.', 'wp-cyber-security' ),
					/* translators: %s: number of files */
					'fingerprinted'  => __( '%s files fingerprinted and trusted.', 'wp-cyber-security' ),
					/* translators: %s: number of threats */
					'threatsFound'   => __( '%s possible threats found. They were not trusted; review them on the Reports page.', 'wp-cyber-security' ),
					'threatsLink'    => __( 'Review threats', 'wp-cyber-security' ),
					'noThreats'      => __( 'No known malware was found.', 'wp-cyber-security' ),
					/* translators: %s: error message */
					'scanFailed'     => __( 'The scan stopped: %s', 'wp-cyber-security' ),
					'scanCancelled'  => __( 'The scan was cancelled. You can start it again.', 'wp-cyber-security' ),
					'runAgain'       => __( 'Run the scan again', 'wp-cyber-security' ),
					'leaving'        => __( 'A scan is running. If you leave, it continues in the background, more slowly.', 'wp-cyber-security' ),
					'sending'        => __( 'Sending...', 'wp-cyber-security' ),
					/* translators: %s: time */
					'unlockedUntil'  => __( 'Unlocked until %s', 'wp-cyber-security' ),
					'locked'         => __( 'Locked', 'wp-cyber-security' ),
					'unlockedToast'  => __( 'Changes are allowed for a few minutes.', 'wp-cyber-security' ),
					'lockedToast'    => __( 'Locked again.', 'wp-cyber-security' ),
					/* translators: %s: protection level name */
					'customHint'     => __( 'Your choices differ from the %s preset, so the level is saved as Custom.', 'wp-cyber-security' ),
					'customNoLevel'  => __( 'Your choices do not match a preset, so the level is saved as Custom.', 'wp-cyber-security' ),
				),
			)
		);
	}

	/**
	 * Removes notices of other plugins from the wizard so it stays focused.
	 */
	public function quiet_wizard_notices() {
		if ( self::WIZARD_PAGE !== self::current_page() ) {
			return;
		}
		remove_all_actions( 'admin_notices' );
		remove_all_actions( 'all_admin_notices' );
		remove_all_actions( 'network_admin_notices' );
		remove_all_actions( 'user_admin_notices' );
	}

	/**
	 * @param string $classes Body classes.
	 * @return string
	 */
	public function body_class( $classes ) {
		$page = self::current_page();
		if ( self::WIZARD_PAGE === $page ) {
			$classes .= ' wpcs-wizard-screen';
		} elseif ( self::SETTINGS_PAGE === $page ) {
			$classes .= ' wpcs-settings-screen';
		}
		return $classes;
	}

	/* ------------------------------------------------------------------ */
	/* Small helpers                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * A service from the container, or null when that module is missing.
	 *
	 * @param string $name Property name on wpcybersec().
	 * @return object|null
	 */
	public static function service( $name ) {
		if ( ! function_exists( 'wpcybersec' ) ) {
			return null;
		}
		$plugin = wpcybersec();
		return ( isset( $plugin->$name ) && is_object( $plugin->$name ) ) ? $plugin->$name : null;
	}

	/**
	 * Calls a method of another module without ever fataling.
	 *
	 * @param string $service Service name.
	 * @param string $method  Method.
	 * @param array  $args    Arguments.
	 * @param mixed  $default Returned when the module or method is missing or throws.
	 * @return mixed
	 */
	public static function call( $service, $method, array $args = array(), $default = null ) {
		$object = self::service( $service );
		if ( ! $object || ! method_exists( $object, $method ) ) {
			return $default;
		}
		try {
			return call_user_func_array( array( $object, $method ), $args );
		} catch ( \Throwable $e ) {
			return $default;
		}
	}

	/**
	 * Writes an activity log entry when the logger exists.
	 *
	 * @param string $event   Event.
	 * @param string $message Message.
	 * @param array  $context Context.
	 */
	private static function log( $event, $message, array $context = array() ) {
		self::call( 'logger', 'log', array( $event, $message, $context ) );
	}

	/**
	 * Queues a notice for the next page view of the current user.
	 *
	 * @param string $message Plain text.
	 * @param string $type    ok | warn | bad | info.
	 */
	public static function flash( $message, $type = 'ok' ) {
		$key   = self::FLASH_PREFIX . get_current_user_id();
		$queue = get_transient( $key );
		$queue = is_array( $queue ) ? $queue : array();
		$queue[] = array(
			'message' => (string) $message,
			'type'    => in_array( $type, array( 'ok', 'warn', 'bad', 'info' ), true ) ? $type : 'info',
		);
		set_transient( $key, $queue, 5 * MINUTE_IN_SECONDS );
	}

	/**
	 * Returns and clears queued notices.
	 *
	 * @return array[] Each { message, type }.
	 */
	public static function take_flash() {
		$key   = self::FLASH_PREFIX . get_current_user_id();
		$queue = get_transient( $key );
		if ( false !== $queue ) {
			delete_transient( $key );
		}
		return is_array( $queue ) ? $queue : array();
	}

	/**
	 * @param string $tab  general | advanced.
	 * @param array  $args Extra query args.
	 * @param string $hash Optional fragment without "#".
	 * @return string
	 */
	public static function settings_url( $tab = 'general', array $args = array(), $hash = '' ) {
		$url = add_query_arg( array_merge( array( 'page' => self::SETTINGS_PAGE, 'tab' => $tab ), $args ), admin_url( 'admin.php' ) );
		return $url . ( $hash ? '#' . $hash : '' );
	}

	/**
	 * @param string $step Step key.
	 * @param array  $args Extra query args.
	 * @return string
	 */
	public static function wizard_url( $step = '', array $args = array() ) {
		$query = array( 'page' => self::WIZARD_PAGE );
		if ( $step ) {
			$query['step'] = $step;
		}
		return add_query_arg( array_merge( $query, $args ), admin_url( 'admin.php' ) );
	}

	/**
	 * Same rule as Admin::can(): manage_options, or manage_network_options on
	 * multisite, because these tools change files shared by the whole network.
	 *
	 * @return bool
	 */
	public static function user_can_manage() {
		if ( class_exists( '\WPCyberSecurity\Admin\Admin' ) ) {
			return Admin\Admin::can();
		}
		return current_user_can( is_multisite() ? 'manage_network_options' : 'manage_options' );
	}

	/**
	 * Capability and nonce gate for admin-post handlers. Dies on failure.
	 *
	 * @param string $nonce_action Nonce action.
	 */
	private function check_request( $nonce_action ) {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'wp-cyber-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce_action );
	}

	/**
	 * Redirects (only to this site) and exits.
	 *
	 * @param string $url Target.
	 */
	private function redirect( $url ) {
		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Redirects to the referring admin page, or the fallback.
	 *
	 * @param string $fallback Fallback URL.
	 */
	private function redirect_back( $fallback ) {
		$referer = wp_get_referer();
		$this->redirect( $referer ? $referer : $fallback );
	}

	/**
	 * Splits a textarea or comma list into trimmed, non-empty strings.
	 *
	 * @param mixed $raw String or array.
	 * @return string[]
	 */
	public static function parse_list( $raw ) {
		if ( is_array( $raw ) ) {
			$items = $raw;
		} else {
			$items = preg_split( '/[\r\n,;]+/', (string) $raw );
		}
		$out = array();
		foreach ( (array) $items as $item ) {
			$item = trim( sanitize_text_field( (string) $item ) );
			if ( '' !== $item ) {
				$out[] = $item;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Quotes a value for a POSIX shell only when needed, so snippets stay readable.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	public static function shell_arg( $value ) {
		$value = (string) $value;
		if ( '' !== $value && preg_match( '#^[A-Za-z0-9_@%+=:,./-]+$#', $value ) ) {
			return $value;
		}
		return "'" . str_replace( "'", "'\\''", $value ) . "'";
	}

	/**
	 * Server type from SERVER_SOFTWARE.
	 *
	 * @return string apache | litespeed | nginx | iis | unknown.
	 */
	public static function server_type() {
		$soft = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		if ( false !== strpos( $soft, 'litespeed' ) ) {
			return 'litespeed';
		}
		if ( false !== strpos( $soft, 'nginx' ) || false !== strpos( $soft, 'openresty' ) ) {
			return 'nginx';
		}
		if ( false !== strpos( $soft, 'apache' ) ) {
			return 'apache';
		}
		if ( false !== strpos( $soft, 'iis' ) ) {
			return 'iis';
		}
		return 'unknown';
	}

	/**
	 * PHP CLI binary for cron snippets: PHP_BINARY when it looks like a CLI
	 * binary, a CLI binary next to php-fpm when one exists, else "php".
	 *
	 * @return string
	 */
	public static function php_binary() {
		$bin  = defined( 'PHP_BINARY' ) ? wp_normalize_path( (string) PHP_BINARY ) : '';
		$base = strtolower( basename( $bin ) );
		if ( '' !== $bin && preg_match( '/^php(\d+(\.\d+)*)?(-cli)?(\.exe)?$/', $base ) ) {
			return self::stable_binary( $bin );
		}
		if ( '' !== $bin && preg_match( '/^php-?fpm([\d.]*)$/', $base, $m ) ) {
			$ver        = $m[1];
			$candidates = array(
				dirname( dirname( $bin ) ) . '/bin/php' . $ver,
				dirname( dirname( $bin ) ) . '/bin/php',
				'/usr/bin/php' . $ver,
				'/usr/local/bin/php' . $ver,
				'/usr/bin/php',
				'/usr/local/bin/php',
			);
			foreach ( $candidates as $candidate ) {
				if ( @is_file( $candidate ) && @is_executable( $candidate ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					return self::stable_binary( $candidate );
				}
			}
		}
		return 'php';
	}

	/**
	 * Homebrew keeps binaries in versioned Cellar folders that disappear on
	 * upgrade; prefer the stable "opt" link of the same formula.
	 *
	 * @param string $bin Binary path.
	 * @return string
	 */
	private static function stable_binary( $bin ) {
		if ( preg_match( '#^(.*)/Cellar/([^/]+)/[^/]+/bin/([^/]+)$#', $bin, $m ) ) {
			$link = $m[1] . '/opt/' . $m[2] . '/bin/' . $m[3];
			if ( @is_file( $link ) && @is_executable( $link ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return $link;
			}
		}
		return $bin;
	}

	/**
	 * @return string ABSPATH without trailing slash, normalized.
	 */
	private static function abspath() {
		return untrailingslashit( wp_normalize_path( ABSPATH ) );
	}

	/**
	 * Location of wp-config.php (WordPress also allows one folder up).
	 *
	 * @return string Empty when not found.
	 */
	public static function wp_config_path() {
		$here   = self::abspath() . '/wp-config.php';
		$parent = dirname( self::abspath() ) . '/wp-config.php';
		if ( @is_file( $here ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $here;
		}
		if ( @is_file( $parent ) && ! @is_file( dirname( self::abspath() ) . '/wp-settings.php' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $parent;
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/* Diagnostics                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Environment checks for the wizard and the advanced settings.
	 *
	 * @param bool $fresh True to ignore cached live probe results.
	 * @return array[] Each { id, label, status pass|warn|fail|info, detail, fix, code, actions[] }.
	 */
	public function diagnostics( $fresh = false ) {
		$methods = array(
			'check_php',
			'check_wordpress',
			'check_https',
			'check_data_dir',
			'check_quarantine_web',
			'check_uploads_php',
			'check_cron',
			'check_prepend',
			'check_exec',
			'check_open_basedir',
			'check_zip',
			'check_wp_config',
			'check_file_edit',
			'check_server',
			'check_plugins',
			'check_security_plugins',
		);
		$checks = array();
		foreach ( $methods as $method ) {
			try {
				$check = $this->$method( $fresh );
			} catch ( \Throwable $e ) {
				$check = array(
					'id'     => $method,
					'label'  => $method,
					'status' => 'info',
					/* translators: %s: error message */
					'detail' => sprintf( __( 'This check could not run: %s', 'wp-cyber-security' ), $e->getMessage() ),
				);
			}
			if ( $check ) {
				$checks[] = array_merge(
					array(
						'id'      => '',
						'label'   => '',
						'status'  => 'info',
						'detail'  => '',
						'fix'     => '',
						'code'    => '',
						'actions' => array(),
					),
					$check
				);
			}
		}

		/**
		 * Filters the environment checks.
		 *
		 * @param array[] $checks Checks.
		 */
		return apply_filters( 'wpcybersec_diagnostics', $checks );
	}

	/**
	 * @return array
	 */
	private function check_php() {
		$version = PHP_VERSION;
		$check   = array(
			'id'    => 'php_version',
			'label' => __( 'PHP version', 'wp-cyber-security' ),
		);
		if ( version_compare( $version, self::PHP_SUPPORTED, '>=' ) ) {
			$check['status'] = 'pass';
			/* translators: %s: PHP version */
			$check['detail'] = sprintf( __( 'PHP %s receives security fixes.', 'wp-cyber-security' ), $version );
		} else {
			$check['status'] = 'warn';
			/* translators: %s: PHP version */
			$check['detail'] = sprintf( __( 'PHP %s no longer receives security fixes.', 'wp-cyber-security' ), $version );
			/* translators: %s: PHP version */
			$check['fix'] = sprintf( __( 'Ask your host to switch this site to PHP %s or newer.', 'wp-cyber-security' ), self::PHP_SUPPORTED );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_wordpress() {
		$version = get_bloginfo( 'version' );
		$check   = array(
			'id'     => 'wp_version',
			'label'  => __( 'WordPress version', 'wp-cyber-security' ),
			'status' => 'pass',
			/* translators: %s: WordPress version */
			'detail' => sprintf( __( 'WordPress %s is up to date.', 'wp-cyber-security' ), $version ),
		);
		if ( ! function_exists( 'get_core_updates' ) && is_readable( ABSPATH . 'wp-admin/includes/update.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( function_exists( 'get_core_updates' ) ) {
			$updates = get_core_updates( array( 'dismissed' => false ) );
			foreach ( (array) $updates as $update ) {
				if ( is_object( $update ) && isset( $update->response, $update->current ) && 'upgrade' === $update->response ) {
					$check['status'] = 'warn';
					/* translators: 1: available version, 2: installed version */
					$check['detail'] = sprintf( __( 'WordPress %1$s is available. This site runs %2$s.', 'wp-cyber-security' ), $update->current, $version );
					$check['fix']    = __( 'Update from Dashboard > Updates. Security fixes ship in every release.', 'wp-cyber-security' );
					break;
				}
			}
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_https() {
		$https = is_ssl() || 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
		return array(
			'id'     => 'https',
			'label'  => __( 'HTTPS', 'wp-cyber-security' ),
			'status' => $https ? 'pass' : 'warn',
			'detail' => $https
				? __( 'The site is served over HTTPS.', 'wp-cyber-security' )
				: __( 'The site does not use HTTPS, so logins and cookies travel unencrypted.', 'wp-cyber-security' ),
			'fix'    => $https ? '' : __( 'Install a TLS certificate (most hosts offer a free one) and change the site address to https:// in Settings > General.', 'wp-cyber-security' ),
		);
	}

	/**
	 * @return array
	 */
	private function check_data_dir() {
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$dir     = $storage->data_dir();
		$check   = array(
			'id'    => 'data_dir',
			'label' => __( 'Data folder', 'wp-cyber-security' ),
		);
		if ( ! is_dir( $dir ) ) {
			$storage->ensure();
		}
		if ( ! is_dir( $dir ) || ! wp_is_writable( $dir ) ) {
			$check['status'] = 'fail';
			/* translators: %s: folder path */
			$check['detail'] = sprintf( __( '%s does not exist or is not writable. Held files cannot be stored.', 'wp-cyber-security' ), $dir );
			$check['fix']    = __( 'Make the folder writable by the web server user, for example: chown www-data and chmod 750.', 'wp-cyber-security' );
			return $check;
		}
		if ( $storage->is_in_webroot( $dir ) ) {
			$check['status'] = 'warn';
			/* translators: %s: folder path */
			$check['detail'] = sprintf( __( '%s is writable but inside the web root. Held files have random .bin names and deny rules, but a folder outside the web root is safer.', 'wp-cyber-security' ), $dir );
			$check['fix']    = __( 'For system administrators: move it outside the web root with this line in wp-config.php.', 'wp-cyber-security' );
			$snippet         = $this->data_dir_snippet();
			$check['code']   = $snippet['config'];
			return $check;
		}
		$check['status'] = 'pass';
		/* translators: %s: folder path */
		$check['detail'] = sprintf( __( '%s is writable and outside the web root.', 'wp-cyber-security' ), $dir );
		return $check;
	}

	/**
	 * @param bool $fresh Ignore the cached probe.
	 * @return array
	 */
	private function check_quarantine_web( $fresh = false ) {
		$check = array(
			'id'    => 'quarantine_web',
			'label' => __( 'Quarantine is not reachable from the web', 'wp-cyber-security' ),
		);
		$probe = $this->probe_quarantine_web( $fresh );
		switch ( $probe['result'] ) {
			case 'outside':
				$check['status'] = 'pass';
				$check['detail'] = __( 'The data folder is outside the web root.', 'wp-cyber-security' );
				break;
			case 'blocked':
				$check['status'] = 'pass';
				/* translators: %d: HTTP status code */
				$check['detail'] = sprintf( __( 'A test file in the quarantine folder could not be downloaded (HTTP %d).', 'wp-cyber-security' ), $probe['code'] );
				break;
			case 'reachable':
				$check['status'] = 'warn';
				$check['detail'] = __( 'A test file in the quarantine folder could be downloaded. The server ignores the .htaccess deny rules (typical for nginx). Held files cannot run, but they can be downloaded by anyone who guesses their name.', 'wp-cyber-security' );
				$check['fix']    = __( 'Add this rule to the nginx server block, or move the data folder outside the web root.', 'wp-cyber-security' );
				$check['code']   = $this->nginx_data_rule();
				break;
			default:
				$check['status'] = 'info';
				$check['detail'] = $probe['message'] ? $probe['message'] : __( 'Could not test web access automatically.', 'wp-cyber-security' );
				$check['actions'] = array( 'probe' );
		}
		return $check;
	}

	/**
	 * @param bool $fresh Ignore cached probe results (live probe only runs on request).
	 * @return array
	 */
	private function check_uploads_php( $fresh = false ) {
		unset( $fresh ); // The live PHP probe only runs when the administrator asks for it.
		$check  = array(
			'id'    => 'uploads_php',
			'label' => __( 'Uploads folder blocks PHP', 'wp-cyber-security' ),
		);
		$server = self::server_type();
		$cached = $this->cached_probe( 'uploads_php' );

		if ( $cached && 'executed' === $cached['result'] ) {
			$check['status'] = 'fail';
			$check['detail'] = __( 'Live test: a PHP file placed in the uploads folder was executed. A backdoor uploaded there would run.', 'wp-cyber-security' );
			if ( 'nginx' === $server ) {
				$check['fix']  = __( 'Add this rule to the nginx server block, then run the test again.', 'wp-cyber-security' );
				$check['code'] = $this->nginx_uploads_rule();
			} else {
				$check['fix']     = __( 'Write the blocking rule to uploads/.htaccess, then run the test again.', 'wp-cyber-security' );
				$check['actions'] = array( 'write_htaccess', 'probe' );
			}
			return $check;
		}
		if ( $cached && 'blocked' === $cached['result'] ) {
			$check['status'] = 'pass';
			if ( $cached['code'] ) {
				/* translators: %d: HTTP status code */
				$check['detail'] = sprintf( __( 'Live test: PHP files in the uploads folder do not run (HTTP %d).', 'wp-cyber-security' ), $cached['code'] );
			} else {
				$check['detail'] = __( 'Live test: PHP files in the uploads folder do not run.', 'wp-cyber-security' );
			}
			return $check;
		}

		$status = $this->uploads_htaccess_status();
		if ( in_array( $server, array( 'apache', 'litespeed' ), true ) ) {
			if ( 'ours' === $status ) {
				$check['status'] = 'pass';
				$check['detail'] = __( 'Blocked by the WP Cyber Security rules in uploads/.htaccess.', 'wp-cyber-security' );
			} elseif ( 'other' === $status ) {
				$check['status'] = 'pass';
				$check['detail'] = __( 'uploads/.htaccess contains rules that block PHP.', 'wp-cyber-security' );
			} else {
				$check['status']  = 'warn';
				$check['detail']  = __( 'No rule in uploads/.htaccess stops PHP files from running there. A file dropped in uploads by a vulnerable plugin could run.', 'wp-cyber-security' );
				$check['fix']     = __( 'Let the plugin add the rule (existing content is kept, and the change is undone if images stop loading), or run a live test first.', 'wp-cyber-security' );
				$check['actions'] = array( 'write_htaccess', 'probe' );
			}
			return $check;
		}
		if ( 'nginx' === $server ) {
			$check['status']  = 'info';
			$check['detail']  = __( 'nginx does not read .htaccess files, so the blocking rule must be in the server configuration.', 'wp-cyber-security' );
			$check['fix']     = __( 'Make sure the server block contains a rule like this one, then run a live test.', 'wp-cyber-security' );
			$check['code']    = $this->nginx_uploads_rule();
			$check['actions'] = array( 'probe' );
			return $check;
		}
		$check['status']  = 'info';
		$check['detail']  = __( 'Unknown web server. Run a live test to see whether PHP runs in the uploads folder.', 'wp-cyber-security' );
		$check['actions'] = array( 'probe' );
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_cron() {
		$disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		$next     = wp_next_scheduled( 'wpcybersec_scheduled_scan' );
		$check    = array(
			'id'    => 'wp_cron',
			'label' => __( 'Scheduled tasks (cron)', 'wp-cyber-security' ),
		);
		$snippets = $this->cron_snippets();
		if ( $next && $next < time() - HOUR_IN_SECONDS ) {
			$check['status'] = 'warn';
			/* translators: %s: time span, e.g. "3 hours" */
			$check['detail'] = sprintf( __( 'Scheduled tasks are late: the last scheduled scan was due %s ago, so cron is not running.', 'wp-cyber-security' ), human_time_diff( $next ) );
			$check['fix']    = __( 'Add a real cron job on the server:', 'wp-cyber-security' );
			$check['code']   = $snippets[0]['code'];
		} elseif ( $disabled ) {
			$check['status'] = 'pass';
			$check['detail'] = __( 'WP-Cron is disabled and tasks run on time, so a real cron job is in place.', 'wp-cyber-security' );
		} else {
			$check['status'] = 'info';
			$check['detail'] = __( 'WP-Cron runs when people visit the site. On quiet sites scheduled scans can start late.', 'wp-cyber-security' );
			$check['fix']    = __( 'Recommended for system administrators: a real cron job (all variants are in Settings > Advanced).', 'wp-cyber-security' );
			$check['code']   = $snippets[0]['code'];
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_prepend() {
		$prepend   = trim( (string) ini_get( 'auto_prepend_file' ) );
		$bootstrap = (string) self::call( 'guard_manager', 'bootstrap_path', array(), ABSPATH . 'wpcybersec-guard.php' );
		$check     = array(
			'id'    => 'auto_prepend_file',
			'label' => __( 'auto_prepend_file', 'wp-cyber-security' ),
		);
		if ( '' === $prepend || 'none' === strtolower( $prepend ) ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'Not set. The optional early upload guard is not active.', 'wp-cyber-security' );
			$check['fix']    = __( 'System administrators can install the early guard in Settings > Advanced. It also holds uploads sent to PHP files outside WordPress.', 'wp-cyber-security' );
			return $check;
		}
		$real_prepend   = @realpath( $prepend ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$real_bootstrap = @realpath( $bootstrap ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ( $real_prepend && $real_bootstrap && $real_prepend === $real_bootstrap ) || wp_normalize_path( $prepend ) === wp_normalize_path( $bootstrap ) ) {
			$check['status'] = 'pass';
			$check['detail'] = __( 'The early upload guard is active.', 'wp-cyber-security' );
			return $check;
		}
		$check['status'] = 'info';
		if ( false !== stripos( $prepend, 'wordfence-waf' ) ) {
			/* translators: %s: file path */
			$check['detail'] = sprintf( __( 'Used by the Wordfence firewall (%s).', 'wp-cyber-security' ), $prepend );
			$check['fix']    = __( 'Both can run: the early guard bootstrap can include the Wordfence file. See Settings > Advanced > Early upload guard.', 'wp-cyber-security' );
		} else {
			/* translators: %s: file path */
			$check['detail'] = sprintf( __( 'Already used by another file: %s', 'wp-cyber-security' ), $prepend );
			$check['fix']    = __( 'Only one auto_prepend_file can be set. Check what that file does before you install the early guard.', 'wp-cyber-security' );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_exec() {
		$parts = array();
		foreach ( array( 'exec', 'proc_open', 'shell_exec' ) as $function ) {
			$parts[] = sprintf(
				'%1$s(): %2$s',
				$function,
				self::function_available( $function ) ? __( 'available', 'wp-cyber-security' ) : __( 'disabled', 'wp-cyber-security' )
			);
		}
		$clam   = $this->clamav_detect();
		$detail = implode( ', ', $parts ) . '. ';
		$detail .= $clam
			/* translators: %s: binary path */
			? sprintf( __( 'ClamAV found at %s.', 'wp-cyber-security' ), $clam )
			: __( 'ClamAV not found.', 'wp-cyber-security' );
		$check = array(
			'id'     => 'exec',
			'label'  => __( 'Command execution and ClamAV', 'wp-cyber-security' ),
			'status' => 'info',
			'detail' => $detail,
		);
		$settings = self::service( 'settings' );
		if ( $clam && self::function_available( 'exec' ) && $settings && ! $settings->get( 'clamav_enabled', false ) ) {
			$check['fix'] = __( 'Turn on ClamAV in Settings > Advanced for a second opinion on uploads.', 'wp-cyber-security' );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_open_basedir() {
		$value = trim( (string) ini_get( 'open_basedir' ) );
		if ( '' === $value ) {
			return array(
				'id'     => 'open_basedir',
				'label'  => __( 'open_basedir', 'wp-cyber-security' ),
				'status' => 'info',
				'detail' => __( 'Not set. PHP can read every folder the web server user can read.', 'wp-cyber-security' ),
			);
		}
		$check = array(
			'id'     => 'open_basedir',
			'label'  => __( 'open_basedir', 'wp-cyber-security' ),
			'status' => 'pass',
			/* translators: %s: list of folders */
			'detail' => sprintf( __( 'PHP is restricted to: %s', 'wp-cyber-security' ), $value ),
		);
		$parent = dirname( self::abspath() );
		if ( ! @is_readable( $parent ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$check['status'] = 'info';
			$check['fix']    = __( 'The folder above WordPress cannot be read, so the "parent folder" scan scope is not available.', 'wp-cyber-security' );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_zip() {
		$ok = class_exists( 'ZipArchive' );
		return array(
			'id'     => 'zip',
			'label'  => __( 'ZipArchive', 'wp-cyber-security' ),
			'status' => $ok ? 'pass' : 'warn',
			'detail' => $ok
				? __( 'Plugin and theme ZIP files can be inspected before you approve them.', 'wp-cyber-security' )
				: __( 'The PHP zip extension is missing, so plugin and theme ZIP files cannot be inspected before approval.', 'wp-cyber-security' ),
			'fix'    => $ok ? '' : __( 'Ask your host to enable the PHP zip extension.', 'wp-cyber-security' ),
		);
	}

	/**
	 * @return array
	 */
	private function check_wp_config() {
		$file  = self::wp_config_path();
		$check = array(
			'id'    => 'wp_config_perms',
			'label' => __( 'wp-config.php permissions', 'wp-cyber-security' ),
		);
		if ( '' === $file ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'wp-config.php was not found in the usual places.', 'wp-cyber-security' );
			return $check;
		}
		if ( '\\' === DIRECTORY_SEPARATOR ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'File permissions cannot be checked on Windows servers.', 'wp-cyber-security' );
			return $check;
		}
		$perms = @fileperms( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $perms ) {
			$check['status'] = 'info';
			$check['detail'] = __( 'The permissions of wp-config.php could not be read.', 'wp-cyber-security' );
			return $check;
		}
		$mode = substr( sprintf( '%o', $perms ), -4 );
		$cmd  = 'chmod 640 ' . self::shell_arg( $file );
		if ( $perms & 0002 ) {
			$check['status'] = 'fail';
			/* translators: %s: permission bits, e.g. 0666 */
			$check['detail'] = sprintf( __( 'wp-config.php is writable by every user on the server (%s).', 'wp-cyber-security' ), $mode );
			$check['fix']    = __( 'Restrict it (use 600 when PHP runs as the file owner):', 'wp-cyber-security' );
			$check['code']   = $cmd;
		} elseif ( $perms & 0004 ) {
			$check['status'] = 'warn';
			/* translators: %s: permission bits, e.g. 0644 */
			$check['detail'] = sprintf( __( 'wp-config.php is readable by every user on the server (%s). It holds the database password.', 'wp-cyber-security' ), $mode );
			$check['fix']    = __( 'Restrict it (use 600 when PHP runs as the file owner):', 'wp-cyber-security' );
			$check['code']   = $cmd;
		} else {
			$check['status'] = 'pass';
			/* translators: %s: permission bits, e.g. 0640 */
			$check['detail'] = sprintf( __( 'Not readable by other users (%s).', 'wp-cyber-security' ), $mode );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_file_edit() {
		$off = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		return array(
			'id'     => 'file_edit',
			'label'  => __( 'Theme and plugin file editor', 'wp-cyber-security' ),
			'status' => $off ? 'pass' : 'warn',
			'detail' => $off
				? __( 'The built-in code editor is disabled.', 'wp-cyber-security' )
				: __( 'The built-in code editor is enabled. Anyone who steals an administrator login can use it to plant code.', 'wp-cyber-security' ),
			'fix'    => $off ? '' : __( 'Add this line to wp-config.php:', 'wp-cyber-security' ),
			'code'   => $off ? '' : "define( 'DISALLOW_FILE_EDIT', true );",
		);
	}

	/**
	 * @return array
	 */
	private function check_server() {
		$soft  = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '';
		$type  = self::server_type();
		$names = array(
			'apache'    => 'Apache',
			'litespeed' => 'LiteSpeed',
			'nginx'     => 'nginx',
			'iis'       => 'IIS',
			'unknown'   => __( 'Unknown', 'wp-cyber-security' ),
		);
		$check = array(
			'id'     => 'server',
			'label'  => __( 'Web server', 'wp-cyber-security' ),
			'status' => 'info',
			/* translators: 1: server name, 2: PHP SAPI */
			'detail' => sprintf( __( '%1$s, PHP runs as %2$s.', 'wp-cyber-security' ), $soft ? $soft : $names[ $type ], PHP_SAPI ),
		);
		if ( 'nginx' === $type ) {
			$check['fix'] = __( 'nginx ignores .htaccess files. Copy the nginx rules from Settings > Advanced into the server configuration.', 'wp-cyber-security' );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all      = get_plugins();
		$active   = (array) get_option( 'active_plugins', array() );
		$network  = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		$active   = array_unique( array_merge( $active, $network ) );
		$total    = count( $all );
		$on       = count( array_intersect( array_keys( $all ), $active ) );
		$inactive = max( 0, $total - $on );
		$check    = array(
			'id'     => 'plugins',
			'label'  => __( 'Installed plugins', 'wp-cyber-security' ),
			'status' => 'info',
			/* translators: 1: installed plugins, 2: active plugins */
			'detail' => sprintf( _n( '%1$d plugin installed, %2$d active.', '%1$d plugins installed, %2$d active.', $total, 'wp-cyber-security' ), $total, $on ),
		);
		if ( $inactive > 0 ) {
			$check['fix'] = __( 'Delete inactive plugins you do not need: their files stay on the server and can still be attacked.', 'wp-cyber-security' );
		}
		return $check;
	}

	/**
	 * @return array
	 */
	private function check_security_plugins() {
		$known  = array(
			'wordfence'                          => 'Wordfence',
			'sucuri-scanner'                     => 'Sucuri Security',
			'better-wp-security'                 => 'Solid Security (iThemes)',
			'ithemes-security-pro'               => 'Solid Security Pro',
			'all-in-one-wp-security-and-firewall' => 'All-In-One Security (AIOS)',
			'wp-simple-firewall'                 => 'Shield Security',
			'malcare-security'                   => 'MalCare',
			'defender-security'                  => 'Defender',
			'ninjafirewall'                      => 'NinjaFirewall',
		);
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		$found = array();
		foreach ( $active as $basename ) {
			$folder = strtok( (string) $basename, '/' );
			if ( isset( $known[ $folder ] ) ) {
				$found[ $folder ] = $known[ $folder ];
			}
		}
		$check = array(
			'id'     => 'security_plugins',
			'label'  => __( 'Other security plugins', 'wp-cyber-security' ),
			'status' => 'info',
		);
		if ( $found ) {
			/* translators: %s: plugin names */
			$check['detail'] = sprintf( __( 'Active: %s. They can run side by side with WP Cyber Security.', 'wp-cyber-security' ), implode( ', ', $found ) );
			$check['fix']    = __( 'If both scan uploads, uploading can take a little longer. Avoid two plugins changing the same .htaccess rules.', 'wp-cyber-security' );
		} else {
			$check['detail'] = __( 'None detected.', 'wp-cyber-security' );
		}
		return $check;
	}

	/**
	 * @param string $function Function name.
	 * @return bool
	 */
	public static function function_available( $function ) {
		if ( ! function_exists( $function ) ) {
			return false;
		}
		$disabled = array_map( 'trim', explode( ',', strtolower( (string) ini_get( 'disable_functions' ) ) ) );
		return ! in_array( strtolower( $function ), $disabled, true );
	}

	/**
	 * Finds a ClamAV binary (configured one first).
	 *
	 * @return string Path or ''.
	 */
	public function clamav_detect() {
		$settings   = self::service( 'settings' );
		$configured = $settings ? (string) $settings->get( 'clamav_binary', '' ) : '';
		$candidates = array_filter(
			array(
				$configured,
				'/usr/bin/clamdscan',
				'/usr/local/bin/clamdscan',
				'/usr/bin/clamscan',
				'/usr/local/bin/clamscan',
				'/opt/homebrew/bin/clamdscan',
				'/opt/homebrew/bin/clamscan',
			)
		);
		foreach ( $candidates as $candidate ) {
			if ( @is_file( $candidate ) && @is_executable( $candidate ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return wp_normalize_path( $candidate );
			}
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/* Live web probes                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $key Probe key.
	 * @return array|null
	 */
	private function cached_probe( $key ) {
		$all = get_transient( self::PROBE_TRANSIENT );
		return ( is_array( $all ) && isset( $all[ $key ] ) && is_array( $all[ $key ] ) ) ? $all[ $key ] : null;
	}

	/**
	 * @param string $key    Probe key.
	 * @param array  $result Result.
	 */
	private function cache_probe( $key, array $result ) {
		$all         = get_transient( self::PROBE_TRANSIENT );
		$all         = is_array( $all ) ? $all : array();
		$all[ $key ] = $result;
		set_transient( self::PROBE_TRANSIENT, $all, HOUR_IN_SECONDS );
	}

	/**
	 * Absolute URL of a path under the WordPress or content folder, or ''.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private static function url_for_path( $path ) {
		$path    = wp_normalize_path( $path );
		$content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
		if ( 0 === strpos( $path . '/', $content . '/' ) ) {
			return content_url( ltrim( substr( $path, strlen( $content ) ), '/' ) );
		}
		$abs = self::abspath();
		if ( 0 === strpos( $path . '/', $abs . '/' ) ) {
			return site_url( ltrim( substr( $path, strlen( $abs ) ), '/' ) );
		}
		return '';
	}

	/**
	 * Writes a temporary file, requests it over HTTP and deletes it again.
	 *
	 * @param string $file    Absolute file path.
	 * @param string $url     URL of that file.
	 * @param string $content Content.
	 * @return array { code: int, body: string, error: string }
	 */
	private function http_probe( $file, $url, $content ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === @file_put_contents( $file, $content ) ) {
			return array(
				'code'  => 0,
				'body'  => '',
				'error' => __( 'Could not write a test file.', 'wp-cyber-security' ),
			);
		}
		@chmod( $file, 0644 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 4,
				'redirection' => 0,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		@unlink( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( is_wp_error( $response ) ) {
			return array(
				'code'  => 0,
				'body'  => '',
				'error' => $response->get_error_message(),
			);
		}
		return array(
			'code'  => (int) wp_remote_retrieve_response_code( $response ),
			'body'  => (string) wp_remote_retrieve_body( $response ),
			'error' => '',
		);
	}

	/**
	 * Tests whether files in the quarantine folder can be downloaded.
	 *
	 * @param bool $fresh Ignore the cached result.
	 * @return array { result: outside|blocked|reachable|unknown, code, message, time }
	 */
	public function probe_quarantine_web( $fresh = false ) {
		if ( ! $fresh ) {
			$cached = $this->cached_probe( 'quarantine_web' );
			if ( $cached ) {
				return $cached;
			}
		}
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$result  = array(
			'result'  => 'unknown',
			'code'    => 0,
			'message' => '',
			'time'    => time(),
		);
		if ( ! $storage->is_in_webroot( $storage->data_dir() ) ) {
			$result['result'] = 'outside';
			$this->cache_probe( 'quarantine_web', $result );
			return $result;
		}
		$storage->ensure();
		$dir = $storage->quarantine_dir();
		$url = self::url_for_path( $dir );
		if ( '' === $url || ! is_dir( $dir ) ) {
			$result['message'] = __( 'The data folder is inside the web root but its address could not be worked out, so web access was not tested.', 'wp-cyber-security' );
			$this->cache_probe( 'quarantine_web', $result );
			return $result;
		}
		$token = 'wpcs-' . wp_generate_password( 24, false, false );
		$name  = 'wpcs-probe-' . strtolower( wp_generate_password( 12, false, false ) ) . '.txt';
		$probe = $this->http_probe( $dir . '/' . $name, trailingslashit( $url ) . $name, $token );
		if ( $probe['error'] ) {
			/* translators: %s: error message */
			$result['message'] = sprintf( __( 'Could not test web access: the site could not reach itself (%s).', 'wp-cyber-security' ), $probe['error'] );
		} elseif ( 200 === $probe['code'] && false !== strpos( $probe['body'], $token ) ) {
			$result['result'] = 'reachable';
			$result['code']   = 200;
		} elseif ( $probe['code'] >= 400 ) {
			$result['result'] = 'blocked';
			$result['code']   = $probe['code'];
		} else {
			/* translators: %d: HTTP status code */
			$result['message'] = sprintf( __( 'Web access test was inconclusive (HTTP %d).', 'wp-cyber-security' ), $probe['code'] );
		}
		$this->cache_probe( 'quarantine_web', $result );
		return $result;
	}

	/**
	 * Live test: does a PHP file in the uploads folder execute? Only run on request.
	 * The test file prints a reversed token, so served-as-text and executed are
	 * told apart, and it is deleted immediately.
	 *
	 * @return array { result: executed|blocked|unknown, code, message, time }
	 */
	public function probe_uploads_php() {
		$result  = array(
			'result'  => 'unknown',
			'code'    => 0,
			'message' => '',
			'time'    => time(),
		);
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) || ! is_dir( $uploads['basedir'] ) ) {
			$result['message'] = __( 'The uploads folder could not be found.', 'wp-cyber-security' );
			$this->cache_probe( 'uploads_php', $result );
			return $result;
		}
		$token = 'wpcs' . strtolower( wp_generate_password( 20, false, false ) );
		$name  = 'wpcs-probe-' . strtolower( wp_generate_password( 12, false, false ) ) . '.php';
		$code  = "<?php\n// WP Cyber Security temporary test file. Safe to delete.\necho strrev( '" . strrev( $token ) . "' );\n";
		$file  = trailingslashit( wp_normalize_path( $uploads['basedir'] ) ) . $name;
		register_shutdown_function(
			static function () use ( $file ) {
				if ( file_exists( $file ) ) {
					@unlink( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				}
			}
		);
		$probe = $this->http_probe( $file, trailingslashit( $uploads['baseurl'] ) . $name, $code );
		if ( $probe['error'] ) {
			/* translators: %s: error message */
			$result['message'] = sprintf( __( 'The live test could not run: %s', 'wp-cyber-security' ), $probe['error'] );
		} elseif ( 200 === $probe['code'] && $token === trim( $probe['body'] ) ) {
			$result['result'] = 'executed';
			$result['code']   = 200;
		} else {
			$result['result'] = 'blocked';
			$result['code']   = $probe['code'];
		}
		$this->cache_probe( 'uploads_php', $result );
		return $result;
	}

	/* ------------------------------------------------------------------ */
	/* Uploads .htaccess                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * @return string Absolute uploads folder ('' when unknown).
	 */
	private static function uploads_dir() {
		$uploads = wp_upload_dir( null, false );
		return empty( $uploads['basedir'] ) ? '' : untrailingslashit( wp_normalize_path( $uploads['basedir'] ) );
	}

	/**
	 * What protects the uploads folder on Apache.
	 *
	 * @return string ours | other | none.
	 */
	public function uploads_htaccess_status() {
		$dir = self::uploads_dir();
		if ( '' === $dir || ! is_readable( $dir . '/.htaccess' ) ) {
			return 'none';
		}
		$content = (string) @file_get_contents( $dir . '/.htaccess' ); // phpcs:ignore
		if ( false !== strpos( $content, '# BEGIN ' . self::MARKER ) ) {
			return 'ours';
		}
		if ( preg_match( '/php_flag\s+engine\s+off|<Files(Match)?\s[^>]*php[^>]*>\s*(Require\s+all\s+denied|deny\s+from\s+all|Order)/i', $content ) ) {
			return 'other';
		}
		return 'none';
	}

	/**
	 * Apache rules that stop PHP from running in the uploads folder, wrapped in
	 * the plugin's markers. Works on Apache 2.2 and 2.4, mod_php and PHP-FPM.
	 *
	 * @return string
	 */
	public function apache_uploads_rules() {
		$lines = array(
			'# BEGIN ' . self::MARKER,
			'# Blocks PHP execution in the uploads folder. Remove this block to undo.',
			'<FilesMatch "\.(?i:php[3-8]?|phtml|phar|pht|phps)(\.|$)|\.(?i:inc)$">',
			"\t<IfModule mod_authz_core.c>",
			"\t\tRequire all denied",
			"\t</IfModule>",
			"\t<IfModule !mod_authz_core.c>",
			"\t\tOrder allow,deny",
			"\t\tDeny from all",
			"\t</IfModule>",
			'</FilesMatch>',
			'<IfModule mod_php.c>',
			"\tphp_flag engine off",
			'</IfModule>',
			'<IfModule mod_php7.c>',
			"\tphp_flag engine off",
			'</IfModule>',
			'<IfModule mod_php5.c>',
			"\tphp_flag engine off",
			'</IfModule>',
			'# END ' . self::MARKER,
		);
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Replaces the plugin's marked block (all copies) with $block, or appends it.
	 *
	 * @param string $content Existing file content.
	 * @param string $block   New block including markers.
	 * @return string
	 */
	public static function replace_marked_block( $content, $block ) {
		$pattern = '/^[ \t]*# BEGIN ' . preg_quote( self::MARKER, '/' ) . '[ \t]*\R.*?^[ \t]*# END ' . preg_quote( self::MARKER, '/' ) . '[ \t]*(\R|\z)/ms';
		if ( ! preg_match( $pattern, $content ) ) {
			return '' === trim( $content ) ? $block : rtrim( $content, "\r\n" ) . "\n\n" . $block;
		}
		$first = false;
		return preg_replace_callback(
			$pattern,
			static function () use ( &$first, $block ) {
				if ( $first ) {
					return '';
				}
				$first = true;
				return $block;
			},
			$content
		);
	}

	/**
	 * Adds (or refreshes) the PHP blocking block in wp-content/uploads/.htaccess.
	 * Idempotent: never duplicates the block and keeps all other content. When
	 * the server answers 500 afterwards (directives not allowed), the previous
	 * file is put back.
	 *
	 * @return string|\WP_Error "written" or "unchanged".
	 */
	public function write_uploads_htaccess() {
		$dir = self::uploads_dir();
		if ( '' === $dir ) {
			return new \WP_Error( 'wpcybersec_uploads', __( 'The uploads folder could not be found.', 'wp-cyber-security' ) );
		}
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'wpcybersec_uploads', __( 'The uploads folder does not exist and could not be created.', 'wp-cyber-security' ) );
		}
		$file   = $dir . '/.htaccess';
		$exists = file_exists( $file );
		if ( $exists && ( is_link( $file ) || ! is_file( $file ) ) ) {
			return new \WP_Error( 'wpcybersec_htaccess', __( 'uploads/.htaccess is not a regular file. Add the rules by hand.', 'wp-cyber-security' ) );
		}
		$old = $exists ? @file_get_contents( $file ) : ''; // phpcs:ignore
		if ( false === $old ) {
			return new \WP_Error( 'wpcybersec_htaccess', __( 'uploads/.htaccess exists but cannot be read. Add the rules by hand.', 'wp-cyber-security' ) );
		}
		$new = self::replace_marked_block( (string) $old, $this->apache_uploads_rules() );
		if ( $new === $old ) {
			return 'unchanged';
		}
		/*
		 * .htaccess is an executable name, so the file monitor reports (or, in
		 * strict mode, quarantines) any change it did not see coming. The new
		 * content is trusted only when everything in it was already trusted: a
		 * new file holds nothing but this block, an existing one must match the
		 * trusted fingerprint. Unreviewed content stays up for review.
		 */
		$old_trusted = $exists && self::manifest_trusts( $file, (string) $old );
		$trust_new   = ! $exists || $old_trusted;
		if ( ( $exists && ! wp_is_writable( $file ) ) || ( ! $exists && ! wp_is_writable( $dir ) ) ) {
			return new \WP_Error( 'wpcybersec_htaccess', __( 'uploads/.htaccess is not writable. Copy the rules from Settings > Advanced and add them by hand.', 'wp-cyber-security' ) );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === @file_put_contents( $file, $new, LOCK_EX ) ) {
			return new \WP_Error( 'wpcybersec_htaccess', __( 'Could not write uploads/.htaccess. Check the file permissions.', 'wp-cyber-security' ) );
		}
		@chmod( $file, 0644 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		/*
		 * Make sure normal files in uploads still load. Apache answers 500 for
		 * every file in the folder when AllowOverride does not permit these
		 * directives, so the change is undone unless a test file still loads.
		 */
		$uploads = wp_upload_dir( null, false );
		if ( in_array( self::server_type(), array( 'apache', 'litespeed', 'unknown' ), true ) ) {
			$rollback = static function () use ( $exists, $file, $old, $old_trusted ) {
				if ( $exists ) {
					@file_put_contents( $file, $old, LOCK_EX ); // phpcs:ignore
					// Same bytes as before, new mtime: refresh the fingerprint so the next scan skips it.
					if ( $old_trusted ) {
						self::call( 'file_monitor', 'trust_file', array( $file ) );
					}
				} else {
					@unlink( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				}
			};
			if ( empty( $uploads['baseurl'] ) ) {
				$rollback();
				return new \WP_Error( 'wpcybersec_htaccess_unverified', __( 'The address of the uploads folder is unknown, so the rules could not be checked and nothing was changed. Add them by hand from Settings > Advanced.', 'wp-cyber-security' ) );
			}
			$name  = 'wpcs-probe-' . strtolower( wp_generate_password( 12, false, false ) ) . '.txt';
			$probe = $this->http_probe( $dir . '/' . $name, trailingslashit( $uploads['baseurl'] ) . $name, 'ok' );
			if ( $probe['error'] ) {
				$rollback();
				return new \WP_Error(
					'wpcybersec_htaccess_unverified',
					/* translators: %s: error message */
					sprintf( __( 'The site could not reach itself to check that uploads still load after the change (%s), so nothing was changed. Add the rules by hand from Settings > Advanced, then check that images still load.', 'wp-cyber-security' ), $probe['error'] )
				);
			}
			if ( $probe['code'] >= 500 ) {
				$rollback();
				return new \WP_Error(
					'wpcybersec_htaccess_500',
					/* translators: %d: HTTP status code */
					sprintf( __( 'The server rejected the new rules (HTTP %d), so they were removed again. This host does not allow these directives in .htaccess (AllowOverride); ask your host to block PHP in the uploads folder.', 'wp-cyber-security' ), $probe['code'] )
				);
			}
		}

		$all = get_transient( self::PROBE_TRANSIENT );
		if ( is_array( $all ) && isset( $all['uploads_php'] ) ) {
			unset( $all['uploads_php'] );
			set_transient( self::PROBE_TRANSIENT, $all, HOUR_IN_SECONDS );
		}
		if ( $trust_new ) {
			self::call( 'file_monitor', 'trust_file', array( $file ) );
		}
		self::log( 'htaccess_written', __( 'Added the PHP blocking rules to uploads/.htaccess.', 'wp-cyber-security' ), array( 'file' => $file ) );
		return 'written';
	}

	/**
	 * Whether the file monitor already trusts exactly these bytes at this path.
	 *
	 * @param string $file    Absolute path.
	 * @param string $content File content.
	 * @return bool
	 */
	private static function manifest_trusts( $file, $content ) {
		$row = self::call( 'store', 'manifest_get', array( Paths::rel( wp_normalize_path( $file ) ) ) );
		return is_array( $row )
			&& Store::STATE_TRUSTED === (string) $row['state']
			&& '' !== (string) $row['sha256']
			&& hash_equals( (string) $row['sha256'], hash( 'sha256', (string) $content ) );
	}

	/* ------------------------------------------------------------------ */
	/* Snippets                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Real cron snippets with absolute paths.
	 *
	 * @return array[] Each { id, label, file, code, help }.
	 */
	public function cron_snippets() {
		$php     = self::shell_arg( self::php_binary() );
		$cron    = self::shell_arg( wp_normalize_path( WPCYBERSEC_DIR ) . 'bin/cron.php' );
		$wp      = self::shell_arg( self::abspath() );
		$wp_cron = self::shell_arg( self::abspath() . '/wp-cron.php' );

		return array(
			array(
				'id'    => 'crontab',
				'label' => __( 'System cron with PHP', 'wp-cyber-security' ),
				'file'  => __( 'crontab -e (as the web server user)', 'wp-cyber-security' ),
				'code'  => "# WP Cyber Security: quick scan every hour, full malware scan every night.\n"
					. "17 * * * * {$php} {$cron} --wp={$wp} > /dev/null 2>&1\n"
					. "30 3 * * * {$php} {$cron} --full --wp={$wp} > /dev/null 2>&1\n"
					. "# Run the rest of WordPress cron every 5 minutes.\n"
					. "*/5 * * * * {$php} {$wp_cron} > /dev/null 2>&1",
				'help'  => __( 'Add these lines to the crontab of the user that owns the site files (often www-data). Only one scan runs at a time, so overlapping runs are harmless.', 'wp-cyber-security' ),
			),
			array(
				'id'    => 'wpcli',
				'label' => __( 'System cron with WP-CLI', 'wp-cyber-security' ),
				'file'  => __( 'crontab -e (as the web server user)', 'wp-cyber-security' ),
				'code'  => "17 * * * * wp wpcybersec scan --path={$wp} --quiet\n"
					. "30 3 * * * wp wpcybersec scan --full --path={$wp} --quiet\n"
					. "*/5 * * * * wp cron event run --due-now --path={$wp} --quiet",
				'help'  => __( 'Use this variant when WP-CLI is installed. Use the full path to wp if cron cannot find it.', 'wp-cyber-security' ),
			),
			array(
				'id'    => 'wpconfig',
				'label' => __( 'Switch off WP-Cron on page visits', 'wp-cyber-security' ),
				'file'  => 'wp-config.php',
				'code'  => "define( 'DISABLE_WP_CRON', true );",
				'help'  => __( 'Add this only after the cron lines above are active, above the line "That\'s all, stop editing!".', 'wp-cyber-security' ),
			),
		);
	}

	/**
	 * URL path (no host) of a folder under the site, or ''.
	 *
	 * @param string $path Absolute folder.
	 * @return string
	 */
	private static function url_path_for( $path ) {
		$url = self::url_for_path( $path );
		if ( '' === $url ) {
			return '';
		}
		$url_path = (string) wp_parse_url( $url, PHP_URL_PATH );
		return '/' . trim( $url_path, '/' ) . '/';
	}

	/**
	 * nginx rule that blocks PHP in uploads.
	 *
	 * @return string
	 */
	private function nginx_uploads_rule() {
		$path = self::url_path_for( self::uploads_dir() );
		$path = '' !== $path ? $path : '/wp-content/uploads/';
		return 'location ~* ^' . str_replace( '\\-', '-', preg_quote( $path, '#' ) ) . '.*\\.(php[3-8]?|phtml|phar|pht|phps|inc)$ {' . "\n    deny all;\n}";
	}

	/**
	 * nginx rule that blocks the data folder (empty comment when outside the web root).
	 *
	 * @return string
	 */
	private function nginx_data_rule() {
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$path    = self::url_path_for( $storage->data_dir() );
		if ( '' === $path || ! $storage->is_in_webroot( $storage->data_dir() ) ) {
			return '# ' . __( 'The data folder is outside the web root: nothing to block.', 'wp-cyber-security' );
		}
		return 'location ^~ ' . $path . " {\n    deny all;\n}";
	}

	/**
	 * Full nginx snippet: PHP in uploads, the data folder and the guard bootstrap.
	 *
	 * @return string
	 */
	public function nginx_rules() {
		$guard = (string) wp_parse_url( site_url( '/' ), PHP_URL_PATH );
		$guard = '/' . trim( $guard, '/' ) . '/wpcybersec-guard.php';
		$guard = str_replace( '//', '/', $guard );
		return '# ' . __( 'Inside the server { } block of this site, above the generic "location ~ \.php$" block.', 'wp-cyber-security' ) . "\n"
			. '# ' . __( 'Block PHP execution in uploads.', 'wp-cyber-security' ) . "\n"
			. $this->nginx_uploads_rule() . "\n\n"
			. '# ' . __( 'Block web access to the WP Cyber Security data folder.', 'wp-cyber-security' ) . "\n"
			. $this->nginx_data_rule() . "\n\n"
			. '# ' . __( 'The early guard bootstrap is only loaded through auto_prepend_file.', 'wp-cyber-security' ) . "\n"
			. 'location = ' . $guard . " {\n    deny all;\n}\n\n"
			. '# ' . __( 'Then test and reload:', 'wp-cyber-security' ) . "\n"
			. '#   nginx -t && systemctl reload nginx';
	}

	/**
	 * Shell commands for safe file permissions.
	 *
	 * @return string
	 */
	public function permission_commands() {
		$root    = self::shell_arg( self::abspath() );
		$config  = self::wp_config_path();
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$data    = self::shell_arg( $storage->data_dir() );
		$uploads = self::shell_arg( self::uploads_dir() );

		$lines = array(
			'# ' . __( 'Run as root or with sudo. Replace www-data and deploy with your web server user and your SSH user.', 'wp-cyber-security' ),
			'cd ' . $root,
			'find . -type d -exec chmod 755 {} +',
			'find . -type f -exec chmod 644 {} +',
		);
		if ( '' !== $config ) {
			$lines[] = 'chmod 640 ' . self::shell_arg( $config );
		}
		$lines[] = 'chmod 750 ' . $data;
		$lines[] = '';
		$lines[] = '# ' . __( 'Stricter: code owned by your SSH user and read-only for PHP; only uploads and the data folder stay writable.', 'wp-cyber-security' );
		$lines[] = '# ' . __( 'Updates from the dashboard stop working with this; update with WP-CLI as deploy instead.', 'wp-cyber-security' );
		$lines[] = '# chown -R deploy:www-data .';
		$lines[] = '# chown -R www-data:www-data ' . $uploads . ' ' . $data;
		return implode( "\n", $lines );
	}

	/**
	 * Streams the fapolicyd trust list: one "path size sha256" line for every
	 * trusted manifest file under the scan root.
	 *
	 * @return \Generator Lines without newline.
	 */
	public function fapolicyd_trust_export() {
		$store = self::service( 'store' );
		yield '# fapolicyd trust file generated by WP Cyber Security on ' . gmdate( 'Y-m-d H:i:s' ) . ' UTC';
		yield '# Site: ' . home_url( '/' );
		yield '# Format: path size sha256. Install it as /etc/fapolicyd/trust.d/wordpress.trust and run: fapolicyd-cli --update';
		if ( ! $store || ! method_exists( $store, 'manifest_page' ) ) {
			yield '# The file manifest is not available.';
			return;
		}
		$root    = Paths::scan_root();
		$offset  = 0;
		$limit   = 2000;
		$skipped = 0;
		$count   = 0;
		do {
			$rows = $store->manifest_page( $limit, $offset );
			foreach ( $rows as $row ) {
				$abs = Paths::is_absolute( (string) $row['path'] ) ? wp_normalize_path( $row['path'] ) : $root . ltrim( (string) $row['path'], '/' );
				$sha = strtolower( (string) $row['sha256'] );
				if ( ! preg_match( '/^[a-f0-9]{64}$/', $sha ) || preg_match( '/[\s\x00-\x1f]/', $abs ) ) {
					++$skipped;
					continue;
				}
				++$count;
				yield $abs . ' ' . (int) $row['size'] . ' ' . $sha;
			}
			$offset += $limit;
		} while ( count( $rows ) === $limit );
		yield '# ' . $count . ' files.' . ( $skipped ? ' Skipped ' . $skipped . ' files with spaces in the name or without a hash.' : '' );
	}

	/**
	 * fapolicyd rules that only let PHP-FPM open trusted PHP files of this site.
	 *
	 * @return string
	 */
	public function fapolicyd_rules() {
		$bin  = defined( 'PHP_BINARY' ) ? wp_normalize_path( (string) PHP_BINARY ) : '';
		$fpm  = ( '' !== $bin && false !== strpos( basename( $bin ), 'fpm' ) ) ? $bin : '/usr/sbin/php-fpm';
		$root = rtrim( Paths::scan_root(), '/' ) . '/';
		return "# /etc/fapolicyd/rules.d/35-wordpress.rules\n"
			. '# ' . __( 'PHP-FPM may only open PHP files of this site that are in the trust list.', 'wp-cyber-security' ) . "\n"
			. "allow perm=open exe={$fpm} : dir={$root} ftype=text/x-php trust=1\n"
			. "deny_audit perm=open exe={$fpm} : dir={$root} ftype=text/x-php\n\n"
			. '# ' . __( 'Install the trust list downloaded above and reload:', 'wp-cyber-security' ) . "\n"
			. "#   cp wordpress.trust /etc/fapolicyd/trust.d/wordpress.trust\n"
			. "#   fagenrules --load && fapolicyd-cli --update\n"
			. '# ' . __( 'Download a fresh trust list after every update you approve, or PHP will be denied the new files.', 'wp-cyber-security' );
	}

	/**
	 * Escapes a literal for a POSIX extended regular expression.
	 *
	 * @param string $value Value.
	 * @return string
	 */
	private static function ere_quote( $value ) {
		return preg_replace( '/([.\[\](){}*+?|^$\\\\])/', '\\\\$1', (string) $value );
	}

	/**
	 * Bash watcher that runs a scan a little after files stop changing.
	 *
	 * @return string
	 */
	public function inotify_script() {
		$root    = rtrim( Paths::scan_root(), '/' );
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$exclude = array(
			self::ere_quote( $storage->data_dir() ) . '/',
			'/wp-content/(cache|upgrade|upgrade-temp-backup)/',
			'/\\.git/',
			'\\.log$',
		);
		$lines = array(
			'#!/usr/bin/env bash',
			'# WP Cyber Security: runs a scan 20 seconds after files stop changing.',
			'# Needs inotify-tools (apt install inotify-tools / dnf install inotify-tools).',
			'# Run it as the web server user, for example from a systemd service:',
			'#   [Service]',
			'#   User=www-data',
			'#   ExecStart=/usr/local/bin/wpcybersec-watch.sh',
			'#   Restart=always',
			'',
			'SITE=' . self::shell_arg( $root ),
			'PHP=' . self::shell_arg( self::php_binary() ),
			'CRON=' . self::shell_arg( wp_normalize_path( WPCYBERSEC_DIR ) . 'bin/cron.php' ),
			'WP=' . self::shell_arg( self::abspath() ),
			'DEBOUNCE=20',
			'EXCLUDE=' . self::shell_arg( '(' . implode( '|', $exclude ) . ')' ),
			'',
			'inotifywait -m -r -q -e close_write,create,moved_to,delete --exclude "$EXCLUDE" --format \'%w%f\' "$SITE" |',
			'while true; do',
			'    if IFS= read -r -t "$DEBOUNCE" changed; then',
			'        pending=1',
			'        continue',
			'    fi',
			'    rc=$?',
			'    # A status of 128 or less means inotifywait stopped: exit so systemd restarts us.',
			'    [ "$rc" -le 128 ] && exit 1',
			'    if [ "${pending:-0}" = 1 ]; then',
			'        pending=0',
			'        "$PHP" "$CRON" --wp="$WP" > /dev/null 2>&1',
			'    fi',
			'done',
		);
		return implode( "\n", $lines );
	}

	/**
	 * Linux Malware Detect (maldet) commands for this site.
	 *
	 * @return string
	 */
	public function maldet_snippet() {
		$root = self::shell_arg( rtrim( Paths::scan_root(), '/' ) );
		return '# ' . __( 'Linux Malware Detect (maldet) as a second scanner. Install it from rfxn.com first.', 'wp-cyber-security' ) . "\n"
			. '# ' . __( 'Scan files changed in the last 2 days, in the background:', 'wp-cyber-security' ) . "\n"
			. "maldet -b -r {$root} 2\n\n"
			. '# ' . __( 'Watch the site in real time (inotify monitor mode):', 'wp-cyber-security' ) . "\n"
			. "echo {$root} >> /usr/local/maldetect/monitor_paths\n"
			. "maldet --monitor /usr/local/maldetect/monitor_paths\n\n"
			. '# ' . __( 'Use ClamAV signatures inside maldet: set scan_clamscan="1" in /usr/local/maldetect/conf.maldet', 'wp-cyber-security' ) . "\n"
			. '# ' . __( 'Keep maldet quarantine off (quarantine_hits="0") and let WP Cyber Security decide, or both will move files.', 'wp-cyber-security' );
	}

	/**
	 * wp-config.php line for the allowlist tamper check, with a fresh random key.
	 *
	 * @return string
	 */
	public function hmac_snippet() {
		if ( defined( 'WPCYBERSEC_HMAC_KEY' ) && WPCYBERSEC_HMAC_KEY ) {
			return '// ' . __( 'WPCYBERSEC_HMAC_KEY is already defined in wp-config.php.', 'wp-cyber-security' );
		}
		return "define( 'WPCYBERSEC_HMAC_KEY', '" . wp_generate_password( 64, false, false ) . "' );";
	}

	/**
	 * wp-config line and shell commands to move the data folder.
	 *
	 * @return array { path, config, shell }
	 */
	public function data_dir_snippet() {
		$storage = self::service( 'storage' );
		$storage = $storage ? $storage : new Storage();
		$current = $storage->data_dir();
		// Same unique, per-install name the one-click move uses.
		$target = method_exists( $storage, 'suggested_outside_dir' ) ? $storage->suggested_outside_dir() : dirname( self::abspath() ) . '/wpcybersec-data';
		if ( $storage->is_in_webroot( $target ) ) {
			$host   = sanitize_title( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
			$target = '/var/lib/wpcybersec/' . ( $host ? $host : 'site' ) . ( method_exists( $storage, 'site_id' ) ? '-' . Storage::site_id() : '' );
		}
		$config = "define( 'WPCYBERSEC_DATA_DIR', '" . str_replace( array( '\\', "'" ), array( '\\\\', "\\'" ), $target ) . "' );";
		$shell  = 'mkdir -p ' . self::shell_arg( $target ) . "\n"
			. 'cp -a ' . self::shell_arg( $current . '/.' ) . ' ' . self::shell_arg( $target . '/' ) . "\n"
			. 'chown -R www-data:www-data ' . self::shell_arg( $target ) . "\n"
			. 'chmod 750 ' . self::shell_arg( $target ) . "\n"
			. '# ' . __( 'Then add the define() line to wp-config.php. If the early guard is installed, reinstall it afterwards. Held items keep pointing at the old folder until you approve or delete them, so the one-click "Move it outside the web root" button in Server health is the easier way: it moves everything and updates every path.', 'wp-cyber-security' );
		return array(
			'path'   => $target,
			'config' => $config,
			'shell'  => $shell,
		);
	}

	/* ------------------------------------------------------------------ */
	/* Test email                                                          */
	/* ------------------------------------------------------------------ */

	/**
	 * Sends a test alert. Uses the notifier when the recipients are the saved
	 * ones, otherwise a plain email to the addresses given.
	 *
	 * @param string[] $emails Optional recipients typed in a form (not saved yet).
	 * @return true|\WP_Error
	 */
	public function send_test_email( array $emails = array() ) {
		$emails   = array_values( array_unique( array_filter( array_map( 'sanitize_email', $emails ), 'is_email' ) ) );
		$settings = self::service( 'settings' );
		$saved    = $settings ? (array) $settings->recipients() : array( get_option( 'admin_email' ) );
		if ( ! $emails ) {
			$emails = $saved;
		}
		$a = $emails;
		$b = $saved;
		sort( $a );
		sort( $b );

		$error    = '';
		$on_error = static function ( $wp_error ) use ( &$error ) {
			if ( is_wp_error( $wp_error ) ) {
				$error = $wp_error->get_error_message();
			}
		};
		add_action( 'wp_mail_failed', $on_error );

		$notifier = self::service( 'notifier' );
		if ( $a === $b && $notifier && method_exists( $notifier, 'send_test' ) ) {
			try {
				$ok = (bool) $notifier->send_test();
			} catch ( \Throwable $e ) {
				$ok    = false;
				$error = $e->getMessage();
			}
		} else {
			$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
			/* translators: %s: site name */
			$subject = sprintf( __( '[%s] WP Cyber Security test email', 'wp-cyber-security' ), $site );
			$body    = __( 'This is a test message from WP Cyber Security.', 'wp-cyber-security' ) . "\n\n"
				/* translators: %s: site address */
				. sprintf( __( 'Alerts for %s will be sent to this address once you save the settings.', 'wp-cyber-security' ), home_url( '/' ) ) . "\n";
			$ok      = wp_mail( $emails, $subject, $body );
		}
		remove_action( 'wp_mail_failed', $on_error );

		if ( $ok ) {
			return true;
		}
		$message = __( 'WordPress could not send the email. The server may not be set up to send mail; an SMTP plugin usually fixes this.', 'wp-cyber-security' );
		if ( $error ) {
			$message .= ' (' . $error . ')';
		}
		return new \WP_Error( 'wpcybersec_mail', $message );
	}

	/**
	 * @param string[] $emails Recipients.
	 * @return string
	 */
	private static function test_sent_message( array $emails ) {
		/* translators: %s: email addresses */
		return sprintf( __( 'Test email sent to %s. If it does not arrive within a few minutes, check the spam folder.', 'wp-cyber-security' ), implode( ', ', $emails ) );
	}

	/**
	 * AJAX: sends a test email to the addresses typed in the form.
	 */
	public function ajax_test_email() {
		if ( ! check_ajax_referer( Ajax::NONCE, '_ajax_nonce', false ) ) {
			wp_send_json_error( array( 'message' => __( 'Your session expired. Reload the page and try again.', 'wp-cyber-security' ) ), 403 );
		}
		if ( ! self::user_can_manage() ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'wp-cyber-security' ) ), 403 );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above.
		$raw    = isset( $_POST['emails'] ) ? sanitize_textarea_field( wp_unslash( $_POST['emails'] ) ) : '';
		$typed  = self::parse_list( $raw );
		$valid  = array_values( array_filter( array_map( 'sanitize_email', $typed ), 'is_email' ) );
		if ( $typed && ! $valid ) {
			wp_send_json_error( array( 'message' => __( 'None of the email addresses is valid.', 'wp-cyber-security' ) ) );
		}
		$result = $this->send_test_email( $valid );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		$settings = self::service( 'settings' );
		$sent_to  = $valid ? $valid : ( $settings ? $settings->recipients() : array( get_option( 'admin_email' ) ) );
		wp_send_json_success( array( 'message' => self::test_sent_message( $sent_to ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* admin-post handlers                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * Wizard form: saves the posted step and moves to the next one.
	 */
	public function handle_wizard() {
		$this->check_request( 'wpcybersec_wizard' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in check_request().
		$steps = array_keys( Admin\Wizard::steps() );
		$step  = isset( $_POST['step'] ) ? sanitize_key( wp_unslash( $_POST['step'] ) ) : '';
		$step  = in_array( $step, $steps, true ) ? $step : $steps[0];
		$nav   = isset( $_POST['wpcs_nav'] ) ? sanitize_key( wp_unslash( $_POST['wpcs_nav'] ) ) : 'next';
		$do    = isset( $_POST['wpcs_do'] ) ? sanitize_key( wp_unslash( $_POST['wpcs_do'] ) ) : '';
		$post  = wp_unslash( $_POST );
		// phpcs:enable

		if ( '' !== $do && in_array( $do, self::WIZARD_ACTIONS, true ) ) {
			$this->wizard_action( $do, $post );
			$this->redirect( self::wizard_url( $step ) );
		}

		if ( 'next' === $nav ) {
			$this->save_wizard_step( $step, $post );
		}

		$index  = (int) array_search( $step, $steps, true );
		$target = 'back' === $nav ? $steps[ max( 0, $index - 1 ) ] : $steps[ min( count( $steps ) - 1, $index + 1 ) ];

		if ( 'done' === $target ) {
			$settings = self::service( 'settings' );
			if ( $settings && ! $settings->get( 'wizard_completed', false ) ) {
				$settings->update( array( 'wizard_completed' => true ) );
				self::log( 'wizard_completed', __( 'Setup wizard completed.', 'wp-cyber-security' ) );
			}
		}
		$this->redirect( self::wizard_url( $target ) );
	}

	/**
	 * Quick actions inside a wizard step.
	 *
	 * @param string $do   Action.
	 * @param array  $post Unslashed POST data.
	 */
	private function wizard_action( $do, array $post ) {
		if ( 'write_htaccess' === $do ) {
			$this->flash_htaccess_result( $this->write_uploads_htaccess() );
			return;
		}
		if ( 'probe' === $do ) {
			$uploads    = $this->probe_uploads_php();
			$quarantine = $this->probe_quarantine_web( true );
			$problems   = ( 'executed' === $uploads['result'] ? 1 : 0 ) + ( 'reachable' === $quarantine['result'] ? 1 : 0 );
			if ( $problems ) {
				self::flash( __( 'Live tests finished. See the highlighted checks below.', 'wp-cyber-security' ), 'warn' );
			} elseif ( 'unknown' === $uploads['result'] && $uploads['message'] ) {
				self::flash( $uploads['message'], 'info' );
			} else {
				self::flash( __( 'Live tests finished: PHP does not run in uploads and the quarantine cannot be downloaded.', 'wp-cyber-security' ), 'ok' );
			}
			return;
		}
		if ( 'send_test' === $do ) {
			$warnings = array();
			$values   = $this->collect_notifications( $post, $warnings );
			$settings = self::service( 'settings' );
			if ( $settings ) {
				$settings->update( $values );
			}
			foreach ( $warnings as $warning ) {
				self::flash( $warning, 'warn' );
			}
			$result = $this->send_test_email();
			if ( is_wp_error( $result ) ) {
				self::flash( $result->get_error_message(), 'bad' );
			} else {
				self::flash( __( 'Saved.', 'wp-cyber-security' ) . ' ' . self::test_sent_message( $settings ? $settings->recipients() : array( get_option( 'admin_email' ) ) ), 'ok' );
			}
		}
	}

	/**
	 * Saves the settings of one wizard step.
	 *
	 * @param string $step Step.
	 * @param array  $post Unslashed POST data.
	 */
	private function save_wizard_step( $step, array $post ) {
		$settings = self::service( 'settings' );
		if ( ! $settings ) {
			return;
		}
		switch ( $step ) {
			case 'protection':
				$presets = Settings::presets();
				$level   = isset( $post['level'] ) ? sanitize_key( $post['level'] ) : '';
				$base    = isset( $presets[ $level ] ) ? $presets[ $level ] : array();
				$values  = $base;

				$roles = isset( $base['upload_bypass_roles'] ) ? (array) $base['upload_bypass_roles'] : (array) $settings->get( 'upload_bypass_roles', array() );
				if ( ! empty( $post['hold_admin_uploads'] ) ) {
					$roles = array_values( array_diff( $roles, array( 'administrator' ) ) );
				} elseif ( ! in_array( 'administrator', $roles, true ) ) {
					$roles[] = 'administrator';
				}
				$values['upload_bypass_roles'] = $roles;
				$values['install_mode']        = ! empty( $post['hold_installs'] ) ? 'hold' : 'off';
				$values['file_mode']           = ! empty( $post['quarantine_php'] ) ? 'quarantine_exec' : 'report';

				$values['protection_level'] = $this->match_level( array_merge( $settings->all(), $values ), $level );
				$settings->update( $values );
				break;

			case 'notifications':
				$warnings = array();
				$settings->update( $this->collect_notifications( $post, $warnings ) );
				foreach ( $warnings as $warning ) {
					self::flash( $warning, 'warn' );
				}
				break;

			case 'hardening':
				$settings->update( array( 'freeze_mods' => ! empty( $post['freeze_mods'] ) ) );
				break;
		}
	}

	/**
	 * Which preset (if any) the given settings match.
	 *
	 * @param array  $values    Settings (merged over the current ones).
	 * @param string $preferred Level to prefer when several match.
	 * @return string strict | balanced | relaxed | custom.
	 */
	public function match_level( array $values, $preferred = '' ) {
		$settings = self::service( 'settings' );
		$values   = $settings ? $settings->sanitize( $values ) : $values;
		$matches  = array();
		foreach ( Settings::presets() as $name => $preset ) {
			$same = true;
			foreach ( $preset as $key => $expected ) {
				if ( in_array( $key, self::LEVEL_IGNORE, true ) ) {
					continue;
				}
				$actual = isset( $values[ $key ] ) ? $values[ $key ] : null;
				if ( is_array( $expected ) ) {
					$x = array_values( (array) $actual );
					$y = array_values( $expected );
					sort( $x );
					sort( $y );
					if ( $x !== $y ) {
						$same = false;
						break;
					}
				} elseif ( is_bool( $expected ) ) {
					if ( (bool) $actual !== $expected ) {
						$same = false;
						break;
					}
				} elseif ( (string) $actual !== (string) $expected ) {
					$same = false;
					break;
				}
			}
			if ( $same ) {
				$matches[] = $name;
			}
		}
		if ( $preferred && in_array( $preferred, $matches, true ) ) {
			return $preferred;
		}
		return $matches ? $matches[0] : 'custom';
	}

	/**
	 * Reads the notification fields of a form.
	 *
	 * @param array    $post     Unslashed POST data.
	 * @param string[] $warnings Receives warnings.
	 * @return array Settings values.
	 */
	private function collect_notifications( array $post, array &$warnings ) {
		$values = array();
		$enums    = Settings::enums();

		if ( isset( $post['notify_mode'] ) && in_array( $post['notify_mode'], $enums['notify_mode'], true ) ) {
			$values['notify_mode'] = $post['notify_mode'];
		}
		if ( isset( $post['notify_emails'] ) ) {
			$typed   = self::parse_list( is_array( $post['notify_emails'] ) ? implode( "\n", $post['notify_emails'] ) : sanitize_textarea_field( (string) $post['notify_emails'] ) );
			$valid   = array();
			$invalid = array();
			foreach ( $typed as $email ) {
				$clean = sanitize_email( $email );
				if ( $clean && is_email( $clean ) ) {
					$valid[] = $clean;
				} else {
					$invalid[] = $email;
				}
			}
			if ( $invalid ) {
				/* translators: %s: invalid email addresses */
				$warnings[] = sprintf( __( 'These addresses are not valid and were not saved: %s', 'wp-cyber-security' ), implode( ', ', $invalid ) );
			}
			$values['notify_emails'] = $valid;
		}
		if ( isset( $post['webhook_url'] ) ) {
			$raw = trim( sanitize_text_field( (string) $post['webhook_url'] ) );
			if ( '' === $raw ) {
				$values['webhook_url'] = '';
			} else {
				$url = esc_url_raw( $raw, array( 'https' ) );
				if ( '' === $url || 0 !== strpos( strtolower( $url ), 'https://' ) ) {
					$warnings[] = __( 'The webhook URL must start with https://. The previous value was kept.', 'wp-cyber-security' );
				} else {
					$values['webhook_url'] = $url;
				}
			}
		}
		return $values;
	}

	/**
	 * @param array  $post Unslashed POST data.
	 * @param string $key  Key.
	 * @return bool Checkbox value (hidden "0" + checkbox "1" pattern).
	 */
	private static function post_bool( array $post, $key ) {
		return isset( $post[ $key ] ) && ! is_array( $post[ $key ] ) && '1' === (string) $post[ $key ];
	}

	/**
	 * @param array  $post    Unslashed POST data.
	 * @param string $key     Enum key.
	 * @param string $current Current value (kept when the posted one is invalid).
	 * @return string
	 */
	private static function post_enum( array $post, $key, $current ) {
		$enums = Settings::enums();
		if ( isset( $post[ $key ] ) && ! is_array( $post[ $key ] ) && isset( $enums[ $key ] ) && in_array( (string) $post[ $key ], $enums[ $key ], true ) ) {
			return (string) $post[ $key ];
		}
		return $current;
	}

	/**
	 * Settings page: saves one tab.
	 */
	public function handle_save_settings() {
		$this->check_request( 'wpcybersec_save_settings' );
		$settings = self::service( 'settings' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in check_request().
		$post = wp_unslash( $_POST );
		$tab  = ( isset( $post['tab'] ) && 'advanced' === $post['tab'] ) ? 'advanced' : 'general';
		if ( ! $settings ) {
			self::flash( __( 'Settings are not available.', 'wp-cyber-security' ), 'bad' );
			$this->redirect( self::settings_url( $tab ) );
		}

		$old      = $settings->all();
		$warnings = array();
		$values   = 'advanced' === $tab ? $this->collect_advanced( $post, $old, $warnings ) : $this->collect_general( $post, $old, $warnings );
		$new      = $settings->update( $values );

		self::log(
			'settings_saved',
			/* translators: %s: tab name */
			sprintf( __( 'Settings saved (%s).', 'wp-cyber-security' ), 'advanced' === $tab ? __( 'Advanced', 'wp-cyber-security' ) : __( 'General', 'wp-cyber-security' ) ),
			array( 'changed' => array_keys( array_diff_assoc( array_map( 'wp_json_encode', $new ), array_map( 'wp_json_encode', $old ) ) ) )
		);

		foreach ( $warnings as $warning ) {
			self::flash( $warning, 'warn' );
		}
		if ( 'advanced' === $tab && ( $new['scan_root'] !== $old['scan_root'] || $new['scan_root_custom'] !== $old['scan_root_custom'] ) ) {
			// forget_baseline_on_root_change() already dropped the old baseline.
			self::flash( __( 'The scan folder changed, so the old baseline no longer applies. Rebuild the baseline from the Dashboard now; otherwise the next scan records it.', 'wp-cyber-security' ), 'warn' );
		}
		if ( 'general' === $tab && ! empty( $post['wpcs_send_test'] ) ) {
			$result = $this->send_test_email();
			if ( is_wp_error( $result ) ) {
				self::flash( $result->get_error_message(), 'bad' );
			} else {
				self::flash( self::test_sent_message( $settings->recipients() ), 'ok' );
			}
		}
		$this->redirect( self::settings_url( $tab, array( 'settings-updated' => 1 ) ) );
	}

	/**
	 * General tab fields.
	 *
	 * @param array    $post     Unslashed POST data.
	 * @param array    $old      Current settings.
	 * @param string[] $warnings Receives warnings.
	 * @return array
	 */
	private function collect_general( array $post, array $old, array &$warnings ) {
		$values = array(
			'upload_mode'     => self::post_enum( $post, 'upload_mode', $old['upload_mode'] ),
			'gate_sideloads'  => self::post_bool( $post, 'gate_sideloads' ),
			'install_mode'    => ( isset( $post['install_mode'] ) && 'hold' === $post['install_mode'] ) ? 'hold' : 'off',
			'hold_updates'    => self::post_bool( $post, 'hold_updates' ),
			'file_mode'       => self::post_enum( $post, 'file_mode', $old['file_mode'] ),
			'modified_action' => self::post_enum( $post, 'modified_action', $old['modified_action'] ),
			'auto_quarantine' => self::post_bool( $post, 'auto_quarantine' ),
			'scan_schedule'   => self::post_enum( $post, 'scan_schedule', $old['scan_schedule'] ),
			'scan_malware'    => self::post_bool( $post, 'scan_malware' ),
			'use_checksums'   => self::post_bool( $post, 'use_checksums' ),
			'min_severity'    => isset( $post['min_severity'] ) ? max( 1, min( 3, (int) $post['min_severity'] ) ) : $old['min_severity'],
			'snapshots'       => self::post_bool( $post, 'snapshots' ),
			'snapshot_max_kb' => isset( $post['snapshot_max_kb'] ) ? max( 16, min( 4096, (int) $post['snapshot_max_kb'] ) ) : $old['snapshot_max_kb'],
		);

		$valid_roles = function_exists( 'wp_roles' ) ? array_keys( wp_roles()->get_names() ) : array( 'administrator' );
		$roles       = ( isset( $post['upload_bypass_roles'] ) && is_array( $post['upload_bypass_roles'] ) ) ? array_map( 'sanitize_key', $post['upload_bypass_roles'] ) : array();
		$values['upload_bypass_roles'] = array_values( array_intersect( $roles, $valid_roles ) );

		$values = array_merge( $values, $this->collect_notifications( $post, $warnings ) );

		// Protection level: a level picked without JavaScript applies its preset.
		$presets = Settings::presets();
		$posted  = isset( $post['protection_level'] ) ? sanitize_key( (string) $post['protection_level'] ) : '';
		$synced  = ! empty( $post['wpcs_level_synced'] );
		if ( isset( $presets[ $posted ] ) && $posted !== $old['protection_level'] && ! $synced ) {
			$values = array_merge( $values, $presets[ $posted ] );
		}
		$values['protection_level'] = $this->match_level( array_merge( $old, $values ), $posted );
		return $values;
	}

	/**
	 * Advanced tab fields.
	 *
	 * @param array    $post     Unslashed POST data.
	 * @param array    $old      Current settings.
	 * @param string[] $warnings Receives warnings.
	 * @return array
	 */
	private function collect_advanced( array $post, array $old, array &$warnings ) {
		$values = array(
			'scan_root'                => self::post_enum( $post, 'scan_root', $old['scan_root'] ),
			'max_file_mb'              => isset( $post['max_file_mb'] ) ? (int) $post['max_file_mb'] : $old['max_file_mb'],
			'tick_seconds'             => isset( $post['tick_seconds'] ) ? (int) $post['tick_seconds'] : $old['tick_seconds'],
			'guard_action'             => self::post_enum( $post, 'guard_action', $old['guard_action'] ),
			'freeze_mods'              => self::post_bool( $post, 'freeze_mods' ),
			'disable_file_editor'      => self::post_bool( $post, 'disable_file_editor' ),
			'unlock_minutes'           => isset( $post['unlock_minutes'] ) ? (int) $post['unlock_minutes'] : $old['unlock_minutes'],
			'clamav_enabled'           => self::post_bool( $post, 'clamav_enabled' ),
			'log_retention_days'       => isset( $post['log_retention_days'] ) ? (int) $post['log_retention_days'] : $old['log_retention_days'],
			'delete_data_on_uninstall' => self::post_bool( $post, 'delete_data_on_uninstall' ),
		);

		if ( 'custom' === $values['scan_root'] ) {
			$raw  = isset( $post['scan_root_custom'] ) ? (string) $post['scan_root_custom'] : '';
			$path = $this->validate_scan_root( $raw, $warnings );
			if ( null === $path ) {
				$values['scan_root'] = $old['scan_root'];
			} else {
				$values['scan_root_custom'] = $path;
			}
		}

		if ( isset( $post['exclusions'] ) ) {
			$values['exclusions'] = $this->clean_exclusions( $post['exclusions'], $warnings );
		}
		if ( isset( $post['exec_extensions'] ) ) {
			$values['exec_extensions'] = $this->clean_extensions( $post['exec_extensions'], $warnings );
		}
		if ( isset( $post['exec_filenames'] ) ) {
			$names                    = self::parse_list( $post['exec_filenames'] );
			$values['exec_filenames'] = array_values( array_unique( array_merge( array( '.htaccess', '.user.ini' ), array_map( 'strtolower', $names ) ) ) );
		}
		if ( isset( $post['guard_exempt'] ) ) {
			$values['guard_exempt'] = self::parse_list( $post['guard_exempt'] );
		}
		if ( isset( $post['clamav_binary'] ) ) {
			$binary = $this->validate_clamav_binary( (string) $post['clamav_binary'], $warnings );
			if ( null !== $binary ) {
				$values['clamav_binary'] = $binary;
			}
		}
		return $values;
	}

	/**
	 * @param string   $raw      Path typed by the administrator.
	 * @param string[] $warnings Receives warnings.
	 * @return string|null Normalized real path, or null when invalid.
	 */
	public function validate_scan_root( $raw, array &$warnings ) {
		$raw = trim( sanitize_text_field( (string) $raw ) );
		if ( '' === $raw ) {
			$warnings[] = __( 'Enter a folder for the custom scan scope. The previous scope was kept.', 'wp-cyber-security' );
			return null;
		}
		$real = @realpath( $raw ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $real || ! @is_dir( $real ) || ! @is_readable( $real ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			/* translators: %s: folder path */
			$warnings[] = sprintf( __( 'The folder %s does not exist or cannot be read. The previous scan scope was kept.', 'wp-cyber-security' ), $raw );
			return null;
		}
		$real  = untrailingslashit( wp_normalize_path( $real ) );
		$depth = count( array_filter( explode( '/', preg_replace( '#^[a-zA-Z]:#', '', $real ) ), 'strlen' ) );
		if ( $depth < 2 ) {
			/* translators: %s: folder path */
			$warnings[] = sprintf( __( '%s is too close to the top of the file system to scan safely. The previous scan scope was kept.', 'wp-cyber-security' ), '' === $real ? '/' : $real );
			return null;
		}
		if ( ! Storage::is_within( ABSPATH, $real ) ) {
			$warnings[] = __( 'Note: WordPress itself is outside the custom scan folder, so its files are not checked.', 'wp-cyber-security' );
		}
		return $real;
	}

	/**
	 * @param string   $raw      Path typed by the administrator.
	 * @param string[] $warnings Receives warnings.
	 * @return string|null '' for auto-detect, the path, or null when invalid.
	 */
	public function validate_clamav_binary( $raw, array &$warnings ) {
		$raw = trim( sanitize_text_field( (string) $raw ) );
		if ( '' === $raw ) {
			return '';
		}
		$real = @realpath( $raw ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $real || ! @is_file( $real ) || ! @is_executable( $real ) || ! preg_match( '/^clamd?scan(\.exe)?$/i', basename( $real ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			/* translators: %s: path */
			$warnings[] = sprintf( __( '%s is not an executable clamscan or clamdscan binary. The previous value was kept.', 'wp-cyber-security' ), $raw );
			return null;
		}
		return wp_normalize_path( $real );
	}

	/**
	 * @param mixed    $raw      Textarea or list.
	 * @param string[] $warnings Receives warnings.
	 * @return string[]
	 */
	private function clean_exclusions( $raw, array &$warnings ) {
		$out = array();
		foreach ( self::parse_list( is_array( $raw ) ? $raw : preg_split( '/\R/', (string) $raw ) ) as $pattern ) {
			$pattern = ltrim( wp_normalize_path( $pattern ), '/' );
			if ( in_array( $pattern, array( '', '*', '**', '/', './', '.', '*/' ), true ) ) {
				/* translators: %s: exclusion pattern */
				$warnings[] = sprintf( __( 'The exclusion "%s" would hide every file and was removed.', 'wp-cyber-security' ), $pattern );
				continue;
			}
			if ( preg_match( '/^\*\.(php\d?|phtml|phar)$/i', $pattern ) ) {
				/* translators: %s: exclusion pattern */
				$warnings[] = sprintf( __( 'The exclusion "%s" hides PHP files from every scan. Keep it only if you are sure.', 'wp-cyber-security' ), $pattern );
			}
			$out[] = $pattern;
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * @param mixed    $raw      Text or list.
	 * @param string[] $warnings Receives warnings.
	 * @return string[]
	 */
	private function clean_extensions( $raw, array &$warnings ) {
		$exts = array();
		foreach ( self::parse_list( $raw ) as $ext ) {
			$ext = strtolower( ltrim( $ext, '.' ) );
			if ( preg_match( '/^[a-z0-9]{1,10}$/', $ext ) ) {
				$exts[] = $ext;
			}
		}
		$required = array( 'php', 'phtml', 'phar' );
		$missing  = array_diff( $required, $exts );
		if ( $missing ) {
			/* translators: %s: file extensions */
			$warnings[] = sprintf( __( 'These extensions are always treated as executable and were added back: %s', 'wp-cyber-security' ), implode( ', ', $missing ) );
		}
		return array_values( array_unique( array_merge( $required, $exts ) ) );
	}

	/**
	 * Early guard: install, uninstall or write .user.ini.
	 */
	public function handle_guard() {
		$this->check_request( 'wpcybersec_guard' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified in check_request().
		$op      = isset( $_REQUEST['op'] ) ? sanitize_key( wp_unslash( $_REQUEST['op'] ) ) : '';
		$methods = array(
			'install'        => 'install',
			'uninstall'      => 'uninstall',
			'write_user_ini' => 'write_user_ini',
		);
		$back    = self::settings_url( 'advanced', array(), 'wpcs-guard' );
		$manager = self::service( 'guard_manager' );
		if ( ! isset( $methods[ $op ] ) ) {
			self::flash( __( 'Unknown action.', 'wp-cyber-security' ), 'bad' );
			$this->redirect( $back );
		}
		if ( ! $manager || ! method_exists( $manager, $methods[ $op ] ) ) {
			self::flash( __( 'The early guard module is not available in this installation.', 'wp-cyber-security' ), 'bad' );
			$this->redirect( $back );
		}
		try {
			$result = call_user_func( array( $manager, $methods[ $op ] ) );
		} catch ( \Throwable $e ) {
			$result = new \WP_Error( 'wpcybersec_guard', $e->getMessage() );
		}
		if ( is_wp_error( $result ) ) {
			self::flash( $result->get_error_message(), 'bad' );
		} elseif ( false === $result ) {
			self::flash( __( 'The action did not complete. Check the file permissions of the WordPress folder and the data folder.', 'wp-cyber-security' ), 'bad' );
		} else {
			$messages = array(
				'install'        => __( 'Early guard installed. It starts working once PHP loads it through auto_prepend_file (see the snippets below).', 'wp-cyber-security' ),
				'uninstall'      => __( 'Early guard switched off. If you added auto_prepend_file to the server configuration, remove that line too.', 'wp-cyber-security' ),
				'write_user_ini' => __( 'auto_prepend_file was added to .user.ini. PHP picks it up within 5 minutes (user_ini.cache_ttl).', 'wp-cyber-security' ),
			);
			self::flash( $messages[ $op ], 'ok' );
			self::log( 'guard_' . $op, $messages[ $op ] );
		}
		$this->redirect( $back );
	}

	/**
	 * Downloads: settings JSON or the fapolicyd trust list.
	 */
	public function handle_export() {
		$this->check_request( 'wpcybersec_export' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified in check_request().
		$type = isset( $_REQUEST['type'] ) ? sanitize_key( wp_unslash( $_REQUEST['type'] ) ) : '';
		$host = sanitize_title( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$host = $host ? $host : 'site';

		if ( 'settings' === $type ) {
			$settings = self::service( 'settings' );
			$data     = array(
				'plugin'      => 'wp-cyber-security',
				'version'     => WPCYBERSEC_VERSION,
				'exported_at' => gmdate( 'c' ),
				'site'        => home_url( '/' ),
				'settings'    => $settings ? $settings->all() : array(),
			);
			unset( $data['settings']['wizard_completed'] );
			self::log( 'settings_exported', __( 'Settings exported.', 'wp-cyber-security' ) );
			nocache_headers();
			header( 'Content-Type: application/json; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="wp-cyber-security-settings-' . $host . '-' . gmdate( 'Ymd' ) . '.json"' );
			header( 'X-Content-Type-Options: nosniff' );
			echo wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON download.
			exit;
		}

		if ( 'fapolicyd' === $type ) {
			if ( function_exists( 'set_time_limit' ) ) {
				@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
			self::log( 'fapolicyd_exported', __( 'fapolicyd trust list downloaded.', 'wp-cyber-security' ) );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="wordpress-' . $host . '.trust"' );
			header( 'X-Content-Type-Options: nosniff' );
			while ( ob_get_level() > 0 ) {
				ob_end_flush();
			}
			foreach ( $this->fapolicyd_trust_export() as $line ) {
				echo $line . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain text download.
			}
			exit;
		}

		self::flash( __( 'Unknown export type.', 'wp-cyber-security' ), 'bad' );
		$this->redirect( self::settings_url( 'advanced', array(), 'wpcs-transfer' ) );
	}

	/**
	 * Imports settings from an uploaded or pasted JSON export.
	 */
	public function handle_import() {
		$this->check_request( 'wpcybersec_import' );
		$back     = self::settings_url( 'advanced', array(), 'wpcs-transfer' );
		$settings = self::service( 'settings' );
		$max      = 512 * KB_IN_BYTES;
		$json     = '';

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in check_request().
		if ( ! empty( $_FILES['wpcs_import_file']['tmp_name'] ) && is_string( $_FILES['wpcs_import_file']['tmp_name'] ) ) {
			$file = $_FILES['wpcs_import_file']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated below.
			if ( ! isset( $file['error'] ) || UPLOAD_ERR_OK !== (int) $file['error'] || ! is_uploaded_file( $file['tmp_name'] ) ) {
				self::flash( __( 'The file could not be uploaded. If the early upload guard is active, paste the JSON instead.', 'wp-cyber-security' ), 'bad' );
				$this->redirect( $back );
			}
			if ( (int) $file['size'] > $max ) {
				self::flash( __( 'The file is too large to be a settings export.', 'wp-cyber-security' ), 'bad' );
				$this->redirect( $back );
			}
			$json = (string) file_get_contents( $file['tmp_name'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		} elseif ( isset( $_POST['wpcs_import_json'] ) && is_string( $_POST['wpcs_import_json'] ) ) {
			$json = trim( wp_unslash( $_POST['wpcs_import_json'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- JSON is decoded and every value sanitized by Settings.
		}
		// phpcs:enable

		if ( '' === $json ) {
			self::flash( __( 'Choose an export file or paste its content first.', 'wp-cyber-security' ), 'bad' );
			$this->redirect( $back );
		}
		if ( strlen( $json ) > $max ) {
			self::flash( __( 'The pasted text is too large to be a settings export.', 'wp-cyber-security' ), 'bad' );
			$this->redirect( $back );
		}
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) ) {
			self::flash( __( 'This is not valid JSON.', 'wp-cyber-security' ), 'bad' );
			$this->redirect( $back );
		}
		if ( isset( $data['plugin'] ) && 'wp-cyber-security' !== $data['plugin'] ) {
			self::flash( __( 'This file was not exported by WP Cyber Security.', 'wp-cyber-security' ), 'bad' );
			$this->redirect( $back );
		}
		$incoming = ( isset( $data['settings'] ) && is_array( $data['settings'] ) ) ? $data['settings'] : $data;
		$defaults = Settings::defaults();
		$values   = array();
		foreach ( array_intersect_key( $incoming, $defaults ) as $key => $value ) {
			if ( 'wizard_completed' === $key ) {
				continue;
			}
			$default = $defaults[ $key ];
			if ( is_array( $default ) ? ! ( is_array( $value ) || is_string( $value ) ) : ! is_scalar( $value ) ) {
				continue;
			}
			$values[ $key ] = $value;
		}

		$warnings = array();
		if ( isset( $values['scan_root_custom'] ) && '' !== (string) $values['scan_root_custom'] ) {
			$path = $this->validate_scan_root( (string) $values['scan_root_custom'], $warnings );
			if ( null === $path ) {
				unset( $values['scan_root_custom'] );
				if ( isset( $values['scan_root'] ) && 'custom' === $values['scan_root'] ) {
					unset( $values['scan_root'] );
				}
			} else {
				$values['scan_root_custom'] = $path;
			}
		}
		if ( isset( $values['clamav_binary'] ) ) {
			$binary = $this->validate_clamav_binary( (string) $values['clamav_binary'], $warnings );
			if ( null === $binary ) {
				unset( $values['clamav_binary'] );
			} else {
				$values['clamav_binary'] = $binary;
			}
		}
		if ( isset( $values['exec_extensions'] ) ) {
			$values['exec_extensions'] = $this->clean_extensions( $values['exec_extensions'], $warnings );
		}
		if ( isset( $values['exclusions'] ) ) {
			$values['exclusions'] = $this->clean_exclusions( $values['exclusions'], $warnings );
		}

		if ( ! $values || ! $settings ) {
			self::flash( __( 'No known settings were found in the import.', 'wp-cyber-security' ), 'bad' );
			$this->redirect( $back );
		}
		$settings->update( $values );
		/* translators: %d: number of settings */
		$message = sprintf( _n( 'Imported %d setting.', 'Imported %d settings.', count( $values ), 'wp-cyber-security' ), count( $values ) );
		self::log( 'settings_imported', $message, array( 'keys' => array_keys( $values ) ) );
		self::flash( $message, 'ok' );
		foreach ( $warnings as $warning ) {
			self::flash( $warning, 'warn' );
		}
		$this->redirect( $back );
	}

	/**
	 * Writes the uploads .htaccess block and returns to the previous page.
	 */
	public function handle_write_htaccess() {
		$this->check_request( 'wpcybersec_write_htaccess' );
		$this->flash_htaccess_result( $this->write_uploads_htaccess() );
		$this->redirect_back( self::settings_url( 'advanced', array(), 'wpcs-hardening' ) );
	}

	/**
	 * @param string|\WP_Error $result write_uploads_htaccess() result.
	 */
	private function flash_htaccess_result( $result ) {
		if ( is_wp_error( $result ) ) {
			self::flash( $result->get_error_message(), 'bad' );
		} elseif ( 'unchanged' === $result ) {
			self::flash( __( 'uploads/.htaccess already contains the current rules.', 'wp-cyber-security' ), 'info' );
		} else {
			$message = __( 'Added the PHP blocking rules to uploads/.htaccess. Other content in the file was kept.', 'wp-cyber-security' );
			if ( 'nginx' === self::server_type() ) {
				$message .= ' ' . __( 'This server runs nginx, which ignores .htaccess: add the nginx rule as well.', 'wp-cyber-security' );
			}
			self::flash( $message, 'ok' );
		}
	}

	/**
	 * Deletes every stored file copy (Settings > Advanced > Data).
	 */
	public function handle_snapshots_clear() {
		$this->check_request( 'wpcybersec_snapshots_clear' );
		$snapshots = self::service( 'snapshots' );
		$deleted   = $snapshots ? (int) $snapshots->clear() : 0;
		/* translators: %s: number of files */
		$message = sprintf( _n( 'Deleted %s stored file copy.', 'Deleted %s stored file copies.', $deleted, 'wp-cyber-security' ), number_format_i18n( $deleted ) );
		self::log( 'snapshots_cleared', $message, array( 'deleted' => $deleted ) );
		self::flash( $message, 'ok' );
		$this->redirect( self::settings_url( 'advanced', array(), 'wpcs-data' ) );
	}

	/**
	 * Sends a test email to the saved recipients and returns to the previous page.
	 */
	public function handle_test_email() {
		$this->check_request( 'wpcybersec_test_email' );
		$result = $this->send_test_email();
		if ( is_wp_error( $result ) ) {
			self::flash( $result->get_error_message(), 'bad' );
		} else {
			$settings = self::service( 'settings' );
			self::flash( self::test_sent_message( $settings ? $settings->recipients() : array( get_option( 'admin_email' ) ) ), 'ok' );
		}
		$this->redirect_back( self::settings_url( 'general', array(), 'wpcs-notifications' ) );
	}
}
