<?php
/**
 * Private data directory (quarantine, scan job files, guard spool).
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves and protects the plugin's data directory.
 *
 * Default: wp-content/wpcybersec. System administrators can move it outside
 * the web root with define( 'WPCYBERSEC_DATA_DIR', '/var/lib/wpcybersec/site' )
 * in wp-config.php. Works before the plugin is booted (activation hooks).
 */
class Storage {

	/** Option set by the one-click "move the data folder" fix (single sites only). */
	const DIR_OPTION = 'wpcybersec_data_dir';

	/**
	 * State of a move that has not finished: { source, target, phase, time }.
	 * phase "copy": copying, nothing switched yet. phase "switched": the plugin
	 * uses the new folder; the old one still has to be emptied.
	 */
	const MOVE_OPTION = 'wpcybersec_data_move';

	/** Lock row (in the options table) held while a move runs: "<time>:<token>". */
	const MOVE_LOCK = 'wpcybersec_data_move_lock';

	/** A lock not refreshed for this long belongs to a request that died. */
	const MOVE_LOCK_STALE = 1800;

	/** File that ties a moved data folder to this site (see site_id()). */
	const MARKER_FILE = '.wpcybersec-site';

	/** Deny files written by protect(). */
	const DENY_FILES = array( '.htaccess', 'index.php', 'web.config' );

	/**
	 * Files of the guard spool that are never copied as they are: their lines
	 * hold absolute paths, so they are moved line by line (migrate_spool()).
	 */
	const SPOOL_RUNTIME = array( 'spool/guard-uploads.jsonl', 'spool/guard-uploads.work.jsonl', 'spool/guard-uploads.work.pos', 'spool/guard-import.lock' );

	/** @var string Value of the move lock this request holds. */
	private $lock_value = '';

	/** @var int Last time the move lock was refreshed. */
	private $lock_beat = 0;

	/**
	 * Resolution order: WPCYBERSEC_DATA_DIR constant, then the folder chosen by
	 * the one-click move (option, single sites only), then wp-content/wpcybersec.
	 *
	 * @return string Absolute path, no trailing slash.
	 */
	public function data_dir() {
		if ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) {
			return untrailingslashit( wp_normalize_path( WPCYBERSEC_DATA_DIR ) );
		}
		// On multisite every site shares one folder, so a per-site option cannot move it.
		if ( ! is_multisite() ) {
			$moved = get_option( self::DIR_OPTION, '' );
			if ( is_string( $moved ) && '' !== $moved && Paths::is_absolute( wp_normalize_path( $moved ) ) && @is_dir( $moved ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return untrailingslashit( wp_normalize_path( $moved ) );
			}
		}
		return $this->default_dir();
	}

	/**
	 * @return string The default folder inside wp-content.
	 */
	public function default_dir() {
		return untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) . '/wpcybersec';
	}

	/**
	 * Short id of this WordPress install: the same for every request of this
	 * site, different for another install (or another table prefix) on the
	 * same server. uninstall.php computes it the same way.
	 *
	 * @return string 8 hex characters.
	 */
	public static function site_id() {
		global $wpdb;
		$prefix = ( isset( $wpdb ) && is_object( $wpdb ) && isset( $wpdb->prefix ) ) ? (string) $wpdb->prefix : '';
		return substr( md5( ABSPATH . $prefix ), 0, 8 );
	}

	/**
	 * Suggested folder outside the web root: next to the WordPress folder,
	 * named after the site plus this install's id, so several sites (even with
	 * the same host name, like example.com and example.com/blog) never share one.
	 *
	 * @return string
	 */
	public function suggested_outside_dir() {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$slug = sanitize_key( str_replace( '.', '-', $host ) );
		$name = 'wpcybersec-' . ( $slug ? $slug : 'data' ) . '-' . self::site_id();

		// Walk up from the WordPress folder. A folder that contains an index file
		// is most likely served by a web server itself (for example a default
		// localhost site whose sub folders are the real sites), so skip it.
		$dir = wp_normalize_path( dirname( untrailingslashit( ABSPATH ) ) );
		for ( $i = 0; $i < 3; $i++ ) {
			if ( ! self::looks_served( $dir ) && Fs::is_writable( $dir ) && ! $this->is_in_webroot( $dir . '/' . $name ) ) {
				return $dir . '/' . $name;
			}
			$up = wp_normalize_path( dirname( $dir ) );
			if ( $up === $dir || '' === trim( $up, '/' ) ) {
				break;
			}
			$dir = $up;
		}
		return wp_normalize_path( dirname( untrailingslashit( ABSPATH ) ) ) . '/' . $name;
	}

	/**
	 * Whether a folder looks like a web document root (has an index page).
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	public static function looks_served( $dir ) {
		foreach ( array( 'index.php', 'index.html', 'index.htm', 'wp-config.php', 'wp-load.php' ) as $index ) {
			if ( @file_exists( $dir . '/' . $index ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return true;
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* Site marker                                                         */
	/* ------------------------------------------------------------------ */

	/**
	 * Whether $dir carries this site's marker file.
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	public function marker_matches( $dir ) {
		$file = untrailingslashit( wp_normalize_path( (string) $dir ) ) . '/' . self::MARKER_FILE;
		if ( ! @is_file( $file ) || @is_link( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$text = (string) @file_get_contents( $file, false, null, 0, 1024 ); // phpcs:ignore
		return (bool) preg_match( '/^site:\s*' . preg_quote( self::site_id(), '/' ) . '\s*$/m', $text );
	}

	/**
	 * Writes this site's marker file into $dir.
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	public function write_marker( $dir ) {
		$file = untrailingslashit( wp_normalize_path( (string) $dir ) ) . '/' . self::MARKER_FILE;
		$text = "CyberGate Security data folder. uninstall.php only removes it when the site id matches.\nsite: " . self::site_id() . "\nhome: " . home_url( '/' ) . "\n";
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== @file_put_contents( $file, $text );
	}

	/**
	 * Whether the data folder may be moved into $dir: it does not exist yet, is
	 * empty, or already belongs to this site (marker file).
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	public function dir_usable( $dir ) {
		$dir = untrailingslashit( wp_normalize_path( (string) $dir ) );
		if ( ! @file_exists( $dir ) && ! @is_link( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return true;
		}
		if ( ! @is_dir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		return self::is_empty_dir( $dir ) || $this->marker_matches( $dir );
	}

	/**
	 * @param string $dir Folder.
	 * @return bool
	 */
	private static function is_empty_dir( $dir ) {
		$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $entries ) ) {
			return false;
		}
		return ! array_diff( $entries, array( '.', '..' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Moving the data folder                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Moves the whole data folder (quarantine, scan files, guard files) to $target
	 * and remembers the new location. Held items keep working: their stored
	 * quarantine paths are rewritten.
	 *
	 * Phase 1 copies everything into $target (hard links on the same disk) and
	 * checks every file; the old folder is not touched. Any failure here removes
	 * the partial copy and nothing is switched. Phase 2 switches the option,
	 * rewrites the stored paths and calls $after_switch (the guard follows the
	 * new folder there). Phase 3 copies what arrived in the old folder meanwhile,
	 * moves the guard's waiting spool lines and only then removes files from the
	 * old folder that are safely in the new one. When phase 3 cannot finish
	 * (for example the guard still points at the old folder), it is retried on
	 * the plugin's admin pages (resume_move()).
	 *
	 * @param string        $target       Absolute folder (created when missing).
	 * @param callable|null $after_switch Called as ( $source, $target ) right after
	 *                                    the switch; a WP_Error keeps the old folder.
	 * @return true|\WP_Error
	 */
	public function relocate( $target, $after_switch = null ) {
		if ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) {
			return new \WP_Error( 'wpcybersec_storage_const', __( 'The data folder is set by WPCYBERSEC_DATA_DIR in wp-config.php. Change it there.', 'cybergate-security' ) );
		}
		if ( is_multisite() ) {
			return new \WP_Error( 'wpcybersec_storage_multisite', __( 'On a multisite network all sites share one data folder, so it can only be moved with WPCYBERSEC_DATA_DIR in wp-config.php.', 'cybergate-security' ) );
		}
		$target = untrailingslashit( wp_normalize_path( (string) $target ) );
		if ( '' === $target || ! Paths::is_absolute( $target ) ) {
			return new \WP_Error( 'wpcybersec_storage_target', __( 'The new folder must be an absolute path.', 'cybergate-security' ) );
		}
		$locked = $this->acquire_move_lock();
		if ( is_wp_error( $locked ) ) {
			return $locked;
		}
		self::keep_running();
		$old_umask = umask( 0077 );
		try {
			$result = $this->relocate_locked( $target, $after_switch );
		} finally {
			umask( $old_umask );
			$this->release_move_lock();
		}
		return $result;
	}

	/**
	 * Finishes a move that was interrupted (called on the plugin's admin pages).
	 *
	 * @return bool|\WP_Error True when nothing is left to do, false when files
	 *                        are still waiting in the old folder.
	 */
	public function resume_move() {
		if ( ! $this->move_state() ) {
			return true;
		}
		$locked = $this->acquire_move_lock();
		if ( is_wp_error( $locked ) ) {
			return $locked;
		}
		self::keep_running();
		$old_umask = umask( 0077 );
		try {
			$state = $this->move_state();
			if ( $state && 'copy' === $state['phase'] ) {
				// The copying request died. Nothing was switched: drop the partial copy.
				$this->drop_partial_copy( $state['target'] );
				delete_option( self::MOVE_OPTION );
				$result = true;
			} else {
				$result = $this->finish_move_locked();
			}
		} finally {
			umask( $old_umask );
			$this->release_move_lock();
		}
		return $result;
	}

	/**
	 * Whether a switched move still has files to bring over from the old folder.
	 *
	 * @return bool
	 */
	public function move_pending() {
		$state = $this->move_state();
		return $state && 'switched' === $state['phase'];
	}

	/**
	 * @return array|null { source, target, phase, time }
	 */
	private function move_state() {
		$state = get_option( self::MOVE_OPTION, null );
		if ( ! is_array( $state ) || empty( $state['source'] ) || empty( $state['target'] ) || empty( $state['phase'] ) ) {
			return null;
		}
		return array(
			'source' => untrailingslashit( wp_normalize_path( (string) $state['source'] ) ),
			'target' => untrailingslashit( wp_normalize_path( (string) $state['target'] ) ),
			'phase'  => (string) $state['phase'],
			'time'   => isset( $state['time'] ) ? (int) $state['time'] : 0,
		);
	}

	/**
	 * @param string $source Old folder.
	 * @param string $target New folder.
	 * @param string $phase  copy | switched.
	 */
	private function save_move_state( $source, $target, $phase ) {
		update_option(
			self::MOVE_OPTION,
			array(
				'source' => $source,
				'target' => $target,
				'phase'  => $phase,
				'time'   => time(),
			),
			false
		);
	}

	/**
	 * relocate() under the move lock.
	 *
	 * @param string        $target       Normalized target.
	 * @param callable|null $after_switch Callback.
	 * @return true|\WP_Error
	 */
	private function relocate_locked( $target, $after_switch ) {
		// An earlier move that switched over but did not finish comes first.
		$state    = $this->move_state();
		$finished = true;
		if ( $state && 'switched' === $state['phase'] ) {
			$finished = $this->finish_move_locked();
			$state    = null;
		}

		$source = $this->data_dir();
		if ( $target === $source ) {
			return true;
		}
		if ( true !== $finished ) {
			return is_wp_error( $finished ) ? $finished : new \WP_Error( 'wpcybersec_storage_pending', __( 'An earlier move of the data folder is still being finished. Try again in a few minutes.', 'cybergate-security' ) );
		}
		if ( 0 === strpos( trailingslashit( $target ), trailingslashit( $source ) ) ) {
			return new \WP_Error( 'wpcybersec_storage_nested', __( 'The new folder cannot be inside the current one.', 'cybergate-security' ) );
		}
		if ( 0 === strpos( trailingslashit( $source ), trailingslashit( $target ) ) ) {
			return new \WP_Error( 'wpcybersec_storage_nested', __( 'The new folder cannot contain the current one.', 'cybergate-security' ) );
		}

		// A copy into another folder that never finished (the request died): drop it.
		$resume = false;
		if ( $state && 'copy' === $state['phase'] ) {
			if ( $state['target'] === $target && $state['source'] === $source ) {
				$resume = true; // Same move again: files already copied are kept.
			} else {
				$this->drop_partial_copy( $state['target'] );
				delete_option( self::MOVE_OPTION );
			}
		}

		if ( ! $this->dir_usable( $target ) ) {
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_taken', sprintf( __( '%s already exists and holds files that do not belong to this site. Nothing was moved; empty that folder or use another one.', 'cybergate-security' ), $target ) );
		}
		$created_root = ! is_dir( $target );
		if ( $created_root && ! wp_mkdir_p( $target ) ) {
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_mkdir', sprintf( __( 'Could not create %s. The parent folder is not writable for WordPress.', 'cybergate-security' ), $target ) );
		}
		if ( ! Fs::is_writable( $target ) ) {
			if ( $created_root ) {
				Fs::rmdir( $target );
			}
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_write', sprintf( __( '%s is not writable for WordPress.', 'cybergate-security' ), $target ) );
		}
		// Everything inside the target is ours to remove again when this move fails.
		$owned = $created_root || $resume || self::is_empty_dir( $target );
		if ( $created_root && is_dir( $source ) ) {
			Fs::chmod( $target, @fileperms( $source ) & 0777 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		if ( ! $this->write_marker( $target ) ) {
			$this->undo_copy( $target, array(), $owned, $created_root );
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_write', sprintf( __( '%s is not writable for WordPress.', 'cybergate-security' ), $target ) );
		}
		$this->save_move_state( $source, $target, 'copy' );

		// No guard spool import may run on the old folder while it is copied.
		$import_lock = self::lock_file( $source . '/spool/guard-import.lock', 30 );
		if ( false === $import_lock ) {
			$this->undo_copy( $target, array(), $owned, $created_root );
			delete_option( self::MOVE_OPTION );
			return new \WP_Error( 'wpcybersec_storage_busy', __( 'The early guard is importing held uploads right now. Nothing was moved; try again in a minute.', 'cybergate-security' ) );
		}

		// Phase 1: copy and check. The old folder stays as it is.
		$created = array();
		$copied  = $this->copy_into( $source, $target, $created, false );
		if ( is_wp_error( $copied ) ) {
			self::unlock_file( $import_lock );
			$this->undo_copy( $target, $created, $owned, $created_root );
			delete_option( self::MOVE_OPTION );
			return new \WP_Error(
				'wpcybersec_storage_move',
				/* translators: 1: error message, 2: folder */
				sprintf( __( '%1$s Nothing was switched over: the data folder is still %2$s and the partial copy was removed.', 'cybergate-security' ), $copied->get_error_message(), $source )
			);
		}

		// Phase 2: switch over.
		$this->save_move_state( $source, $target, 'switched' );
		update_option( self::DIR_OPTION, $target, true );
		$this->ensure();
		$this->rewrite_item_paths( $source, $target );
		self::unlock_file( $import_lock );

		if ( is_callable( $after_switch ) ) {
			$after = call_user_func( $after_switch, $source, $target );
			if ( is_wp_error( $after ) ) {
				return $after; // Switched; the old folder is kept until the cause is fixed.
			}
		}

		// Phase 3: bring over what arrived meanwhile, then empty the old folder.
		$finished = $this->finish_move_locked();
		if ( is_wp_error( $finished ) ) {
			self::log(
				'data_dir_move',
				/* translators: %s: error message */
				sprintf( __( 'The data folder was moved, but the old folder could not be emptied yet: %s It is retried when an administrator opens the plugin.', 'cybergate-security' ), $finished->get_error_message() )
			);
		}
		return true;
	}

	/**
	 * Phase 3 of a switched move, under the move lock.
	 *
	 * @return bool|\WP_Error True when done, false when files are left for a retry.
	 */
	private function finish_move_locked() {
		$state = $this->move_state();
		if ( ! $state || 'switched' !== $state['phase'] ) {
			return true;
		}
		$source = $state['source'];
		$target = $state['target'];
		if ( ! is_dir( $target ) ) {
			return new \WP_Error( 'wpcybersec_storage_target', __( 'The new data folder is missing.', 'cybergate-security' ) );
		}
		if ( ! is_dir( $source ) ) {
			$this->rewrite_item_paths( $source, $target );
			delete_option( self::MOVE_OPTION );
			return true;
		}
		if ( self::guard_uses( $source ) ) {
			return new \WP_Error( 'wpcybersec_storage_guard', __( 'The early guard file still points to the old data folder, so the old folder is kept until the guard is updated.', 'cybergate-security' ) );
		}
		$import_lock = self::lock_file( $source . '/spool/guard-import.lock', 30 );
		if ( false === $import_lock ) {
			return new \WP_Error( 'wpcybersec_storage_busy', __( 'The early guard is importing held uploads from the old folder right now.', 'cybergate-security' ) );
		}
		$left = 0;
		try {
			// Files written to the old folder after the copy (for example uploads held meanwhile).
			$created = array();
			$copied  = $this->copy_into( $source, $target, $created, true );
			if ( is_wp_error( $copied ) ) {
				return $copied;
			}
			$moved = $this->migrate_spool( $source, $target );
			if ( is_wp_error( $moved ) ) {
				return $moved;
			}
			$this->rewrite_item_paths( $source, $target );
			$left = self::remove_copied( $source, $target, '' );
		} finally {
			self::unlock_file( $import_lock );
		}
		if ( 0 === $left ) {
			Fs::delete( $source . '/spool/guard-import.lock' );
			Fs::rmdir( $source . '/spool' );
			Fs::rmdir( $source );
			delete_option( self::MOVE_OPTION );
			return true;
		}
		return false;
	}

	/**
	 * Whether the installed early guard still loads its config from $dir.
	 * The guard bootstrap has the config path written into it, so the old
	 * folder must stay until the bootstrap points to the new one.
	 *
	 * @param string $dir Data folder.
	 * @return bool
	 */
	private static function guard_uses( $dir ) {
		if ( ! get_option( 'wpcybersec_guard_installed', false ) ) {
			return false;
		}
		$bootstrap = ABSPATH . 'wpcybersec-guard.php';
		if ( ! @is_file( $bootstrap ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$code = (string) @file_get_contents( $bootstrap, false, null, 0, 65536 ); // phpcs:ignore
		return false !== strpos( $code, var_export( $dir . '/guard/config.php', true ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
	}

	/**
	 * Removes a partial copy left by a move that never switched over.
	 *
	 * @param string $dir Target of that move.
	 */
	private function drop_partial_copy( $dir ) {
		if ( '' === $dir || ! is_dir( $dir ) || $dir === $this->data_dir() || $dir === $this->default_dir() ) {
			return;
		}
		if ( $this->marker_matches( $dir ) ) {
			self::empty_dir( $dir ); // The folder itself stays: an administrator may have created it.
		}
	}

	/**
	 * Undoes phase 1 after a failure.
	 *
	 * @param string   $target       Target folder.
	 * @param string[] $created      Files and folders this move created, in order.
	 * @param bool     $owned        Everything inside the target belongs to this move.
	 * @param bool     $created_root This move created the target folder itself.
	 */
	private function undo_copy( $target, array $created, $owned, $created_root ) {
		if ( $owned ) {
			self::empty_dir( $target );
			if ( $created_root ) {
				Fs::rmdir( $target );
			}
			return;
		}
		foreach ( array_reverse( $created ) as $path ) {
			if ( is_dir( $path ) && ! is_link( $path ) ) {
				Fs::rmdir( $path );
			} else {
				Fs::delete( $path );
			}
		}
	}

	/**
	 * Copies the data folder into $target. On the same disk files are hard
	 * linked (instant, no extra space, the old folder stays intact); otherwise
	 * they are copied. Every file is checked afterwards.
	 *
	 * @param string   $source       Old folder.
	 * @param string   $target       New folder.
	 * @param string[] $created      Receives every file and folder created.
	 * @param bool     $only_missing Only copy files the target does not have yet.
	 * @return true|\WP_Error
	 */
	private function copy_into( $source, $target, array &$created, $only_missing ) {
		if ( ! is_dir( $source ) ) {
			return true;
		}
		$tree = self::list_tree( $source );
		$link = self::same_device( $source, $target ) && self::can_link();

		if ( ! $link ) {
			$need = 0;
			foreach ( $tree['files'] as $rel => $size ) {
				if ( ! is_file( $target . '/' . $rel ) ) {
					$need += $size;
				}
			}
			$free = function_exists( 'disk_free_space' ) ? @disk_free_space( $target ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( is_numeric( $free ) && (float) $free < $need + 32 * MB_IN_BYTES ) {
				return new \WP_Error(
					'wpcybersec_storage_space',
					/* translators: 1: size, 2: folder, 3: size */
					sprintf( __( 'The data needs %1$s but %2$s has only %3$s free.', 'cybergate-security' ), size_format( $need + 32 * MB_IN_BYTES ), $target, size_format( (float) $free ) )
				);
			}
		}

		foreach ( $tree['dirs'] as $rel ) {
			$made = $this->make_dir( $source . '/' . $rel, $target . '/' . $rel, $created );
			if ( is_wp_error( $made ) ) {
				return $made;
			}
		}
		foreach ( $tree['files'] as $rel => $size ) {
			$to = $target . '/' . $rel;
			if ( is_file( $to ) && ( $only_missing || (int) @filesize( $to ) === (int) $size ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue; // Copied by an earlier try.
			}
			if ( ! self::copy_file( $source . '/' . $rel, $to, $link ) ) {
				/* translators: 1: file, 2: folder */
				return new \WP_Error( 'wpcybersec_storage_copy', sprintf( __( 'Could not copy %1$s into %2$s.', 'cybergate-security' ), $source . '/' . $rel, $target ) );
			}
			$created[] = $to;
			$this->beat_move_lock();
		}
		if ( $only_missing ) {
			return true;
		}

		// Check: every file of the old folder is in the new one with the same size.
		// A file that changed or appeared while copying is copied once more.
		$check = self::list_tree( $source );
		foreach ( $check['dirs'] as $rel ) {
			$made = $this->make_dir( $source . '/' . $rel, $target . '/' . $rel, $created );
			if ( is_wp_error( $made ) ) {
				return $made;
			}
		}
		foreach ( $check['files'] as $rel => $size ) {
			$to = $target . '/' . $rel;
			clearstatcache( true, $to );
			if ( is_file( $to ) && (int) @filesize( $to ) === (int) $size ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			if ( ! self::copy_file( $source . '/' . $rel, $to, $link ) ) {
				/* translators: %s: file */
				return new \WP_Error( 'wpcybersec_storage_verify', sprintf( __( 'The copy of %s could not be checked.', 'cybergate-security' ), $source . '/' . $rel ) );
			}
			$created[] = $to;
		}
		return true;
	}

	/**
	 * Creates one folder of the copy with the permissions of the original.
	 *
	 * @param string   $from    Original folder.
	 * @param string   $to      New folder.
	 * @param string[] $created Receives the folder when it was created.
	 * @return true|\WP_Error
	 */
	private function make_dir( $from, $to, array &$created ) {
		if ( is_dir( $to ) ) {
			return true;
		}
		if ( file_exists( $to ) || is_link( $to ) || ! Fs::mkdir( $to, 0700 ) ) {
			/* translators: %s: folder */
			return new \WP_Error( 'wpcybersec_storage_mkdir', sprintf( __( 'Could not create %s.', 'cybergate-security' ), $to ) );
		}
		$created[] = $to;
		$perms = @fileperms( $from ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $perms ) {
			Fs::chmod( $to, $perms & 0777 );
		}
		return true;
	}

	/**
	 * Copies (or hard links) one file and checks its size.
	 *
	 * @param string $from Source file.
	 * @param string $to   Target file.
	 * @param bool   $link Try a hard link first.
	 * @return bool
	 */
	private static function copy_file( $from, $to, $link ) {
		if ( file_exists( $to ) || is_link( $to ) ) {
			Fs::delete( $to );
		}
		if ( $link && @link( $from, $to ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return true;
		}
		if ( ! @copy( $from, $to ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Fs::delete( $to );
			return false;
		}
		$perms = @fileperms( $from ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		Fs::chmod( $to, $perms ? ( $perms & 0777 ) : 0600 );
		clearstatcache( true, $from );
		clearstatcache( true, $to );
		return (int) @filesize( $to ) === (int) @filesize( $from ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Folders and files of the data folder, without symlinks, the marker and
	 * the guard spool runtime files.
	 *
	 * @param string $root Folder.
	 * @return array { dirs: string[] (parents first), files: array rel => size }
	 */
	private static function list_tree( $root ) {
		$dirs  = array();
		$files = array();
		$stack = array( '' );
		while ( $stack ) {
			$rel     = array_pop( $stack );
			$abs     = '' === $rel ? $root : $root . '/' . $rel;
			$entries = @scandir( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! is_array( $entries ) ) {
				continue;
			}
			foreach ( $entries as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$child = '' === $rel ? $entry : $rel . '/' . $entry;
				$path  = $abs . '/' . $entry;
				if ( is_link( $path ) ) {
					continue; // Never followed, never copied.
				}
				if ( is_dir( $path ) ) {
					$dirs[]  = $child;
					$stack[] = $child;
					continue;
				}
				if ( self::MARKER_FILE === $child || in_array( $child, self::SPOOL_RUNTIME, true ) || 0 === strpos( $child, 'spool/guard-uploads.work.jsonl.' ) ) {
					continue;
				}
				$files[ $child ] = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
		}
		usort(
			$dirs,
			static function ( $a, $b ) {
				return substr_count( $a, '/' ) - substr_count( $b, '/' );
			}
		);
		return array(
			'dirs'  => $dirs,
			'files' => $files,
		);
	}

	/**
	 * Moves the guard's waiting spool lines (and the unfinished rest of its work
	 * file) from the old folder to the new one, with their held-copy paths
	 * rewritten, so uploads held during the move keep their copies.
	 *
	 * @param string $source Old folder.
	 * @param string $target New folder.
	 * @return true|\WP_Error
	 */
	private function migrate_spool( $source, $target ) {
		$dir = $source . '/spool';
		if ( ! is_dir( $dir ) ) {
			return true;
		}
		$lines = array();
		$work  = $dir . '/guard-uploads.work.jsonl';
		if ( is_file( $work ) ) {
			$offset = 0;
			$pos    = json_decode( (string) @file_get_contents( $dir . '/guard-uploads.work.pos' ), true ); // phpcs:ignore
			if ( is_array( $pos ) && isset( $pos['offset'] ) ) {
				$offset = max( 0, (int) $pos['offset'] );
			}
			$size = (int) @filesize( $work ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( $offset < $size ) {
				$rest  = @file_get_contents( $work, false, null, $offset ); // phpcs:ignore
				$lines = array_merge( $lines, preg_split( '/\r\n|\n|\r/', (string) $rest ) );
			}
		}

		// Lock the old spool so a guard request still using it cannot add a line
		// between reading and emptying it.
		$spool  = $dir . '/guard-uploads.jsonl';
		$handle = null;
		if ( is_file( $spool ) ) {
			$handle = @fopen( $spool, 'c+' ); // phpcs:ignore
			if ( ! $handle || ! @flock( $handle, LOCK_EX ) ) { // phpcs:ignore
				if ( $handle ) {
					@fclose( $handle ); // phpcs:ignore
				}
				return new \WP_Error( 'wpcybersec_storage_spool', __( 'Could not lock the early guard spool in the old folder.', 'cybergate-security' ) );
			}
			rewind( $handle );
			$lines = array_merge( $lines, preg_split( '/\r\n|\n|\r/', (string) stream_get_contents( $handle ) ) );
		}

		$out = '';
		foreach ( $lines as $line ) {
			$line = trim( (string) $line );
			if ( '' !== $line ) {
				$out .= self::rewrite_spool_line( $line, $source, $target ) . "\n";
			}
		}
		$ok = true;
		if ( '' !== $out ) {
			$ok = false;
			if ( is_dir( $target . '/spool' ) || wp_mkdir_p( $target . '/spool' ) ) {
				$out_handle = @fopen( $target . '/spool/guard-uploads.jsonl', 'ab' ); // phpcs:ignore
				if ( $out_handle ) {
					if ( @flock( $out_handle, LOCK_EX ) ) { // phpcs:ignore
						$ok = strlen( $out ) === @fwrite( $out_handle, $out ); // phpcs:ignore
						@fflush( $out_handle ); // phpcs:ignore
						@flock( $out_handle, LOCK_UN ); // phpcs:ignore
					}
					@fclose( $out_handle ); // phpcs:ignore
				}
			}
		}
		if ( $ok ) {
			if ( $handle ) {
				ftruncate( $handle, 0 );
				fflush( $handle );
			}
			Fs::delete( $work );
			Fs::delete( $dir . '/guard-uploads.work.pos' );
		}
		if ( $handle ) {
			@flock( $handle, LOCK_UN ); // phpcs:ignore
			@fclose( $handle ); // phpcs:ignore
		}
		return $ok ? true : new \WP_Error( 'wpcybersec_storage_spool', __( 'Could not move the early guard\'s waiting uploads to the new folder.', 'cybergate-security' ) );
	}

	/**
	 * @param string $line   One spool line (JSON).
	 * @param string $source Old folder.
	 * @param string $target New folder.
	 * @return string
	 */
	private static function rewrite_spool_line( $line, $source, $target ) {
		$entry = json_decode( $line, true );
		if ( ! is_array( $entry ) || ! isset( $entry['quarantine_path'] ) || ! is_string( $entry['quarantine_path'] ) ) {
			return $line;
		}
		$path = wp_normalize_path( $entry['quarantine_path'] );
		if ( 0 !== strpos( $path, $source . '/' ) ) {
			return $line;
		}
		$entry['quarantine_path'] = $target . substr( $path, strlen( $source ) );
		$json                     = wp_json_encode( $entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		return is_string( $json ) && '' !== $json ? $json : $line;
	}

	/**
	 * Points held items at the new folder. Rows are read and written by id and
	 * the prefix is replaced in PHP, so multibyte paths stay intact.
	 *
	 * @param string $from Old folder.
	 * @param string $to   New folder.
	 */
	private function rewrite_item_paths( $from, $to ) {
		global $wpdb;
		$table = Store::table( 'items' );
		$like  = $wpdb->esc_like( $from . '/' ) . '%';
		$last  = 0;
		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is Store::table(): $wpdb->prefix plus a fixed name.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, quarantine_path FROM {$table} WHERE id > %d AND quarantine_path LIKE %s ORDER BY id ASC LIMIT 500", $last, $like ), ARRAY_A );
			$rows = is_array( $rows ) ? $rows : array();
			foreach ( $rows as $row ) {
				$last = (int) $row['id'];
				$path = wp_normalize_path( (string) $row['quarantine_path'] );
				if ( 0 !== strpos( $path, $from . '/' ) ) {
					continue; // LIKE ignores case; the prefix must match exactly.
				}
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->update( $table, array( 'quarantine_path' => $to . substr( $path, strlen( $from ) ) ), array( 'id' => $last ), array( '%s' ), array( '%d' ) );
			}
		} while ( 500 === count( $rows ) );
	}

	/**
	 * Deletes files of the old folder that are in the new folder (and our own
	 * deny files and emptied spool files). Anything else stays for a retry.
	 *
	 * @param string $src Old folder (or a sub folder of it).
	 * @param string $dst Matching folder in the new location.
	 * @param string $rel Relative path of $src.
	 * @return int Files left behind.
	 */
	private static function remove_copied( $src, $dst, $rel ) {
		$left    = 0;
		$entries = @scandir( $src ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $entries ) ) {
			return 1;
		}
		foreach ( $entries as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path  = $src . '/' . $entry;
			$child = '' === $rel ? $entry : $rel . '/' . $entry;
			if ( is_link( $path ) ) {
				Fs::delete( $path );
				continue;
			}
			if ( is_dir( $path ) ) {
				$left += self::remove_copied( $path, $dst . '/' . $entry, $child );
				Fs::rmdir( $path );
				continue;
			}
			if ( 'spool/guard-import.lock' === $child ) {
				continue; // Held by this request; removed after unlocking.
			}
			if ( in_array( $child, self::SPOOL_RUNTIME, true ) ) {
				clearstatcache( true, $path );
				if ( 0 === (int) @filesize( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					Fs::delete( $path );
				} else {
					++$left; // A line arrived after it was moved: next run.
				}
				continue;
			}
			$ours = self::MARKER_FILE === $child || in_array( $entry, self::DENY_FILES, true ) || 0 === strpos( $child, 'spool/guard-uploads.work.jsonl.' );
			if ( $ours || is_file( $dst . '/' . $entry ) ) {
				if ( ! Fs::delete( $path ) ) {
					++$left;
				}
				continue;
			}
			++$left;
		}
		return $left;
	}

	/**
	 * Takes the move lock (a row in the options table, created atomically).
	 *
	 * @return true|\WP_Error
	 */
	private function acquire_move_lock() {
		global $wpdb;
		$value = time() . ':' . wp_generate_password( 16, false );
		for ( $try = 0; $try < 2; $try++ ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$added = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", self::MOVE_LOCK, $value ) );
			if ( 1 === (int) $added ) {
				$this->lock_value = $value;
				$this->lock_beat  = time();
				return true;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$current = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::MOVE_LOCK ) );
			$since   = (int) strtok( $current, ':' );
			if ( $since > time() - self::MOVE_LOCK_STALE ) {
				break;
			}
			// Left behind by a request that died: take it over.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", self::MOVE_LOCK, $current ) );
		}
		return new \WP_Error( 'wpcybersec_storage_busy', __( 'The data folder is being moved right now. Try again in a few minutes.', 'cybergate-security' ) );
	}

	/**
	 * Refreshes the move lock during a long copy.
	 */
	private function beat_move_lock() {
		global $wpdb;
		if ( '' === $this->lock_value || time() - $this->lock_beat < 60 ) {
			return;
		}
		$value = time() . ':' . substr( $this->lock_value, strpos( $this->lock_value, ':' ) + 1 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s", $value, self::MOVE_LOCK, $this->lock_value ) );
		$this->lock_value = $value;
		$this->lock_beat  = time();
	}

	/**
	 * Releases the move lock taken by this request.
	 */
	private function release_move_lock() {
		global $wpdb;
		if ( '' === $this->lock_value ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", self::MOVE_LOCK, $this->lock_value ) );
		$this->lock_value = '';
	}

	/**
	 * Exclusive flock on $file, waiting up to $wait seconds.
	 *
	 * @param string $file Lock file.
	 * @param int    $wait Seconds.
	 * @return resource|null|false Handle, null when there is nothing to lock (no folder), false when busy.
	 */
	private static function lock_file( $file, $wait ) {
		if ( ! is_dir( dirname( $file ) ) ) {
			return null;
		}
		$handle = @fopen( $file, 'c' ); // phpcs:ignore
		if ( ! $handle ) {
			return false;
		}
		$until = microtime( true ) + $wait;
		while ( ! @flock( $handle, LOCK_EX | LOCK_NB ) ) { // phpcs:ignore
			if ( microtime( true ) >= $until ) {
				@fclose( $handle ); // phpcs:ignore
				return false;
			}
			usleep( 200000 );
		}
		return $handle;
	}

	/**
	 * @param resource|null|false $handle From lock_file().
	 */
	private static function unlock_file( $handle ) {
		if ( is_resource( $handle ) ) {
			@flock( $handle, LOCK_UN ); // phpcs:ignore
			@fclose( $handle ); // phpcs:ignore
		}
	}

	/**
	 * @param string $a Folder.
	 * @param string $b Folder.
	 * @return bool
	 */
	private static function same_device( $a, $b ) {
		$sa = @stat( $a ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$sb = @stat( $b ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return is_array( $sa ) && is_array( $sb ) && isset( $sa['dev'], $sb['dev'] ) && $sa['dev'] === $sb['dev'];
	}

	/**
	 * @return bool Whether link() can be used.
	 */
	private static function can_link() {
		if ( ! function_exists( 'link' ) ) {
			return false;
		}
		$disabled = array_map( 'trim', explode( ',', strtolower( (string) ini_get( 'disable_functions' ) ) ) );
		return ! in_array( 'link', $disabled, true );
	}

	/**
	 * Lets a long file operation finish even when the browser gives up.
	 */
	public static function keep_running() {
		if ( function_exists( 'ignore_user_abort' ) ) {
			@ignore_user_abort( true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- moving the data folder must not stop half way; it is resumable, but a timeout leaves two copies until the next run.
		}
	}

	/**
	 * Activity log entry when the plugin is booted.
	 *
	 * @param string $event   Event.
	 * @param string $message Message.
	 */
	private static function log( $event, $message ) {
		if ( ! function_exists( 'wpcybersec' ) ) {
			return;
		}
		$plugin = wpcybersec();
		if ( isset( $plugin->logger ) && is_object( $plugin->logger ) ) {
			$plugin->logger->log( $event, $message );
		}
	}

	/**
	 * Recursive delete (does not follow symlinks).
	 *
	 * @param string $path File or folder.
	 */
	private static function delete_tree( $path ) {
		if ( is_link( $path ) || is_file( $path ) ) {
			Fs::delete( $path );
			return;
		}
		if ( ! is_dir( $path ) ) {
			return;
		}
		foreach ( (array) scandir( $path ) as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			self::delete_tree( $path . '/' . $entry );
		}
		Fs::rmdir( $path );
	}

	/**
	 * Deletes everything inside a folder, keeping the folder.
	 *
	 * @param string $dir Folder.
	 */
	private static function empty_dir( $dir ) {
		if ( is_link( $dir ) || ! is_dir( $dir ) ) {
			return;
		}
		foreach ( (array) scandir( $dir ) as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			self::delete_tree( $dir . '/' . $entry );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Paths                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string $sub Sub path inside the data dir.
	 * @return string
	 */
	public function path( $sub = '' ) {
		return $this->data_dir() . ( $sub ? '/' . ltrim( $sub, '/' ) : '' );
	}

	/** @return string */
	public function quarantine_dir() {
		return $this->path( 'quarantine' );
	}

	/** @return string */
	public function jobs_dir() {
		return $this->path( 'jobs' );
	}

	/** @return string */
	public function spool_dir() {
		return $this->path( 'spool' );
	}

	/** @return string */
	public function guard_dir() {
		return $this->path( 'guard' );
	}

	/**
	 * Creates the directory tree and drops deny files into each folder.
	 *
	 * @return true|\WP_Error
	 */
	public function ensure() {
		$dirs = array( $this->data_dir(), $this->quarantine_dir(), $this->jobs_dir(), $this->spool_dir(), $this->guard_dir() );
		foreach ( $dirs as $dir ) {
			if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
				/* translators: %s: directory path */
				return new \WP_Error( 'wpcybersec_storage', sprintf( __( 'Could not create %s. Check folder permissions.', 'cybergate-security' ), $dir ) );
			}
			$this->protect( $dir );
		}
		return true;
	}

	/**
	 * Blocks web access to a folder on Apache, LiteSpeed and IIS, and hides listings.
	 * Nginx ignores these files, so the advanced settings page shows an nginx rule.
	 *
	 * @param string $dir Directory.
	 */
	public function protect( $dir ) {
		$files = array(
			'.htaccess'  => "# CyberGate Security: no web access.\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\nOptions -Indexes\n<IfModule mod_php.c>\n\tphp_flag engine off\n</IfModule>\n<IfModule mod_php7.c>\n\tphp_flag engine off\n</IfModule>\n",
			'index.php'  => "<?php\n// Silence is golden.\n",
			'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
		);
		foreach ( $files as $name => $content ) {
			$file = $dir . '/' . $name;
			if ( ! file_exists( $file ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				@file_put_contents( $file, $content );
			}
		}
	}

	/**
	 * Whether a path is reachable through the web server document root.
	 *
	 * @param string $path Absolute path.
	 * @return bool
	 */
	public function is_in_webroot( $path ) {
		$path  = wp_normalize_path( (string) ( realpath( $path ) ?: $path ) );
		$roots = array( wp_normalize_path( (string) ( realpath( ABSPATH ) ?: ABSPATH ) ) );
		if ( ! empty( $_SERVER['DOCUMENT_ROOT'] ) ) {
			$doc = realpath( wp_unslash( $_SERVER['DOCUMENT_ROOT'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( $doc ) {
				$roots[] = wp_normalize_path( $doc );
			}
		}
		foreach ( $roots as $root ) {
			if ( 0 === strpos( trailingslashit( $path ), trailingslashit( $root ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether $path is inside $dir (after resolving symlinks and "..").
	 *
	 * @param string $path File or folder.
	 * @param string $dir  Parent folder.
	 * @return bool
	 */
	public static function is_within( $path, $dir ) {
		$real_dir  = realpath( $dir );
		$real_path = realpath( $path );
		if ( false === $real_path ) {
			$parent    = realpath( dirname( $path ) );
			$real_path = $parent ? $parent . '/' . basename( $path ) : false;
		}
		if ( ! $real_dir || ! $real_path ) {
			return false;
		}
		return 0 === strpos( trailingslashit( wp_normalize_path( $real_path ) ), trailingslashit( wp_normalize_path( $real_dir ) ) )
			|| wp_normalize_path( $real_path ) === wp_normalize_path( $real_dir );
	}
}
