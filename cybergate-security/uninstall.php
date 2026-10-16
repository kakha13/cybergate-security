<?php
/**
 * Uninstall: removes data only when "Delete all data on uninstall" is on.
 * Backups of wp-config.php are always removed.
 *
 * @package WPCyberSecurity
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

/*
 * The data folder, resolved like Storage::data_dir(): WPCYBERSEC_DATA_DIR, else
 * the folder chosen by the one-click move (single sites only), else
 * wp-content/wpcybersec. Read before the options are deleted.
 */
$wpcybersec_default = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) . '/wpcybersec';
$wpcybersec_moved   = is_multisite() ? '' : get_option( 'wpcybersec_data_dir', '' );
$wpcybersec_moved   = is_string( $wpcybersec_moved ) && '' !== $wpcybersec_moved ? untrailingslashit( wp_normalize_path( $wpcybersec_moved ) ) : '';
if ( defined( 'WPCYBERSEC_DATA_DIR' ) && WPCYBERSEC_DATA_DIR ) {
	$wpcybersec_data = untrailingslashit( wp_normalize_path( WPCYBERSEC_DATA_DIR ) );
} elseif ( '' !== $wpcybersec_moved && is_dir( $wpcybersec_moved ) ) {
	$wpcybersec_data = $wpcybersec_moved;
} else {
	$wpcybersec_data = $wpcybersec_default;
}

/*
 * Backups of wp-config.php hold the database password and the salts: remove
 * them even when the rest of the data is kept. Only the plugin's own backup
 * files and deny files are deleted, so a folder set by hand stays intact.
 */
foreach ( array_unique( array( $wpcybersec_data, $wpcybersec_default ) ) as $wpcybersec_base ) {
	$wpcybersec_backups = $wpcybersec_base . '/backups';
	if ( ! is_dir( $wpcybersec_backups ) || is_link( $wpcybersec_backups ) ) {
		continue;
	}
	foreach ( (array) scandir( $wpcybersec_backups ) as $wpcybersec_name ) {
		$wpcybersec_file = $wpcybersec_backups . '/' . $wpcybersec_name;
		if ( ( is_file( $wpcybersec_file ) || is_link( $wpcybersec_file ) ) && ( preg_match( '/^wp-config-[0-9-]+(-[a-z0-9]+)?(\.php)?\.bak$/', $wpcybersec_name ) || in_array( $wpcybersec_name, array( '.htaccess', 'index.php', 'web.config' ), true ) ) ) {
			@unlink( $wpcybersec_file ); // phpcs:ignore
		}
	}
	@rmdir( $wpcybersec_backups ); // phpcs:ignore
}

$wpcybersec_settings = get_option( 'wpcybersec_settings', array() );
if ( empty( $wpcybersec_settings['delete_data_on_uninstall'] ) ) {
	return;
}

foreach ( array( 'items', 'manifest', 'allowlist', 'log' ) as $wpcybersec_table ) {
	$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'wpcybersec_' . $wpcybersec_table ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table names come from the fixed list above.
}

$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'wpcybersec\\_%' OR option_name LIKE '\\_transient\\_wpcybersec\\_%' OR option_name LIKE '\\_transient\\_timeout\\_wpcybersec\\_%'" ); // phpcs:ignore WordPress.DB

foreach ( array( 'wpcybersec_scheduled_scan', 'wpcybersec_scan_tick', 'wpcybersec_digest', 'wpcybersec_maintenance', 'wpcybersec_guard_import', 'wpcybersec_notify_flush' ) as $wpcybersec_hook ) {
	wp_clear_scheduled_hook( $wpcybersec_hook );
}

delete_metadata( 'user', 0, 'wpcybersec_dismiss_setup', '', true );
delete_metadata( 'user', 0, 'wpcybersec_dismiss_pending', '', true );
delete_metadata( 'user', 0, 'wpcybersec_diff_layout', '', true );

/*
 * Remove the data folder: the default one inside wp-content, and the one the
 * plugin moved itself, but only when that folder carries this site's marker
 * file (another install on the same server may use a folder with a similar
 * name). A WPCYBERSEC_DATA_DIR set by hand in wp-config.php is left for the
 * system administrator.
 */
$wpcybersec_marker_ok = static function ( $dir ) use ( $wpdb ) {
	$file = $dir . '/.wpcybersec-site';
	if ( ! is_file( $file ) || is_link( $file ) ) {
		return false;
	}
	$text = (string) @file_get_contents( $file, false, null, 0, 1024 ); // phpcs:ignore
	// Same id as WPCyberSecurity\Storage::site_id().
	$id = substr( md5( ABSPATH . $wpdb->prefix ), 0, 8 );
	return (bool) preg_match( '/^site:\s*' . $id . '\s*$/m', $text );
};
$wpcybersec_dirs = array();
if ( ! defined( 'WPCYBERSEC_DATA_DIR' ) ) {
	$wpcybersec_dirs[] = $wpcybersec_default;
	if ( '' !== $wpcybersec_moved && $wpcybersec_moved !== $wpcybersec_default && 0 === strpos( basename( $wpcybersec_moved ), 'wpcybersec-' ) && is_dir( $wpcybersec_moved ) && ! is_link( $wpcybersec_moved ) && $wpcybersec_marker_ok( $wpcybersec_moved ) ) {
		$wpcybersec_dirs[] = $wpcybersec_moved;
	}
}
foreach ( $wpcybersec_dirs as $wpcybersec_dir ) {
	if ( ! is_dir( $wpcybersec_dir ) || is_link( $wpcybersec_dir ) ) {
		continue;
	}
	$wpcybersec_it = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $wpcybersec_dir, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ( $wpcybersec_it as $wpcybersec_file ) {
		if ( $wpcybersec_file->isLink() || $wpcybersec_file->isFile() ) {
			@unlink( $wpcybersec_file->getPathname() ); // phpcs:ignore
		} else {
			@rmdir( $wpcybersec_file->getPathname() ); // phpcs:ignore
		}
	}
	@rmdir( $wpcybersec_dir ); // phpcs:ignore
}

/*
 * The guard bootstrap (ABSPATH/wpcybersec-guard.php) is removed only when it is
 * certain that nothing points auto_prepend_file at it. Deleting it while PHP
 * still prepends it makes every request on the site fail with a fatal error.
 * Left in place it does nothing: it only loads the guard when the plugin's
 * guard file and config still exist, and both are gone after uninstall.
 *
 * It is always kept when uninstalling from WP-CLI: the command line PHP does
 * not see the web server's settings (mod_php .htaccess values, PHP-FPM pool,
 * nginx fastcgi_param, the web php.ini), so ini_get() proves nothing there.
 */
$wpcybersec_bootstrap = ABSPATH . 'wpcybersec-guard.php';
if ( is_file( $wpcybersec_bootstrap ) && ! is_link( $wpcybersec_bootstrap ) && 'cli' !== PHP_SAPI && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
	$wpcybersec_referenced = false !== strpos( (string) ini_get( 'auto_prepend_file' ), 'wpcybersec-guard.php' );

	// Also check the files the guard setup tells administrators to edit, in
	// case PHP has not picked up a change yet (.user.ini is cached for minutes).
	$wpcybersec_ini_name = (string) ini_get( 'user_ini.filename' );
	$wpcybersec_ini_name = '' === $wpcybersec_ini_name ? '.user.ini' : $wpcybersec_ini_name;
	$wpcybersec_configs  = array_unique(
		array(
			ABSPATH . '.htaccess',
			ABSPATH . $wpcybersec_ini_name,
			ABSPATH . '.user.ini',
			dirname( ABSPATH ) . '/.htaccess',
			dirname( ABSPATH ) . '/' . $wpcybersec_ini_name,
			dirname( ABSPATH ) . '/.user.ini',
		)
	);
	foreach ( $wpcybersec_configs as $wpcybersec_config ) {
		if ( $wpcybersec_referenced ) {
			break;
		}
		if ( ! @is_readable( $wpcybersec_config ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			continue;
		}
		foreach ( preg_split( '/\r\n|\n|\r/', (string) @file_get_contents( $wpcybersec_config ) ) as $wpcybersec_line ) { // phpcs:ignore
			$wpcybersec_line = ltrim( $wpcybersec_line );
			if ( '' === $wpcybersec_line || ';' === $wpcybersec_line[0] || '#' === $wpcybersec_line[0] ) {
				continue;
			}
			if ( false !== stripos( $wpcybersec_line, 'auto_prepend_file' ) && false !== strpos( $wpcybersec_line, 'wpcybersec-guard.php' ) ) {
				$wpcybersec_referenced = true;
				break;
			}
		}
	}

	// Only delete the file this plugin generated.
	$wpcybersec_head = (string) @file_get_contents( $wpcybersec_bootstrap, false, null, 0, 4096 ); // phpcs:ignore
	if ( ! $wpcybersec_referenced && false !== strpos( $wpcybersec_head, 'WPCYBERSEC_GUARD_BOOTSTRAPPED' ) ) {
		@unlink( $wpcybersec_bootstrap ); // phpcs:ignore
	}
}
