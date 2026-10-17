<?php
/**
 * Activation, upgrades and deactivation.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Must work before the plugin is booted: activation runs after plugins_loaded
 * has already fired, so nothing here may rely on wpcybersec()->service.
 */
class Installer {

	const DB_OPTION       = 'wpcybersec_db_version';
	const REDIRECT_OPTION = 'wpcybersec_activation_redirect';

	/** Cron hooks owned by the plugin. */
	const CRON_HOOKS = array(
		'wpcybersec_scheduled_scan',
		'wpcybersec_scan_tick',
		'wpcybersec_digest',
		'wpcybersec_maintenance',
		'wpcybersec_guard_import',
		'wpcybersec_notify_flush',
	);

	/**
	 * Activation hook. On multisite the plugin is network activated only
	 * (header "Network: true") and works once for the whole network.
	 *
	 * @param bool $network_wide Network activation (multisite).
	 */
	public static function activate( $network_wide = false ) {
		unset( $network_wide );
		self::install();
		// Read by Admin on the next admin page load to open the setup wizard.
		Network::update_option( self::REDIRECT_OPTION, get_current_user_id() ? get_current_user_id() : 1, false );
		if ( Network::get_option( 'wpcybersec_guard_installed' ) ) {
			Guard_Config::set_enabled( true );
		}
	}

	/**
	 * Creates or updates tables, default settings and the data folder.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$items   = Store::table( 'items' );
		$man     = Store::table( 'manifest' );
		$allow   = Store::table( 'allowlist' );
		$log     = Store::table( 'log' );

		/*
		 * Index sizes: utf8mb4 needs 4 bytes per character and InnoDB COMPACT rows
		 * (MySQL 5.6, MariaDB 10.1 without large prefixes) allow 767 bytes per
		 * index. The allowlist unique key (kind, value) is (16 + 150) x 4 = 664
		 * bytes. Values are sha256 hex (64) or "plugin:<folder>" install keys.
		 */
		$sql = array(
			"CREATE TABLE {$items} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				type varchar(20) NOT NULL DEFAULT '',
				status varchar(20) NOT NULL DEFAULT 'pending',
				severity tinyint(3) unsigned NOT NULL DEFAULT 0,
				path text NOT NULL,
				original_path text NOT NULL,
				quarantine_path text NOT NULL,
				sha256 char(64) NOT NULL DEFAULT '',
				size bigint(20) unsigned NOT NULL DEFAULT 0,
				mime varchar(100) NOT NULL DEFAULT '',
				source varchar(50) NOT NULL DEFAULT '',
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				ip varchar(45) NOT NULL DEFAULT '',
				details longtext NULL,
				created_at datetime NOT NULL,
				updated_at datetime NOT NULL,
				decided_by bigint(20) unsigned NOT NULL DEFAULT 0,
				decided_at datetime NULL DEFAULT NULL,
				PRIMARY KEY  (id),
				KEY type_status (type,status),
				KEY sha256 (sha256)
			) {$charset};",
			"CREATE TABLE {$man} (
				path_hash char(40) NOT NULL,
				path text NOT NULL,
				sha256 char(64) NOT NULL DEFAULT '',
				size bigint(20) unsigned NOT NULL DEFAULT 0,
				mtime int(10) unsigned NOT NULL DEFAULT 0,
				state varchar(12) NOT NULL DEFAULT 'trusted',
				run_id varchar(32) NOT NULL DEFAULT '',
				updated_at datetime NOT NULL,
				PRIMARY KEY  (path_hash),
				KEY run_id (run_id),
				KEY state (state),
				KEY mtime (mtime)
			) {$charset};",
			"CREATE TABLE {$allow} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				kind varchar(16) NOT NULL DEFAULT 'hash',
				value varchar(150) NOT NULL,
				label varchar(255) NOT NULL DEFAULT '',
				note text NULL,
				created_by bigint(20) unsigned NOT NULL DEFAULT 0,
				created_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY kind_value (kind,value)
			) {$charset};",
			"CREATE TABLE {$log} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				event varchar(50) NOT NULL DEFAULT '',
				message text NOT NULL,
				context longtext NULL,
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				ip varchar(45) NOT NULL DEFAULT '',
				created_at datetime NOT NULL,
				PRIMARY KEY  (id),
				KEY event (event),
				KEY created_at (created_at)
			) {$charset};",
		);
		// Multisite: settings and state of an older per-site install move to
		// network options before defaults are seeded (see Network).
		Network::migrate_main_options();

		dbDelta( $sql );

		if ( false === Network::get_option( Settings::OPTION, false ) ) {
			Network::add_option( Settings::OPTION, Settings::defaults(), '', true );
		}
		if ( ! Network::get_option( 'wpcybersec_installed_at' ) ) {
			Network::add_option( 'wpcybersec_installed_at', time(), '', false );
		}

		// Where the data can live (a fallback inside uploads when wp-content is
		// read-only); remembered so the admin notice can explain a problem.
		$storage = new Storage();
		$status  = $storage->check();
		if ( 'unavailable' !== $status['state'] ) {
			$storage->ensure();
		}

		// Administrators present now are trusted; later ones wait for review.
		User_Watch::seed();

		Network::update_option( self::DB_OPTION, WPCYBERSEC_DB_VERSION, true );

		// Per-site tables and options of the other sites (bounded; the rest
		// continues on later admin, cron and CLI requests, see Plugin::boot()).
		if ( Network::migration_pending() && did_action( 'init' ) ) {
			Network::migrate_sites();
		}
	}

	/**
	 * Runs install() again when the DB version changed (after plugin updates).
	 */
	public static function maybe_upgrade() {
		$old = Network::get_option( self::DB_OPTION );
		if ( $old !== WPCYBERSEC_DB_VERSION ) {
			self::install();
			if ( $old && version_compare( (string) $old, '3', '<' ) ) {
				self::add_default_exclusion( 'error_log' );
			}
		}
	}

	/**
	 * Adds a pattern that became a default to the saved exclusions of an
	 * existing install (once, when upgrading past the version that added it).
	 *
	 * @param string $pattern Exclusion pattern.
	 */
	private static function add_default_exclusion( $pattern ) {
		$settings = Network::get_option( Settings::OPTION, array() );
		if ( ! is_array( $settings ) || ! isset( $settings['exclusions'] ) || ! is_array( $settings['exclusions'] ) ) {
			return; // Defaults apply.
		}
		if ( ! in_array( $pattern, $settings['exclusions'], true ) ) {
			$settings['exclusions'][] = $pattern;
			Network::update_option( Settings::OPTION, $settings );
		}
	}

	/**
	 * Deactivation hook: stops cron (on every site of a network) and switches
	 * the early guard off so it does not keep holding uploads while the plugin
	 * is inactive.
	 *
	 * @param bool $network_wide Network deactivation (multisite).
	 */
	public static function deactivate( $network_wide = false ) {
		unset( $network_wide );
		Network::clear_cron_everywhere();
		Guard_Config::set_enabled( false );
		Network::delete_option( self::REDIRECT_OPTION );
	}

	/**
	 * @return string[] Table names.
	 */
	public static function tables() {
		return array( Store::table( 'items' ), Store::table( 'manifest' ), Store::table( 'allowlist' ), Store::table( 'log' ) );
	}
}
