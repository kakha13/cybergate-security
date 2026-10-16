<?php
/**
 * Admin menu, assets, notices, admin bar and admin-post handlers.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Decisions;
use WPCyberSecurity\Installer;
use WPCyberSecurity\Store;

defined( 'ABSPATH' ) || exit;

/**
 * Glue for every admin screen of the plugin. Pages:
 *
 *   wpcybersec           Dashboard_Page
 *   wpcybersec-reports   Reports_Page
 *   wpcybersec-settings  Settings_Page (setup module)
 *   wpcybersec-wizard    Wizard (setup module)
 *
 * Other modules can rely on:
 *   Admin::header( $title, $subtitle, $actions_html )   page header partial
 *   Admin::page_url( $page, $args )                     admin URL of a plugin page
 *   Admin::is_plugin_page()                             true on any plugin screen
 *   action wpcybersec_admin_enqueue( $page, $hook )     fires after base + admin assets are enqueued
 *   filter wpcybersec_is_plugin_screen( $bool, $hook )  extend which screens get the assets
 */
class Admin {

	/**
	 * Capability on a single site. On multisite every screen and handler needs
	 * NETWORK_CAP instead (see cap()), because the plugin works on the shared
	 * file system: a site administrator must not be able to change the scan
	 * folder, quarantine or download files of the whole network.
	 */
	const CAP         = 'manage_options';
	const NETWORK_CAP = 'manage_network_options';

	const PAGE_DASHBOARD = 'wpcybersec';
	const PAGE_REPORTS   = 'wpcybersec-reports';
	const PAGE_SETTINGS  = 'wpcybersec-settings';
	const PAGE_WIZARD    = 'wpcybersec-wizard';

	const META_DISMISS_SETUP   = 'wpcybersec_dismiss_setup';
	const META_DISMISS_PENDING = 'wpcybersec_dismiss_pending';

	/** @var array|null Per-request cache of Store::counts(). */
	private static $counts = null;

	/** @var object|null Admin\Settings_Page instance (setup module). */
	private $settings_page = null;

	/** @var object|null Admin\Wizard instance (setup module). */
	private $wizard = null;

	/** @var bool */
	private $admin_bar_registered = false;

	/**
	 * Capability required for every plugin screen, AJAX endpoint and admin-post
	 * handler.
	 *
	 * @return string
	 */
	public static function cap() {
		return is_multisite() ? self::NETWORK_CAP : self::CAP;
	}

	/**
	 * Whether the current user may use the plugin (see cap()).
	 *
	 * @return bool
	 */
	public static function can() {
		return current_user_can( self::cap() );
	}

	/**
	 * Hooks. Runs on plugins_loaded inside is_admin() requests (admin pages,
	 * admin-post.php and admin-ajax.php).
	 */
	public function register() {
		// Setup module pages register their own handlers (admin-post wpcybersec_wizard, wpcybersec_save_settings).
		$this->settings_page = $this->make( __NAMESPACE__ . '\\Settings_Page' );
		$this->wizard        = $this->make( __NAMESPACE__ . '\\Wizard' );
		foreach ( array( $this->settings_page, $this->wizard ) as $page ) {
			if ( is_object( $page ) && method_exists( $page, 'register' ) ) {
				$page->register();
			}
		}

		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_menu', array( $this, 'menu_bubbles' ), 999 );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_init', array( $this, 'maybe_redirect' ), 1 );
		add_action( 'admin_notices', array( $this, 'notices' ) );
		add_filter( 'plugin_action_links_' . WPCYBERSEC_BASENAME, array( $this, 'action_links' ) );
		add_filter( 'removable_query_args', array( $this, 'removable_query_args' ) );

		add_action( 'admin_post_wpcybersec_download', array( $this, 'handle_download' ) );
		add_action( 'admin_post_wpcybersec_allowlist_remove', array( $this, 'handle_allowlist_remove' ) );
		add_action( 'admin_post_wpcybersec_reports_bulk', array( $this, 'handle_reports_bulk' ) );
		add_action( 'admin_post_wpcybersec_dismiss_notice', array( $this, 'handle_dismiss_notice' ) );

		$this->register_admin_bar();
	}

	/**
	 * Admin bar node. Public so the front end can show it too:
	 * ( new Admin\Admin() )->register_admin_bar().
	 */
	public function register_admin_bar() {
		if ( $this->admin_bar_registered ) {
			return;
		}
		$this->admin_bar_registered = true;
		add_action( 'admin_bar_menu', array( $this, 'admin_bar' ), 85 );
		add_action( 'wp_enqueue_scripts', array( $this, 'admin_bar_style' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'admin_bar_style' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Menu                                                                */
	/* ------------------------------------------------------------------ */

	/**
	 * Registers the top level menu and its pages.
	 */
	public function menu() {
		$dashboard = new Dashboard_Page();
		$reports   = new Reports_Page();

		add_menu_page(
			__( 'WP Cyber Security', 'wp-cyber-security' ),
			__( 'Cyber Security', 'wp-cyber-security' ),
			self::cap(),
			self::PAGE_DASHBOARD,
			array( $dashboard, 'render' ),
			'dashicons-shield',
			80
		);

		add_submenu_page(
			self::PAGE_DASHBOARD,
			__( 'Security Dashboard', 'wp-cyber-security' ),
			__( 'Dashboard', 'wp-cyber-security' ),
			self::cap(),
			self::PAGE_DASHBOARD,
			array( $dashboard, 'render' )
		);

		add_submenu_page(
			self::PAGE_DASHBOARD,
			__( 'Security Reports', 'wp-cyber-security' ),
			__( 'Reports', 'wp-cyber-security' ),
			self::cap(),
			self::PAGE_REPORTS,
			array( $reports, 'render' )
		);

		add_submenu_page(
			self::PAGE_DASHBOARD,
			__( 'Security Settings', 'wp-cyber-security' ),
			__( 'Settings', 'wp-cyber-security' ),
			self::cap(),
			self::PAGE_SETTINGS,
			$this->page_callback( $this->settings_page, __( 'Settings', 'wp-cyber-security' ) )
		);

		add_submenu_page(
			self::PAGE_DASHBOARD,
			__( 'Security Setup Wizard', 'wp-cyber-security' ),
			__( 'Setup Wizard', 'wp-cyber-security' ),
			self::cap(),
			self::PAGE_WIZARD,
			$this->page_callback( $this->wizard, __( 'Setup Wizard', 'wp-cyber-security' ) )
		);
	}

	/**
	 * Appends count bubbles after the menu is built, so page hook names stay
	 * stable ("cyber-security_page_wpcybersec-reports") whatever the count is.
	 */
	public function menu_bubbles() {
		global $menu, $submenu;
		if ( ! self::can() ) {
			return;
		}
		$counts = self::counts();
		$total  = $counts['pending'] + $counts['threats'];
		if ( $total < 1 ) {
			return;
		}
		$bubble = self::bubble_html( $total );

		if ( is_array( $menu ) ) {
			foreach ( $menu as $key => $item ) {
				if ( isset( $item[2] ) && self::PAGE_DASHBOARD === $item[2] ) {
					$menu[ $key ][0] .= $bubble; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				}
			}
		}
		if ( isset( $submenu[ self::PAGE_DASHBOARD ] ) && is_array( $submenu[ self::PAGE_DASHBOARD ] ) ) {
			foreach ( $submenu[ self::PAGE_DASHBOARD ] as $key => $item ) {
				if ( isset( $item[2] ) && self::PAGE_REPORTS === $item[2] ) {
					$submenu[ self::PAGE_DASHBOARD ][ $key ][0] .= $bubble; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				}
			}
		}
	}

	/**
	 * WordPress' standard "awaiting-mod" count bubble.
	 *
	 * @param int $total Count.
	 * @return string
	 */
	private static function bubble_html( $total ) {
		$total = (int) $total;
		return sprintf(
			' <span class="awaiting-mod wpcs-menu-count count-%1$d"><span class="pending-count" aria-hidden="true">%2$s</span><span class="screen-reader-text">%3$s</span></span>',
			$total,
			esc_html( number_format_i18n( $total ) ),
			esc_html(
				sprintf(
					/* translators: %s: number of items */
					_n( '%s item needs your review', '%s items need your review', $total, 'wp-cyber-security' ),
					number_format_i18n( $total )
				)
			)
		);
	}

	/**
	 * Creates a setup module page object if its class is available.
	 *
	 * @param string $class Fully qualified class name.
	 * @return object|null
	 */
	private function make( $class ) {
		try {
			if ( class_exists( $class ) ) {
				return new $class();
			}
		} catch ( \Throwable $e ) {
			self::debug_log( $e );
		}
		return null;
	}

	/**
	 * @param object|null $page  Page object with render().
	 * @param string      $label Page name for the fallback message.
	 * @return callable
	 */
	private function page_callback( $page, $label ) {
		if ( is_object( $page ) && method_exists( $page, 'render' ) ) {
			return array( $page, 'render' );
		}
		return static function () use ( $label ) {
			self::render_missing( $label );
		};
	}

	/**
	 * Fallback when a page from another module is not installed.
	 *
	 * @param string $label Page name.
	 */
	public static function render_missing( $label ) {
		echo '<div class="wrap wpcs-wrap">';
		self::header( $label );
		echo '<div class="wpcs-notice wpcs-notice--warn"><span class="dashicons dashicons-warning" aria-hidden="true"></span><div><p><strong>'
			. esc_html__( 'This page is not available.', 'wp-cyber-security' )
			. '</strong></p><p>'
			. esc_html__( 'Some plugin files are missing or could not be loaded. Reinstall WP Cyber Security to restore them. Your settings, approvals and allowlist are kept.', 'wp-cyber-security' )
			. '</p></div></div>';
		echo '<p><a class="button" href="' . esc_url( self::page_url( self::PAGE_DASHBOARD ) ) . '">' . esc_html__( 'Back to the dashboard', 'wp-cyber-security' ) . '</a></p>';
		echo '</div>';
	}

	/* ------------------------------------------------------------------ */
	/* Assets                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Registers shared handles everywhere and enqueues them on plugin screens
	 * (dashboard, reports, settings and wizard).
	 *
	 * @param string $hook Admin page hook suffix.
	 */
	public function enqueue( $hook ) {
		Assets::register();

		if ( ! $this->is_plugin_screen( $hook ) ) {
			return;
		}

		Assets::enqueue();
		wp_enqueue_style( 'wpcybersec-admin', WPCYBERSEC_URL . 'assets/css/admin.css', array( 'wpcybersec-base' ), \WPCyberSecurity\Admin\Assets::ver( 'assets/css/admin.css' ) );
		wp_enqueue_script( 'wpcybersec-admin', WPCYBERSEC_URL . 'assets/js/admin.js', array( 'wpcybersec-core' ), \WPCyberSecurity\Admin\Assets::ver( 'assets/js/admin.js' ), true );
		wp_localize_script(
			'wpcybersec-admin',
			'wpcybersecAdmin',
			array(
				'i18n' => array(
					'details'        => __( 'Details', 'wp-cyber-security' ),
					'hideDetails'    => __( 'Hide details', 'wp-cyber-security' ),
					'chooseAction'   => __( 'Choose a bulk action first.', 'wp-cyber-security' ),
					'chooseItems'    => __( 'Select at least one item.', 'wp-cyber-security' ),
					'confirmDeleteOne' => __( 'Delete the selected item permanently? Its held copy or live file is removed and this cannot be undone.', 'wp-cyber-security' ),
					/* translators: %s: number of items */
					'confirmDelete'    => __( 'Delete %s items permanently? Held copies and live files are removed and this cannot be undone.', 'wp-cyber-security' ),
					'confirmDenyOne'   => __( 'Deny the selected item? Its held copy is deleted.', 'wp-cyber-security' ),
					/* translators: %s: number of items */
					'confirmDeny'      => __( 'Deny %s items? Their held copies are deleted.', 'wp-cyber-security' ),
					'bulkDoneOne'      => __( '1 item updated.', 'wp-cyber-security' ),
					/* translators: %s: number of items */
					'bulkDone'         => __( '%s items updated.', 'wp-cyber-security' ),
					'bulkFailedOne'    => __( '1 item could not be changed:', 'wp-cyber-security' ),
					/* translators: %s: number of items */
					'bulkFailed'       => __( '%s items could not be changed:', 'wp-cyber-security' ),
					'working'        => __( 'Working...', 'wp-cyber-security' ),
					'comparing'      => __( 'Comparing...', 'wp-cyber-security' ),
					'unlocked'       => __( 'File changes unlocked. Install or update what you need, then lock again.', 'wp-cyber-security' ),
					'locked'         => __( 'File changes locked.', 'wp-cyber-security' ),
					'refreshing'     => __( 'Scan finished. Refreshing the dashboard...', 'wp-cyber-security' ),
					/* translators: %s: number of items */
					'menuCount'      => __( '%s items need your review', 'wp-cyber-security' ),
				),
			)
		);

		/**
		 * Fires after the base, core and admin assets are enqueued on a plugin screen.
		 * The setup module can enqueue setup.css / setup.js here.
		 *
		 * @param string $page Current plugin page slug (wpcybersec, wpcybersec-reports, ...).
		 * @param string $hook Admin page hook suffix.
		 */
		do_action( 'wpcybersec_admin_enqueue', self::current_page(), $hook );
	}

	/**
	 * @param string $hook Admin page hook suffix.
	 * @return bool
	 */
	private function is_plugin_screen( $hook ) {
		$is = ( false !== strpos( (string) $hook, 'wpcybersec' ) ) || self::is_plugin_page();

		/**
		 * Filters whether the shared plugin assets load on this screen.
		 *
		 * @param bool   $is   Whether this is a plugin screen.
		 * @param string $hook Admin page hook suffix.
		 */
		return (bool) apply_filters( 'wpcybersec_is_plugin_screen', $is, $hook );
	}

	/**
	 * @return string Current plugin page slug, '' when not on a plugin page.
	 */
	public static function current_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		return 0 === strpos( $page, 'wpcybersec' ) ? $page : '';
	}

	/**
	 * @return bool True on any of the plugin's admin pages.
	 */
	public static function is_plugin_page() {
		return is_admin() && '' !== self::current_page();
	}

	/* ------------------------------------------------------------------ */
	/* Page header and shared helpers                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Prints the page header used by every plugin page.
	 *
	 * @param string $title        Page title (plain text).
	 * @param string $subtitle     Short description (plain text).
	 * @param string $actions_html Buttons/links, already escaped by the caller (filtered through wp_kses).
	 */
	public static function header( $title, $subtitle = '', $actions_html = '' ) {
		echo '<div class="wpcs-header">';
		echo '<div class="wpcs-header__icon" aria-hidden="true"><span class="dashicons dashicons-shield"></span></div>';
		echo '<div class="wpcs-header__text"><h1>' . esc_html( $title ) . '</h1>';
		if ( '' !== (string) $subtitle ) {
			echo '<p>' . esc_html( $subtitle ) . '</p>';
		}
		echo '</div>';
		if ( '' !== trim( (string) $actions_html ) ) {
			echo '<div class="wpcs-header__actions">' . wp_kses( $actions_html, self::allowed_header_html() ) . '</div>';
		}
		echo '</div>';
		// WordPress moves admin notices after this marker instead of into the header.
		echo '<hr class="wp-header-end">';
	}

	/**
	 * Tags allowed in header actions.
	 *
	 * @return array
	 */
	private static function allowed_header_html() {
		$common = array(
			'class'            => true,
			'id'               => true,
			'title'            => true,
			'role'             => true,
			'aria-label'       => true,
			'aria-hidden'      => true,
			'aria-expanded'    => true,
			'aria-controls'    => true,
			'aria-describedby' => true,
			'data-*'           => true,
		);
		$allowed = array(
			'a'      => array_merge( $common, array( 'href' => true, 'target' => true, 'rel' => true ) ),
			'button' => array_merge( $common, array( 'type' => true, 'name' => true, 'value' => true, 'disabled' => true, 'form' => true ) ),
			'span'   => $common,
			'strong' => $common,
			'em'     => $common,
			'form'   => array_merge( $common, array( 'action' => true, 'method' => true ) ),
			'input'  => array_merge( $common, array( 'type' => true, 'name' => true, 'value' => true, 'checked' => true, 'disabled' => true, 'form' => true ) ),
			'select' => array_merge( $common, array( 'name' => true, 'disabled' => true, 'form' => true ) ),
			'option' => array_merge( $common, array( 'value' => true, 'selected' => true ) ),
		);

		/**
		 * Filters the HTML allowed in page header actions.
		 *
		 * @param array $allowed wp_kses allowed tags.
		 */
		return apply_filters( 'wpcybersec_header_allowed_html', $allowed );
	}

	/**
	 * Admin URL of a plugin page.
	 *
	 * @param string $page Page slug (wpcybersec, wpcybersec-reports, ...).
	 * @param array  $args Extra query args (raw values, encoded here).
	 * @return string Unescaped URL.
	 */
	public static function page_url( $page, $args = array() ) {
		$query = array( 'page' => sanitize_key( $page ) );
		foreach ( (array) $args as $key => $value ) {
			if ( null === $value || '' === $value || false === $value ) {
				continue;
			}
			$query[ sanitize_key( $key ) ] = rawurlencode( (string) $value );
		}
		return add_query_arg( $query, admin_url( 'admin.php' ) );
	}

	/**
	 * Store::counts() with a per-request cache and zero fallback.
	 *
	 * @param bool $fresh Bypass the cache.
	 * @return array { pending, threats, quarantined }
	 */
	public static function counts( $fresh = false ) {
		if ( null === self::$counts || $fresh ) {
			$counts       = self::call( 'store', 'counts', array(), array() );
			$counts       = is_array( $counts ) ? $counts : array();
			self::$counts = array(
				'pending'     => isset( $counts['pending'] ) ? (int) $counts['pending'] : 0,
				'threats'     => isset( $counts['threats'] ) ? (int) $counts['threats'] : 0,
				'quarantined' => isset( $counts['quarantined'] ) ? (int) $counts['quarantined'] : 0,
			);
		}
		return self::$counts;
	}

	/**
	 * A service from the container, or null when it is missing.
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
	 * Calls a service method defensively: a missing module or an exception
	 * returns $default instead of breaking the admin screen.
	 *
	 * @param string $service Service name.
	 * @param string $method  Method name.
	 * @param array  $args    Arguments.
	 * @param mixed  $default Fallback.
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
			self::debug_log( $e );
			return $default;
		}
	}

	/**
	 * @param string $key     Setting.
	 * @param mixed  $default Fallback.
	 * @return mixed
	 */
	public static function setting( $key, $default = null ) {
		return self::call( 'settings', 'get', array( $key, $default ), $default );
	}

	/**
	 * @param \Throwable $e Error.
	 */
	public static function debug_log( $e ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && $e instanceof \Throwable ) {
			error_log( 'WP Cyber Security admin: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		}
	}

	/**
	 * UTC "Y-m-d H:i:s" to a unix timestamp (0 when empty).
	 *
	 * @param string $utc Datetime.
	 * @return int
	 */
	public static function utc_ts( $utc ) {
		$utc = (string) $utc;
		if ( '' === $utc || 0 === strpos( $utc, '0000-00-00' ) ) {
			return 0;
		}
		$ts = strtotime( $utc . ' UTC' );
		return $ts ? (int) $ts : 0;
	}

	/**
	 * "3 hours ago" / "in 2 hours".
	 *
	 * @param int $ts Unix timestamp.
	 * @return string
	 */
	public static function ago( $ts ) {
		$ts = (int) $ts;
		if ( $ts <= 0 ) {
			return '';
		}
		$now = time();
		if ( $ts > $now + 60 ) {
			/* translators: %s: time span such as "2 hours" */
			return sprintf( __( 'in %s', 'wp-cyber-security' ), human_time_diff( $now, $ts ) );
		}
		if ( $now - $ts < 60 ) {
			return __( 'just now', 'wp-cyber-security' );
		}
		/* translators: %s: time span such as "2 hours" */
		return sprintf( __( '%s ago', 'wp-cyber-security' ), human_time_diff( $ts, $now ) );
	}

	/**
	 * Site-local date and time.
	 *
	 * @param int $ts Unix timestamp.
	 * @return string
	 */
	public static function datetime( $ts ) {
		$ts = (int) $ts;
		if ( $ts <= 0 ) {
			return '';
		}
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts );
	}

	/**
	 * Display name of a user, cached.
	 *
	 * @param int $user_id User id.
	 * @return string '' when the user does not exist.
	 */
	public static function user_name( $user_id ) {
		static $cache = array();
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return '';
		}
		if ( ! isset( $cache[ $user_id ] ) ) {
			$user              = get_userdata( $user_id );
			$cache[ $user_id ] = $user ? (string) $user->display_name : '';
		}
		return $cache[ $user_id ];
	}

	/**
	 * Status badge HTML for an item status.
	 *
	 * @param string $status Item status.
	 * @return string
	 */
	public static function status_badge( $status ) {
		$map = array(
			Store::STATUS_PENDING     => array( __( 'Waiting', 'wp-cyber-security' ), 'pending' ),
			Store::STATUS_APPROVED    => array( __( 'Approved', 'wp-cyber-security' ), 'ok' ),
			Store::STATUS_DENIED      => array( __( 'Denied', 'wp-cyber-security' ), 'muted' ),
			Store::STATUS_IGNORED     => array( __( 'Marked safe', 'wp-cyber-security' ), 'ok' ),
			Store::STATUS_QUARANTINED => array( __( 'Quarantined', 'wp-cyber-security' ), 'medium' ),
			Store::STATUS_RESTORED    => array( __( 'Restored', 'wp-cyber-security' ), 'info' ),
			Store::STATUS_DELETED     => array( __( 'Deleted', 'wp-cyber-security' ), 'muted' ),
			Store::STATUS_RESOLVED    => array( __( 'Resolved', 'wp-cyber-security' ), 'muted' ),
		);
		$entry = isset( $map[ $status ] ) ? $map[ $status ] : array( ucfirst( (string) $status ), 'muted' );
		return '<span class="wpcs-badge wpcs-badge--' . esc_attr( $entry[1] ) . '">' . esc_html( $entry[0] ) . '</span>';
	}

	/**
	 * Severity badge HTML.
	 *
	 * @param int $severity 0-3.
	 * @return string
	 */
	public static function severity_badge( $severity ) {
		$severity = max( 0, min( 3, (int) $severity ) );
		$classes  = array( 'info', 'medium', 'high', 'critical' );
		return '<span class="wpcs-badge wpcs-badge--' . esc_attr( $classes[ $severity ] ) . '">' . esc_html( Store::severity_label( $severity ) ) . '</span>';
	}

	/**
	 * Icon, tone and readable label for an activity log event.
	 *
	 * @param string $event Event machine name.
	 * @return array { icon, tone, label }
	 */
	public static function event_meta( $event ) {
		$event = (string) $event;
		$rules = array(
			array( array( 'decision_failed', '_failed', 'error' ), 'dismiss', 'bad' ),
			array( array( 'threat', 'malware', 'tamper' ), 'warning', 'bad' ),
			array( array( 'deleted', 'purged' ), 'trash', 'muted' ),
			array( array( 'denied', 'blocked' ), 'dismiss', 'muted' ),
			array( array( 'allowlist_removed' ), 'minus', 'muted' ),
			array( array( 'approved', 'ignored', 'allowlist', 'trusted' ), 'yes-alt', 'ok' ),
			array( array( 'quarantine' ), 'lock', 'medium' ),
			array( array( 'restored' ), 'undo', 'info' ),
			array( array( 'download' ), 'download', 'info' ),
			array( array( 'unlock' ), 'unlock', 'medium' ),
			array( array( 'lock', 'freeze' ), 'lock', 'info' ),
			array( array( 'upload' ), 'upload', 'pending' ),
			array( array( 'install', 'update' ), 'admin-plugins', 'pending' ),
			array( array( 'guard' ), 'shield', 'info' ),
			array( array( 'scan', 'baseline' ), 'search', 'info' ),
			array( array( 'notif', 'email', 'digest', 'webhook' ), 'email-alt', 'info' ),
			array( array( 'setting', 'wizard', 'setup' ), 'admin-generic', 'info' ),
			array( array( 'file' ), 'media-code', 'pending' ),
		);
		$icon = 'info-outline';
		$tone = 'info';
		foreach ( $rules as $rule ) {
			foreach ( $rule[0] as $needle ) {
				if ( false !== strpos( $event, $needle ) ) {
					$icon = $rule[1];
					$tone = $rule[2];
					break 2;
				}
			}
		}
		$label = ucfirst( trim( str_replace( array( '_', '-' ), ' ', $event ) ) );
		return array(
			'icon'  => $icon,
			'tone'  => $tone,
			'label' => '' !== $label ? $label : __( 'Event', 'wp-cyber-security' ),
		);
	}

	/* ------------------------------------------------------------------ */
	/* Activation redirect                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * Opens the setup wizard once right after activation.
	 */
	public function maybe_redirect() {
		if ( ! get_option( Installer::REDIRECT_OPTION ) ) {
			return;
		}
		if ( wp_doing_ajax() || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'IFRAME_REQUEST' ) && IFRAME_REQUEST ) ) {
			return; // Keep the flag for the next normal page load.
		}
		global $pagenow;
		if ( 'admin-post.php' === $pagenow || ! self::can() ) {
			return;
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'GET' !== $method ) {
			return;
		}

		delete_option( Installer::REDIRECT_OPTION );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only flag set by WordPress.
		if ( is_network_admin() || isset( $_GET['activate-multi'] ) ) {
			return;
		}
		if ( self::setting( 'wizard_completed', false ) || self::PAGE_WIZARD === self::current_page() ) {
			return;
		}
		wp_safe_redirect( self::page_url( self::PAGE_WIZARD ) );
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Notices                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Setup and pending-approval notices on screens outside the plugin.
	 */
	public function notices() {
		if ( ! self::can() || self::is_plugin_page() || is_network_admin() ) {
			return;
		}
		$user_id = get_current_user_id();

		if ( ! self::setting( 'wizard_completed', false ) ) {
			$until = (int) get_user_meta( $user_id, self::META_DISMISS_SETUP, true );
			if ( $until < time() ) {
				$this->print_setup_notice();
			}
		}

		$counts = self::counts();
		$total  = $counts['pending'] + $counts['threats'];
		if ( $total > 0 ) {
			$newest    = self::newest_open_item_id();
			$dismissed = (int) get_user_meta( $user_id, self::META_DISMISS_PENDING, true );
			if ( $newest > $dismissed ) {
				$this->print_pending_notice( $counts );
			}
		}
	}

	/**
	 * "Finish setting up" notice.
	 */
	private function print_setup_notice() {
		?>
		<div class="notice notice-info wpcs-admin-notice">
			<p>
				<strong><?php esc_html_e( 'Finish setting up WP Cyber Security', 'wp-cyber-security' ); ?></strong><br>
				<?php esc_html_e( 'The setup wizard picks a protection level, records a trusted baseline of your files and sets up alerts. It takes about three minutes.', 'wp-cyber-security' ); ?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( self::page_url( self::PAGE_WIZARD ) ); ?>"><?php esc_html_e( 'Start the setup wizard', 'wp-cyber-security' ); ?></a>
				<a class="button-link" style="margin-left:8px" href="<?php echo esc_url( self::dismiss_url( 'setup' ) ); ?>"><?php esc_html_e( 'Remind me in 3 days', 'wp-cyber-security' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * "N items are waiting for your approval" notice.
	 *
	 * @param array $counts Counts.
	 */
	private function print_pending_notice( array $counts ) {
		$lines = array();
		if ( $counts['pending'] > 0 ) {
			$lines[] = sprintf(
				/* translators: %s: number of items */
				_n( '%s upload, install or file is waiting for your approval.', '%s uploads, installs or files are waiting for your approval.', $counts['pending'], 'wp-cyber-security' ),
				number_format_i18n( $counts['pending'] )
			);
		}
		if ( $counts['threats'] > 0 ) {
			$lines[] = sprintf(
				/* translators: %s: number of threats */
				_n( '%s possible threat needs your attention.', '%s possible threats need your attention.', $counts['threats'], 'wp-cyber-security' ),
				number_format_i18n( $counts['threats'] )
			);
		}
		$tab   = $counts['pending'] > 0 ? 'pending' : 'threats';
		$class = $counts['threats'] > 0 ? 'notice-error' : 'notice-warning';
		?>
		<div class="notice <?php echo esc_attr( $class ); ?> wpcs-admin-notice">
			<p>
				<strong><?php esc_html_e( 'WP Cyber Security:', 'wp-cyber-security' ); ?></strong>
				<?php echo esc_html( implode( ' ', $lines ) ); ?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( self::page_url( self::PAGE_REPORTS, array( 'tab' => $tab ) ) ); ?>"><?php esc_html_e( 'Review now', 'wp-cyber-security' ); ?></a>
				<a class="button-link" style="margin-left:8px" href="<?php echo esc_url( self::dismiss_url( 'pending' ) ); ?>"><?php esc_html_e( 'Hide until something new arrives', 'wp-cyber-security' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * @param string $which setup | pending.
	 * @return string
	 */
	private static function dismiss_url( $which ) {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => 'wpcybersec_dismiss_notice',
					'notice' => $which,
				),
				admin_url( 'admin-post.php' )
			),
			'wpcybersec_dismiss_' . $which
		);
	}

	/**
	 * Highest id among open items (used to re-show a dismissed notice when new items arrive).
	 *
	 * @return int
	 */
	private static function newest_open_item_id() {
		$result = self::call(
			'store',
			'items_query',
			array(
				array(
					'type'     => array( Store::TYPE_UPLOAD, Store::TYPE_INSTALL, Store::TYPE_FILE, Store::TYPE_THREAT, Store::TYPE_USER ),
					'status'   => Store::STATUS_PENDING,
					'orderby'  => 'id',
					'order'    => 'DESC',
					'per_page' => 1,
				),
			),
			array()
		);
		return ! empty( $result['rows'][0]['id'] ) ? (int) $result['rows'][0]['id'] : 0;
	}

	/* ------------------------------------------------------------------ */
	/* Admin bar                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * @param \WP_Admin_Bar $bar Admin bar.
	 */
	public function admin_bar( $bar ) {
		if ( ! is_object( $bar ) || ! is_admin_bar_showing() || ! self::can() ) {
			return;
		}
		$counts = self::counts();
		$total  = $counts['pending'] + $counts['threats'];
		if ( $total < 1 ) {
			return;
		}
		$title = '<span class="ab-icon" aria-hidden="true"></span>'
			. '<span class="ab-label">' . esc_html__( 'Cyber Security', 'wp-cyber-security' ) . '</span>'
			. '<span class="wpcs-ab-count" aria-hidden="true">' . esc_html( number_format_i18n( $total ) ) . '</span>'
			. '<span class="screen-reader-text">' . esc_html(
				sprintf(
					/* translators: %s: number of items */
					_n( '%s item needs your review', '%s items need your review', $total, 'wp-cyber-security' ),
					number_format_i18n( $total )
				)
			) . '</span>';

		$bar->add_node(
			array(
				'id'    => 'wpcybersec',
				'title' => $title,
				'href'  => self::page_url( self::PAGE_REPORTS, array( 'tab' => $counts['pending'] > 0 ? 'pending' : 'threats' ) ),
				'meta'  => array( 'class' => $counts['threats'] > 0 ? 'wpcs-ab-threats' : '' ),
			)
		);
		if ( $counts['pending'] > 0 ) {
			$bar->add_node(
				array(
					'parent' => 'wpcybersec',
					'id'     => 'wpcybersec-pending',
					'title'  => esc_html(
						sprintf(
							/* translators: %s: number of items */
							_n( '%s waiting for approval', '%s waiting for approval', $counts['pending'], 'wp-cyber-security' ),
							number_format_i18n( $counts['pending'] )
						)
					),
					'href'   => self::page_url( self::PAGE_REPORTS, array( 'tab' => 'pending' ) ),
				)
			);
		}
		if ( $counts['threats'] > 0 ) {
			$bar->add_node(
				array(
					'parent' => 'wpcybersec',
					'id'     => 'wpcybersec-threats',
					'title'  => esc_html(
						sprintf(
							/* translators: %s: number of threats */
							_n( '%s possible threat', '%s possible threats', $counts['threats'], 'wp-cyber-security' ),
							number_format_i18n( $counts['threats'] )
						)
					),
					'href'   => self::page_url( self::PAGE_REPORTS, array( 'tab' => 'threats' ) ),
				)
			);
		}
		$bar->add_node(
			array(
				'parent' => 'wpcybersec',
				'id'     => 'wpcybersec-dashboard',
				'title'  => esc_html__( 'Security dashboard', 'wp-cyber-security' ),
				'href'   => self::page_url( self::PAGE_DASHBOARD ),
			)
		);
	}

	/**
	 * Small inline style for the admin bar node (front end and admin).
	 */
	public function admin_bar_style() {
		if ( ! is_admin_bar_showing() || ! self::can() || ! wp_style_is( 'admin-bar', 'registered' ) ) {
			return;
		}
		$counts = self::counts();
		if ( $counts['pending'] + $counts['threats'] < 1 ) {
			return;
		}
		$css = '#wpadminbar #wp-admin-bar-wpcybersec .ab-icon:before{content:"\f332";top:2px}'
			. '#wpadminbar #wp-admin-bar-wpcybersec .wpcs-ab-count{display:inline-block;min-width:18px;height:18px;margin-left:6px;padding:0 5px;border-radius:9px;background:#d63638;color:#fff;font-size:11px;line-height:18px;text-align:center;vertical-align:middle;box-sizing:border-box}'
			. '#wpadminbar #wp-admin-bar-wpcybersec:not(.wpcs-ab-threats) .wpcs-ab-count{background:#dba617;color:#1d2327}'
			. '@media screen and (max-width:782px){#wpadminbar #wp-admin-bar-wpcybersec{display:block}#wpadminbar #wp-admin-bar-wpcybersec .ab-label{display:none}#wpadminbar #wp-admin-bar-wpcybersec .ab-icon:before{top:0}}';
		wp_add_inline_style( 'admin-bar', $css );
	}

	/* ------------------------------------------------------------------ */
	/* Plugins screen                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * @param array $links Action links.
	 * @return array
	 */
	public function action_links( $links ) {
		if ( ! self::can() ) {
			return $links;
		}
		$own = array(
			'wpcybersec-settings' => '<a href="' . esc_url( self::page_url( self::PAGE_SETTINGS ) ) . '">' . esc_html__( 'Settings', 'wp-cyber-security' ) . '</a>',
			'wpcybersec-setup'    => '<a href="' . esc_url( self::page_url( self::PAGE_WIZARD ) ) . '">' . esc_html__( 'Setup', 'wp-cyber-security' ) . '</a>',
			'wpcybersec-reports'  => '<a href="' . esc_url( self::page_url( self::PAGE_REPORTS ) ) . '">' . esc_html__( 'Reports', 'wp-cyber-security' ) . '</a>',
		);
		return array_merge( $own, (array) $links );
	}

	/**
	 * Result args stripped from the address bar after display.
	 *
	 * @param array $args Args.
	 * @return array
	 */
	public function removable_query_args( $args ) {
		return array_merge( (array) $args, array( 'wpcs_msg', 'wpcs_done', 'wpcs_failed' ) );
	}

	/* ------------------------------------------------------------------ */
	/* admin-post handlers                                                 */
	/* ------------------------------------------------------------------ */

	/**
	 * Common capability gate for handlers.
	 */
	private function require_cap() {
		if ( ! self::can() ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'wp-cyber-security' ), esc_html__( 'Forbidden', 'wp-cyber-security' ), array( 'response' => 403, 'back_link' => true ) );
		}
	}

	/**
	 * Streams a held (quarantined) copy so an administrator can inspect it.
	 */
	public function handle_download() {
		$this->require_cap();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified right below.
		$id = isset( $_GET['id'] ) ? absint( wp_unslash( $_GET['id'] ) ) : 0;
		check_admin_referer( 'wpcybersec_download_' . $id );

		$item = $id ? self::call( 'store', 'item_get', array( $id ) ) : null;
		if ( ! is_array( $item ) || '' === (string) $item['quarantine_path'] ) {
			wp_die( esc_html__( 'This file is no longer held, so there is nothing to download.', 'wp-cyber-security' ), esc_html__( 'Not found', 'wp-cyber-security' ), array( 'response' => 404, 'back_link' => true ) );
		}
		$quarantine = self::service( 'quarantine' );
		if ( ! $quarantine || ! method_exists( $quarantine, 'stream' ) ) {
			wp_die( esc_html__( 'Quarantine storage is not available.', 'wp-cyber-security' ), '', array( 'response' => 500, 'back_link' => true ) );
		}
		self::call(
			'logger',
			'log',
			array(
				'item_downloaded',
				/* translators: %s: file name or path */
				sprintf( __( 'Downloaded the held copy of %s for inspection.', 'wp-cyber-security' ), $item['path'] ),
				array( 'item_id' => (int) $item['id'] ),
			)
		);
		// Validates that the path is inside the quarantine folder, sends the file and exits.
		$quarantine->stream( $item );
		exit;
	}

	/**
	 * Removes one allowlist entry.
	 */
	public function handle_allowlist_remove() {
		$this->require_cap();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified right below.
		$id = isset( $_GET['entry'] ) ? absint( wp_unslash( $_GET['entry'] ) ) : 0;
		check_admin_referer( 'wpcybersec_allowlist_remove_' . $id );

		$removed = $id ? (bool) self::call( 'allowlist', 'remove', array( $id ), false ) : false;
		$this->redirect_back(
			self::page_url( self::PAGE_REPORTS, array( 'tab' => 'allowlist' ) ),
			array( 'wpcs_msg' => $removed ? 'allowlist_removed' : 'allowlist_missing' )
		);
	}

	/**
	 * Non-JS fallback for the reports table: bulk form and single action buttons.
	 */
	public function handle_reports_bulk() {
		$this->require_cap();
		check_admin_referer( 'wpcybersec_reports_bulk' );

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified above.
		$action = '';
		$ids    = array();
		$single = isset( $_POST['wpcs_single'] ) ? sanitize_text_field( wp_unslash( $_POST['wpcs_single'] ) ) : '';
		if ( '' !== $single && preg_match( '/^([a-z]+):(\d+)$/', $single, $m ) ) {
			$action = $m[1];
			$ids    = array( (int) $m[2] );
		} else {
			$action = isset( $_POST['bulk_action'] ) ? sanitize_key( wp_unslash( $_POST['bulk_action'] ) ) : '';
			$ids    = isset( $_POST['ids'] ) ? array_map( 'absint', (array) wp_unslash( $_POST['ids'] ) ) : array();
		}
		$tab = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : 'pending';
		// phpcs:enable

		$ids      = array_values( array_unique( array_filter( $ids ) ) );
		$fallback = self::page_url( self::PAGE_REPORTS, array( 'tab' => $tab ) );

		if ( ! in_array( $action, Decisions::ACTIONS, true ) ) {
			$this->redirect_back( $fallback, array( 'wpcs_msg' => 'no_action' ) );
		}
		if ( ! $ids ) {
			$this->redirect_back( $fallback, array( 'wpcs_msg' => 'no_items' ) );
		}

		$result = self::call( 'decisions', 'bulk', array( $action, $ids ), null );
		if ( ! is_array( $result ) ) {
			$this->redirect_back( $fallback, array( 'wpcs_msg' => 'failed' ) );
		}
		$errors = isset( $result['errors'] ) ? array_slice( array_map( 'strval', (array) $result['errors'] ), 0, 20 ) : array();
		if ( $errors ) {
			set_transient( 'wpcybersec_bulk_errors_' . get_current_user_id(), $errors, 5 * MINUTE_IN_SECONDS );
		}
		$this->redirect_back(
			$fallback,
			array(
				'wpcs_msg'    => 'bulk',
				'wpcs_done'   => isset( $result['done'] ) ? (int) $result['done'] : 0,
				'wpcs_failed' => count( $errors ),
			)
		);
	}

	/**
	 * Hides a notice: setup for 3 days, pending until a newer item arrives.
	 */
	public function handle_dismiss_notice() {
		$this->require_cap();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified right below.
		$which = isset( $_GET['notice'] ) ? sanitize_key( wp_unslash( $_GET['notice'] ) ) : '';
		check_admin_referer( 'wpcybersec_dismiss_' . $which );

		$user_id = get_current_user_id();
		if ( 'setup' === $which ) {
			update_user_meta( $user_id, self::META_DISMISS_SETUP, time() + 3 * DAY_IN_SECONDS );
		} elseif ( 'pending' === $which ) {
			update_user_meta( $user_id, self::META_DISMISS_PENDING, self::newest_open_item_id() );
		}
		$this->redirect_back( admin_url(), array() );
	}

	/**
	 * Redirects to the referring admin page (or $fallback) with result args, then exits.
	 *
	 * @param string $fallback URL used when there is no valid referer.
	 * @param array  $args     Query args to add.
	 */
	private function redirect_back( $fallback, array $args ) {
		$target     = (string) wp_get_referer();
		$admin_path = (string) wp_parse_url( admin_url(), PHP_URL_PATH );
		$is_admin   = '' !== $target && ( 0 === strpos( $target, admin_url() ) || ( '' !== $admin_path && 0 === strpos( $target, $admin_path ) ) );
		if ( ! $is_admin || false !== strpos( $target, 'admin-post.php' ) ) {
			$target = $fallback;
		}
		$target = remove_query_arg( array( 'wpcs_msg', 'wpcs_done', 'wpcs_failed' ), $target );
		if ( $args ) {
			$target = add_query_arg( array_map( 'rawurlencode', array_map( 'strval', $args ) ), $target );
		}
		wp_safe_redirect( $target );
		exit;
	}
}
