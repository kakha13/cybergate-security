<?php
/**
 * Shared admin assets.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Ajax;

defined( 'ABSPATH' ) || exit;

/**
 * Registers the shared handles. Pages call Assets::enqueue() and then enqueue
 * their own files with 'wpcybersec-base' / 'wpcybersec-core' as dependencies.
 *
 * Handles:
 *   style  wpcybersec-base   assets/css/base.css  (design tokens + components)
 *   script wpcybersec-core   assets/js/core.js    (window.WPCyberSec API)
 */
class Assets {

	/**
	 * Cache-busting version for an asset: plugin version plus the file's
	 * modification time, so browsers fetch a changed file right away.
	 *
	 * @param string $rel Path inside the plugin, e.g. assets/css/base.css.
	 * @return string
	 */
	public static function ver( $rel ) {
		$mtime = @filemtime( WPCYBERSEC_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return WPCYBERSEC_VERSION . ( $mtime ? '.' . $mtime : '' );
	}

	/**
	 * Registers handles (call on admin_enqueue_scripts).
	 */
	public static function register() {
		wp_register_style( 'wpcybersec-base', WPCYBERSEC_URL . 'assets/css/base.css', array( 'dashicons' ), Assets::ver( 'assets/css/base.css' ) );
		wp_register_script( 'wpcybersec-core', WPCYBERSEC_URL . 'assets/js/core.js', array(), Assets::ver( 'assets/js/core.js' ), true );
		wp_localize_script(
			'wpcybersec-core',
			'wpcybersecData',
			array(
				'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
				'nonce'    => wp_create_nonce( Ajax::NONCE ),
				'adminUrl' => admin_url(),
				'i18n'     => array(
					'error'          => __( 'Something went wrong.', 'cybergate-security' ),
					'copied'         => __( 'Copied', 'cybergate-security' ),
					'copy'           => __( 'Copy', 'cybergate-security' ),
					'confirm'        => __( 'Are you sure?', 'cybergate-security' ),
					'confirmDelete'  => __( 'Delete this file permanently? This cannot be undone.', 'cybergate-security' ),
					'scanning'       => __( 'Scanning', 'cybergate-security' ),
					'enumerating'    => __( 'Listing files', 'cybergate-security' ),
					'processing'     => __( 'Checking files', 'cybergate-security' ),
					'finishing'      => __( 'Finishing', 'cybergate-security' ),
					'done'           => __( 'Scan complete', 'cybergate-security' ),
					'failed'         => __( 'Scan failed', 'cybergate-security' ),
					'cancelled'      => __( 'Scan cancelled', 'cybergate-security' ),
					/* translators: 1: files checked so far, 2: files in total */
					'filesChecked'   => __( '%1$s of %2$s files checked', 'cybergate-security' ),
					/* translators: %s: number of files */
					'filesFound'     => __( '%s files found so far', 'cybergate-security' ),
					'approved'       => __( 'Approved', 'cybergate-security' ),
					'denied'         => __( 'Denied', 'cybergate-security' ),
					'ignored'        => __( 'Marked safe', 'cybergate-security' ),
					'quarantined'    => __( 'Quarantined', 'cybergate-security' ),
					'restored'       => __( 'Restored', 'cybergate-security' ),
					'resolved'       => __( 'Resolved', 'cybergate-security' ),
					'deleted'        => __( 'Deleted', 'cybergate-security' ),
				),
			)
		);
	}

	/**
	 * Enqueues the shared base style and core script.
	 */
	public static function enqueue() {
		if ( ! wp_style_is( 'wpcybersec-base', 'registered' ) ) {
			self::register();
		}
		wp_enqueue_style( 'wpcybersec-base' );
		wp_enqueue_script( 'wpcybersec-core' );
	}
}
