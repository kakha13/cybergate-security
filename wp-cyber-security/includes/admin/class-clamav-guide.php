<?php
/**
 * Step-by-step ClamAV install guide for Settings > Advanced > ClamAV.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity\Admin;

use WPCyberSecurity\Sysadmin_Tools;

defined( 'ABSPATH' ) || exit;

/**
 * Copy-and-paste install steps per server type. The section that matches this
 * server (from /etc/os-release or the PHP OS family) opens first.
 */
class Clamav_Guide {

	/**
	 * Server family: debian | rhel | macos | other.
	 *
	 * @return string
	 */
	public static function platform() {
		if ( 'Darwin' === PHP_OS_FAMILY ) {
			return 'macos';
		}
		if ( 'Linux' !== PHP_OS_FAMILY ) {
			return 'other';
		}
		$release = @is_readable( '/etc/os-release' ) ? (string) @file_get_contents( '/etc/os-release' ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$ids     = '';
		if ( preg_match_all( '/^(?:ID|ID_LIKE)="?([^"\n]+)"?/m', $release, $m ) ) {
			$ids = strtolower( implode( ' ', $m[1] ) );
		}
		if ( preg_match( '/\b(debian|ubuntu)\b/', $ids ) ) {
			return 'debian';
		}
		if ( preg_match( '/\b(rhel|centos|fedora|almalinux|rocky|cloudlinux|ol)\b/', $ids ) ) {
			return 'rhel';
		}
		return 'other';
	}

	/**
	 * Short status line and the one thing still missing.
	 *
	 * @param string $detected Detected binary ('' when none).
	 * @param bool   $exec     exec()/proc_open() available.
	 * @param bool   $daemon   clamd daemon reachable.
	 */
	private static function status( $detected, $exec, $daemon ) {
		if ( ! $exec ) {
			Settings_Page::notice( __( 'PHP is not allowed to run programs on this server (exec and proc_open are disabled), so the plugin cannot call ClamAV even when it is installed. Ask your host to allow proc_open for this site, or skip ClamAV: the plugin\'s own signatures and checksums keep working.', 'wp-cyber-security' ), 'warn' );
			return;
		}
		if ( '' === $detected ) {
			Settings_Page::notice( __( 'ClamAV is not installed on this server. Follow the steps for your server below, then press "Check again".', 'wp-cyber-security' ), 'info' );
			return;
		}
		if ( ! $daemon ) {
			Settings_Page::notice( __( 'ClamAV is installed, but its background service (clamd) is not running. Uploads can be scanned already; start the service (step 3 below) so whole-site scans can use it too.', 'wp-cyber-security' ), 'info' );
			return;
		}
		Settings_Page::notice( __( 'ClamAV and its background service are ready. Turn on "Also scan uploads with ClamAV" above and save.', 'wp-cyber-security' ), 'ok' );
	}

	/**
	 * Prints the guide.
	 *
	 * @param string $detected Detected binary path.
	 * @param bool   $exec     exec()/proc_open() available.
	 * @param bool   $daemon   clamd reachable.
	 */
	public static function render( $detected, $exec, $daemon ) {
		$platform = self::platform();
		$ready    = '' !== $detected && $exec && $daemon;

		echo '<div class="wpcs-clamav-guide">';
		self::status( $detected, $exec, $daemon );

		echo '<p class="wpcs-sub">' . esc_html__( 'What it adds: ClamAV recognises millions of known malicious files (web shells, phishing kits, infected uploads) that pattern checks can miss. What it does not do: it does not block attacks. Think of it as a second opinion that finds more.', 'wp-cyber-security' ) . '</p>';

		$guides = array(
			'debian' => array( __( 'Ubuntu or Debian server', 'wp-cyber-security' ), self::steps_debian() ),
			'rhel'   => array( __( 'AlmaLinux, Rocky, CentOS, RHEL or CloudLinux server', 'wp-cyber-security' ), self::steps_rhel() ),
			'shared' => array( __( 'Shared hosting (no root access)', 'wp-cyber-security' ), self::steps_shared() ),
			'macos'  => array( __( 'macOS (local development with Homebrew)', 'wp-cyber-security' ), self::steps_macos() ),
		);
		$open = 'other' === $platform ? 'shared' : $platform;

		echo '<div class="wpcs-guide-list">';
		foreach ( $guides as $id => $guide ) {
			$is_open = ! $ready && $id === $open;
			echo '<details class="wpcs-manual wpcs-guide"' . ( $is_open ? ' open' : '' ) . '>';
			echo '<summary>' . esc_html( $guide[0] );
			if ( $id === $platform ) {
				echo ' <span class="wpcs-badge wpcs-badge--info">' . esc_html__( 'This server', 'wp-cyber-security' ) . '</span>';
			}
			echo '</summary>';
			Settings_Page::render_steps( $guide[1] );
			echo '</details>';
		}
		echo '</div>';

		$url = Sysadmin_Tools::settings_url( 'advanced', array( 'recheck' => 1 ), 'wpcs-clamav' );
		echo '<p class="wpcs-guide-actions"><a class="button" href="' . esc_url( $url ) . '"><span class="dashicons dashicons-update" aria-hidden="true"></span>' . esc_html__( 'Check again', 'wp-cyber-security' ) . '</a></p>';
		echo '</div>';
	}

	/**
	 * Test step shared by the server guides. The test file comes from eicar.org,
	 * so the harmless test string never lives inside this plugin's own files.
	 *
	 * @param string $scanner Command to test with.
	 * @return array
	 */
	private static function test_step( $scanner ) {
		return array(
			'text' => __( 'Test it with the harmless EICAR test file every antivirus recognises. The last line should end with "FOUND":', 'wp-cyber-security' ),
			'code' => "curl -s -o /tmp/eicar.txt https://secure.eicar.org/eicar.com.txt\n" . $scanner . " /tmp/eicar.txt\nrm /tmp/eicar.txt",
		);
	}

	/**
	 * @return array[]
	 */
	private static function steps_debian() {
		return array(
			array(
				'text' => __( 'Connect to the server with SSH as root or a sudo user, and install ClamAV with its background service:', 'wp-cyber-security' ),
				'code' => "sudo apt-get update\nsudo apt-get install -y clamav clamav-daemon",
			),
			array(
				'text' => __( 'Download the virus database (takes a minute the first time):', 'wp-cyber-security' ),
				'code' => "sudo systemctl stop clamav-freshclam\nsudo freshclam\nsudo systemctl enable --now clamav-freshclam",
			),
			array(
				'text' => __( 'Start the background service so scans are fast, and start it on every boot:', 'wp-cyber-security' ),
				'code' => "sudo systemctl enable --now clamav-daemon\nsudo systemctl status clamav-daemon --no-pager",
			),
			self::test_step( 'clamdscan --fdpass' ),
			array( 'text' => __( 'Come back here, press "Check again", then turn on "Also scan uploads with ClamAV" and save. The database updates itself several times a day from now on.', 'wp-cyber-security' ) ),
		);
	}

	/**
	 * @return array[]
	 */
	private static function steps_rhel() {
		return array(
			array(
				'text' => __( 'Connect with SSH as root or a sudo user. ClamAV comes from the EPEL repository:', 'wp-cyber-security' ),
				'code' => "sudo dnf install -y epel-release\nsudo dnf install -y clamav clamav-update clamd",
			),
			array(
				'text' => __( 'Switch on the configuration files (they ship with an "Example" line that stops them from loading) and the local socket:', 'wp-cyber-security' ),
				'code' => "sudo sed -i 's/^Example/#Example/' /etc/freshclam.conf /etc/clamd.d/scan.conf\nsudo sed -i 's|^#LocalSocket .*|LocalSocket /run/clamd.scan/clamd.sock|' /etc/clamd.d/scan.conf",
			),
			array(
				'text' => __( 'Download the virus database and keep it updated:', 'wp-cyber-security' ),
				'code' => "sudo freshclam\nsudo systemctl enable --now clamav-freshclam",
			),
			array(
				'text' => __( 'Start the background service. With SELinux enforcing, also allow it to read website files:', 'wp-cyber-security' ),
				'code' => "sudo setsebool -P antivirus_can_scan_system 1\nsudo systemctl enable --now clamd@scan\nsudo systemctl status clamd@scan --no-pager",
			),
			self::test_step( 'clamdscan --fdpass' ),
			array( 'text' => __( 'Come back here, press "Check again", then turn on "Also scan uploads with ClamAV" and save.', 'wp-cyber-security' ) ),
		);
	}

	/**
	 * @return array[]
	 */
	private static function steps_shared() {
		$site = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		return array(
			array( 'text' => __( 'Without root access you cannot install ClamAV yourself. First look in your hosting control panel:', 'wp-cyber-security' ) ),
			array( 'text' => __( 'cPanel: Security > "Virus Scanner" (ClamAV), or "Imunify360" / "ImunifyAV". Plesk: "Imunify" or "Security Advisor". Run a full scan there; it covers what this plugin cannot.', 'wp-cyber-security' ) ),
			array(
				'text' => __( 'To let this plugin use ClamAV for every upload, send your host this request:', 'wp-cyber-security' ),
				/* translators: %s: site domain */
				'code' => sprintf( __( "Hello, please install ClamAV with the clamd service (clamdscan) on the server that hosts %s and keep its virus database updated with freshclam. My WordPress security plugin scans uploads with /usr/bin/clamdscan, so PHP needs to be allowed to run it (proc_open or exec enabled for my account). Thank you.", 'wp-cyber-security' ), $site ? $site : 'my site' ),
			),
			array( 'text' => __( 'When the host confirms, come back here and press "Check again".', 'wp-cyber-security' ) ),
		);
	}

	/**
	 * @return array[]
	 */
	private static function steps_macos() {
		return array(
			array(
				'text' => __( 'Install ClamAV with Homebrew:', 'wp-cyber-security' ),
				'code' => 'brew install clamav',
			),
			array(
				'text' => __( 'Create the configuration files from the samples:', 'wp-cyber-security' ),
				'code' => "cd \"\$(brew --prefix)/etc/clamav\"\ncp freshclam.conf.sample freshclam.conf && sed -i '' 's/^Example/#Example/' freshclam.conf\ncp clamd.conf.sample clamd.conf && sed -i '' -e 's/^Example/#Example/' -e 's|^#LocalSocket .*|LocalSocket /tmp/clamd.socket|' clamd.conf",
			),
			array(
				'text' => __( 'Download the virus database and start the background service:', 'wp-cyber-security' ),
				'code' => "freshclam\nclamd",
			),
			self::test_step( 'clamdscan --fdpass' ),
			array( 'text' => __( 'Come back here and press "Check again". On a Mac the service stops at restart; run "clamd" again after a reboot.', 'wp-cyber-security' ) ),
		);
	}
}
