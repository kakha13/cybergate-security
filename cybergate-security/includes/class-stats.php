<?php
/**
 * Opt-in install statistics sent to the developer (Qartvelo Company).
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Off by default. Nothing is sent before an administrator turns on
 * "share_stats" (setup wizard, Alerts step, or Settings > General), and
 * nothing at all while the constant WPCYBERSEC_DISABLE_STATS is true.
 *
 * Events: opt_in (when switched on, at once), heartbeat (weekly cron event on
 * the main site), deactivate, uninstall (uninstall.php) and opt_out (one last
 * message when switched off). Never on a page view: the weekly event runs in
 * cron, the others in the request that changed the setting or the plugin state.
 *
 * Every body is JSON, signed with an HMAC-SHA256 key that is created at opt
 * in and sent once in the opt_in event (header X-CGS-Signature), so the
 * server can tell that later events come from the same install. The install
 * id and the key are regenerated when the site address changes, so a copied
 * site is a new install instead of merging with the original.
 *
 * Never sent: email addresses, user names, file names or paths, visitor IP
 * addresses, keys or passwords, or any content of the site.
 */
class Stats {

	/** Weekly cron event (main site). */
	const HOOK = 'wpcybersec_stats_heartbeat';

	/** Network option { id, secret, site, registered }; not autoloaded. */
	const IDENTITY_OPTION = 'wpcybersec_stats_identity';

	/** Network option { at, event, ok (bool|null), code, error }; not autoloaded. */
	const LAST_OPTION = 'wpcybersec_stats_last';

	/** Endpoint unless WPCYBERSEC_STATS_URL or the wpcybersec_stats_url filter says otherwise. */
	const DEFAULT_URL = 'https://qartvelo.com/api/cybergate-security/stats';

	/** What is sent and why, in full. */
	const PRIVACY_URL = 'https://qartvelo.com/cybergate-security/docs/privacy-and-external-services';

	/** Seconds per request. */
	const TIMEOUT = 5;

	/** Events the server accepts. */
	const EVENTS = array( 'opt_in', 'heartbeat', 'deactivate', 'uninstall', 'opt_out' );

	/**
	 * Nothing heavy here; see register().
	 */
	public function __construct() {}

	/**
	 * Hooks. Keeping the schedule in shape (on init, like the scan schedule,
	 * so a reactivation from WP-CLI is picked up too) reads only the
	 * autoloaded cron and settings options: pages cost no query.
	 */
	public function register() {
		add_action( self::HOOK, array( $this, 'heartbeat' ) );
		add_action( 'wpcybersec_settings_updated', array( $this, 'settings_changed' ), 20, 2 );
		add_action( 'init', array( $this, 'schedule' ), 30 );
	}

	/* ------------------------------------------------------------------ */
	/* State                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * @return bool True when WPCYBERSEC_DISABLE_STATS turns statistics off for good.
	 */
	public static function disabled_by_constant() {
		return defined( 'WPCYBERSEC_DISABLE_STATS' ) && WPCYBERSEC_DISABLE_STATS;
	}

	/**
	 * Whether statistics may be sent: opted in, and not disabled by the constant.
	 *
	 * @param Settings|null $settings Settings (the service, else a fresh reader).
	 * @return bool
	 */
	public static function enabled( $settings = null ) {
		if ( self::disabled_by_constant() ) {
			return false;
		}
		$settings = $settings instanceof Settings ? $settings : self::settings();
		return (bool) $settings->get( 'share_stats', false );
	}

	/**
	 * @return Settings The service, or a reader that works before boot (deactivation, uninstall).
	 */
	private static function settings() {
		if ( function_exists( 'wpcybersec' ) && wpcybersec()->settings instanceof Settings ) {
			return wpcybersec()->settings;
		}
		return new Settings();
	}

	/**
	 * @return string Endpoint URL ('' when the filter returned nothing usable).
	 */
	public static function endpoint() {
		$url = ( defined( 'WPCYBERSEC_STATS_URL' ) && is_string( WPCYBERSEC_STATS_URL ) && '' !== WPCYBERSEC_STATS_URL ) ? WPCYBERSEC_STATS_URL : self::DEFAULT_URL;

		/**
		 * Address the opt-in statistics are posted to.
		 *
		 * @param string $url Endpoint URL.
		 */
		$url = (string) apply_filters( 'wpcybersec_stats_url', $url );
		return esc_url_raw( $url, array( 'https', 'http' ) );
	}

	/**
	 * Result of the last message, for the "Last sent" line.
	 *
	 * @return array|null { at, event, ok (bool|null when no reply was awaited), code, error }
	 */
	public static function last() {
		$last = Network::get_option( self::LAST_OPTION, array() );
		if ( ! is_array( $last ) || empty( $last['at'] ) ) {
			return null;
		}
		return array(
			'at'    => (int) $last['at'],
			'event' => isset( $last['event'] ) ? (string) $last['event'] : '',
			'ok'    => array_key_exists( 'ok', $last ) && null !== $last['ok'] ? (bool) $last['ok'] : null,
			'code'  => isset( $last['code'] ) ? (int) $last['code'] : 0,
			'error' => isset( $last['error'] ) ? (string) $last['error'] : '',
		);
	}

	/**
	 * The site address without the scheme, so http/https switches are not a new site.
	 *
	 * @return string
	 */
	private static function site_key() {
		$url = strtolower( (string) Network::home_url( '/' ) );
		return untrailingslashit( (string) preg_replace( '#^[a-z]+://#', '', $url ) );
	}

	/**
	 * Install id and signing key, created on first use and created again when
	 * the site address changed (a copy of the site is a new install).
	 *
	 * @return array { id, secret, site, registered }
	 */
	private function identity() {
		$saved = Network::get_option( self::IDENTITY_OPTION, array() );
		$site  = self::site_key();
		if ( is_array( $saved ) && ! empty( $saved['id'] ) && ! empty( $saved['secret'] ) && isset( $saved['site'] ) && $site === $saved['site'] ) {
			return array(
				'id'         => (string) $saved['id'],
				'secret'     => (string) $saved['secret'],
				'site'       => $site,
				'registered' => ! empty( $saved['registered'] ),
			);
		}
		$identity = array(
			'id'         => wp_generate_uuid4(),
			'secret'     => self::new_secret(),
			'site'       => $site,
			'registered' => false,
		);
		Network::update_option( self::IDENTITY_OPTION, $identity, false );
		return $identity;
	}

	/**
	 * @return string 64 hex characters.
	 */
	private static function new_secret() {
		try {
			return bin2hex( random_bytes( 32 ) );
		} catch ( \Throwable $e ) {
			unset( $e );
			return hash( 'sha256', wp_generate_password( 64, true, true ) . microtime() );
		}
	}

	/**
	 * Remembers that the server knows this install (after an accepted opt_in),
	 * or forgets it (the server answered "unknown install").
	 *
	 * @param bool $registered State.
	 */
	private function set_registered( $registered ) {
		$identity               = $this->identity();
		$identity['registered'] = (bool) $registered;
		Network::update_option( self::IDENTITY_OPTION, $identity, false );
	}

	/* ------------------------------------------------------------------ */
	/* Events                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Switched on: opt_in at once. Switched off: one last opt_out, so the
	 * server marks the install inactive.
	 *
	 * @param array $new New settings.
	 * @param array $old Previous settings.
	 */
	public function settings_changed( $new, $old ) {
		$was = ! empty( $old['share_stats'] );
		$now = ! empty( $new['share_stats'] );
		if ( $was === $now ) {
			return;
		}
		if ( self::disabled_by_constant() ) {
			$this->schedule();
			return;
		}
		if ( $now ) {
			$this->send( 'opt_in' );
		} else {
			$this->send( 'opt_out', true, true );
		}
		$this->schedule();
	}

	/**
	 * Keeps the weekly event in line with the setting (main site only).
	 */
	public function schedule() {
		if ( ! Network::is_main() ) {
			return; // Multisite: the plugin's cron events live on the main site.
		}
		$next = Network::next_scheduled( self::HOOK );
		if ( ! self::enabled() ) {
			if ( $next ) {
				Network::clear_hook( self::HOOK );
			}
			return;
		}
		if ( $next ) {
			return;
		}
		// After an opt in or a recent check-in the next one is due a week later;
		// after a reactivation (the event was cleared) the server hears soon.
		$last  = self::last();
		$first = time() + 10 * MINUTE_IN_SECONDS;
		if ( $last && $last['ok'] && in_array( $last['event'], array( 'opt_in', 'heartbeat' ), true ) && $last['at'] > time() - 6 * DAY_IN_SECONDS ) {
			$first = $last['at'] + WEEK_IN_SECONDS;
		}
		Network::schedule_event( $first, 'weekly', self::HOOK );
	}

	/**
	 * Weekly cron event. Registers again when the server does not know the
	 * install (a first opt_in that never arrived, or a new site address).
	 */
	public function heartbeat() {
		if ( ! Network::is_main() ) {
			return;
		}
		if ( ! self::enabled() ) {
			Network::clear_hook( self::HOOK );
			return;
		}
		$identity = $this->identity();
		if ( ! $identity['registered'] ) {
			$this->send( 'opt_in' );
			return;
		}
		$result = $this->send( 'heartbeat' );
		if ( 404 === $result['code'] ) {
			$this->send( 'opt_in' );
		}
	}

	/**
	 * Deactivation (Installer::deactivate()): does not wait for the reply.
	 */
	public static function on_deactivate() {
		if ( self::enabled() ) {
			( new self() )->send( 'deactivate', false );
		}
	}

	/**
	 * uninstall.php, before the plugin's options are deleted: does not wait for the reply.
	 */
	public static function on_uninstall() {
		if ( self::enabled() ) {
			( new self() )->send( 'uninstall', false );
		}
	}

	/**
	 * Posts one event.
	 *
	 * @param string $event    One of EVENTS.
	 * @param bool   $blocking Wait for the reply (deactivate and uninstall do not).
	 * @param bool   $force    Send although share_stats is off (the opt_out message).
	 * @return array { ok (bool|null), code, error }
	 */
	public function send( $event, $blocking = true, $force = false ) {
		$none = array(
			'ok'    => false,
			'code'  => 0,
			'error' => '',
		);
		if ( ! in_array( $event, self::EVENTS, true ) || self::disabled_by_constant() || ( ! $force && ! self::enabled() ) ) {
			return $none;
		}
		$url = self::endpoint();
		if ( '' === $url ) {
			return $none;
		}
		$identity = $this->identity();
		$payload  = $this->payload( $event, $identity );
		$body     = wp_json_encode( $payload );
		if ( ! is_string( $body ) ) {
			return $none;
		}
		$response = wp_remote_post(
			$url,
			array(
				'timeout'     => self::TIMEOUT,
				'blocking'    => (bool) $blocking,
				'redirection' => 0,
				'user-agent'  => 'CyberGate-Security/' . WPCYBERSEC_VERSION,
				'headers'     => array(
					'Content-Type'    => 'application/json',
					'Accept'          => 'application/json',
					'X-CGS-Signature' => hash_hmac( 'sha256', $body, $identity['secret'] ),
				),
				'body'        => $body,
			)
		);

		if ( ! $blocking ) {
			$result = array(
				'ok'    => is_wp_error( $response ) ? false : null,
				'code'  => 0,
				'error' => is_wp_error( $response ) ? $response->get_error_message() : '',
			);
		} elseif ( is_wp_error( $response ) ) {
			$result = array(
				'ok'    => false,
				'code'  => 0,
				'error' => $response->get_error_message(),
			);
		} else {
			$code   = (int) wp_remote_retrieve_response_code( $response );
			$result = array(
				'ok'    => $code >= 200 && $code < 300,
				'code'  => $code,
				/* translators: %d: HTTP status code */
				'error' => $code >= 200 && $code < 300 ? '' : sprintf( __( 'The server answered with HTTP status %d.', 'cybergate-security' ), $code ),
			);
		}

		if ( 'opt_in' === $event && $result['ok'] ) {
			$this->set_registered( true );
		} elseif ( 404 === $result['code'] ) {
			$this->set_registered( false );
		}
		Network::update_option(
			self::LAST_OPTION,
			array(
				'at'    => time(),
				'event' => $event,
				'ok'    => $result['ok'],
				'code'  => $result['code'],
				'error' => substr( sanitize_text_field( $result['error'] ), 0, 200 ),
			),
			false
		);
		return $result;
	}

	/* ------------------------------------------------------------------ */
	/* Payload                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * What one event sends. deactivate and uninstall send the short form (no
	 * settings, no counts); opt_out only says which install stops.
	 *
	 * @param string $event    Event.
	 * @param array  $identity identity().
	 * @return array
	 */
	public function payload( $event, array $identity ) {
		$data = array(
			'install_id'     => $identity['id'],
			'event'          => $event,
			'sent_at'        => time(),
			'plugin'         => 'cybergate-security',
			'plugin_version' => WPCYBERSEC_VERSION,
		);
		if ( 'opt_out' === $event ) {
			return $data;
		}
		if ( 'opt_in' === $event ) {
			$data['signing_secret'] = $identity['secret'];
		}
		$data = array_merge(
			$data,
			array(
				'site_url'    => (string) Network::home_url( '/' ),
				'site_name'   => substr( (string) Network::name(), 0, 200 ),
				'wp_version'  => (string) get_bloginfo( 'version' ),
				'php_version' => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '.' . PHP_RELEASE_VERSION,
				'db_version'  => (string) Network::get_option( Installer::DB_OPTION, '' ),
				'locale'      => (string) get_locale(),
				'multisite'   => is_multisite(),
				'sites_count' => is_multisite() && function_exists( 'get_blog_count' ) ? max( 1, (int) get_blog_count() ) : 1,
			)
		);
		if ( in_array( $event, array( 'deactivate', 'uninstall' ), true ) ) {
			return $data;
		}
		return array_merge( $data, $this->setup_details() );
	}

	/**
	 * Server, hosting panel, protection settings and rounded counts.
	 *
	 * @return array
	 */
	private function setup_details() {
		$plugin   = function_exists( 'wpcybersec' ) ? wpcybersec() : null;
		$settings = self::settings();

		$server = Sysadmin_Tools::server_type();
		$panel  = array(
			'id'   => '',
			'name' => '',
		);
		try {
			$hosting = $plugin && $plugin->hosting instanceof Hosting ? $plugin->hosting : new Hosting();
			$current = $hosting->current();
			$panel   = array(
				'id'   => isset( $current['id'] ) ? (string) $current['id'] : '',
				'name' => isset( $current['name'] ) ? (string) $current['name'] : '',
			);
			if ( 'unknown' === $server && ! empty( $current['web_server'] ) ) {
				$server = (string) $current['web_server']; // Cron from the command line has no SERVER_SOFTWARE.
			}
		} catch ( \Throwable $e ) {
			unset( $e );
		}

		$guard = false;
		try {
			if ( $plugin && $plugin->guard_manager instanceof Guard_Manager ) {
				$live  = $plugin->guard_manager->live_state();
				$guard = in_array( $live['state'], array( 'active', 'confirmed' ), true );
			}
		} catch ( \Throwable $e ) {
			unset( $e );
		}

		$files   = 0;
		$pending = 0;
		$threats = 0;
		$scan_at = 0;
		try {
			if ( $plugin && $plugin->store instanceof Store ) {
				$files   = (int) $plugin->store->manifest_count();
				$counts  = $plugin->store->counts();
				$pending = (int) $counts['pending'];
			}
			if ( $plugin && $plugin->scan_job instanceof Scan_Job ) {
				$scan    = $plugin->scan_job->last_result();
				$threats = isset( $scan['threats'] ) ? (int) $scan['threats'] : 0;
				$scan_at = isset( $scan['finished_at'] ) ? (int) $scan['finished_at'] : 0;
			}
		} catch ( \Throwable $e ) {
			unset( $e );
		}

		return array(
			'server_software'    => substr( sanitize_key( $server ), 0, 32 ),
			'hosting_panel'      => substr( sanitize_key( $panel['id'] ), 0, 64 ),
			'hosting_panel_name' => substr( sanitize_text_field( $panel['name'] ), 0, 100 ),
			'settings'           => array(
				'protection_level' => (string) $settings->get( 'protection_level', '' ),
				'upload_mode'      => (string) $settings->get( 'upload_mode', '' ),
				'install_mode'     => (string) $settings->get( 'install_mode', '' ),
				'file_mode'        => (string) $settings->get( 'file_mode', '' ),
				'clamav_enabled'   => (bool) $settings->get( 'clamav_enabled', false ),
				'maldet_installed' => '' !== Sysadmin_Tools::maldet_detect(),
				'guard_active'     => $guard,
			),
			'stats'              => array(
				'files_monitored'   => self::round_count( $files ),
				'pending_items'     => self::round_count( $pending ),
				'threats_last_scan' => self::round_count( $threats ),
				'last_scan_at'      => $scan_at > 0 ? $scan_at : null,
			),
		);
	}

	/**
	 * Rounds a count to two significant digits (below 10: exact), so the
	 * numbers describe the size of a site without being a fingerprint.
	 *
	 * @param int $n Count.
	 * @return int
	 */
	public static function round_count( $n ) {
		$n = max( 0, (int) $n );
		if ( $n < 10 ) {
			return $n;
		}
		$step = (int) pow( 10, (int) floor( log10( $n ) ) - 1 );
		return (int) ( round( $n / $step ) * $step );
	}

	/**
	 * Every field the statistics contain, for the "What is sent" list.
	 *
	 * @return string[]
	 */
	public static function fields() {
		return array(
			__( 'A random install ID created when you opt in, and the event: opt in, weekly check-in, deactivation, uninstall or opt out.', 'cybergate-security' ),
			__( 'Your site address and site name (on multisite: the network address and name).', 'cybergate-security' ),
			__( 'Versions of CyberGate Security, WordPress and PHP, the plugin database version and the site language.', 'cybergate-security' ),
			__( 'Whether the site is a multisite network, and how many sites it has.', 'cybergate-security' ),
			__( 'The web server type (Apache, nginx, LiteSpeed) and the detected hosting panel.', 'cybergate-security' ),
			__( 'Protection settings: protection level and how uploads, plugin installs and new files are handled.', 'cybergate-security' ),
			__( 'Whether ClamAV scanning is on, Linux Malware Detect is installed and the early upload guard is active.', 'cybergate-security' ),
			__( 'Rounded counts: files monitored, items waiting for approval and threats found by the last scan, plus the time of the last scan.', 'cybergate-security' ),
			__( 'A signing key, sent once when you opt in, so the server can tell that later messages really come from this site.', 'cybergate-security' ),
		);
	}
}
