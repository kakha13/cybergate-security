<?php
/**
 * File scanner: malware signatures, official checksums and optional ClamAV.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Stateless per file, but keeps per-request caches so verify() stays cheap:
 * the core checksum map and each plugin checksum map are loaded once per
 * request (from transients, or from wordpress.org at most every 12 hours).
 */
class Scanner {

	/** Transient prefixes (the rest is an md5, well under the 172 char limit). */
	const CORE_TRANSIENT    = 'wpcybersec_core_sums_';
	const PLUGIN_TRANSIENT  = 'wpcybersec_plugin_sums_';
	const OFFLINE_TRANSIENT = 'wpcybersec_sums_offline';

	const CACHE_TTL      = 12 * HOUR_IN_SECONDS;
	const MISS_TTL       = 6 * HOUR_IN_SECONDS;
	const NETWORK_ERR_TTL = HOUR_IN_SECONDS;

	/** @var array|false|null path => md5, false when unavailable, null before loading. */
	private $core_map = null;

	/** @var array|null plugin folder => version. */
	private $plugin_versions = null;

	/** @var array plugin folder => display name (filled with $plugin_versions). */
	private $plugin_names = array();

	/** @var array slug@version => array|false */
	private $plugin_maps = array();

	/** @var int Network failures in this request (circuit breaker). */
	private $fetch_failures = 0;

	/** @var string[]|null Usable ClamAV binaries, daemon client first. */
	private $clamav_bins = null;

	/** File in the plugin folder that lists the sha256 of every shipped file (bin/build-checksums.php). */
	const SELF_CHECKSUMS = 'checksums.json';

	/** @var array|false|null Own checksums: inner path => sha256, false when missing or unreadable. */
	private $self_map = null;

	/** @var string[]|null Plugin folder roots (as given and resolved), with trailing slash. */
	private $self_roots = null;

	/**
	 * Hooks.
	 */
	public function register() {
		// After an update the installed versions change; drop per-request caches
		// before Install_Gate re-baselines the updated folders.
		add_action( 'upgrader_process_complete', array( $this, 'reset_caches' ), 1 );
		add_action( 'wpcybersec_settings_updated', array( $this, 'reset_clamav' ) );
	}

	/**
	 * Drops per-request caches.
	 */
	public function reset_caches() {
		$this->core_map        = null;
		$this->plugin_versions = null;
		$this->plugin_names    = array();
		$this->plugin_maps     = array();
		$this->self_map        = null; // An update of this plugin ships a new checksums.json.
		if ( function_exists( 'wp_clean_plugins_cache' ) ) {
			wp_clean_plugins_cache( false );
		}
	}

	/**
	 * Forgets the detected ClamAV binary (after settings change).
	 */
	public function reset_clamav() {
		$this->clamav_bins = null;
	}

	/* ------------------------------------------------------------------ */
	/* Malware scanning                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Malware hits for a file on disk.
	 *
	 * @param string $abs Absolute path.
	 * @param string $rel Relative path (computed when empty).
	 * @return array[] Hits { sig, title, severity, line, snippet }.
	 */
	public function scan_file( $abs, $rel = '' ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs || ! @is_file( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return array();
		}
		if ( '' === $rel ) {
			$rel = Paths::rel( $abs );
		}
		$min  = $this->min_severity();
		$hits = Signatures::inspect_file( $abs, $rel, $min, $this->max_bytes() );

		// Custom upload folders (UPLOADS constant) are not under wp-content/uploads.
		if ( $this->in_custom_uploads( $abs ) && $this->is_php_name( $abs ) && 1 >= $min && ! $this->has_sig( $hits, 'path_php_in_uploads' ) && ! $this->is_harmless_stub( $abs ) ) {
			$hits[] = array(
				'sig'      => 'path_php_in_uploads',
				'title'    => __( 'PHP file inside the uploads folder', 'wp-cyber-security' ),
				'severity' => Store::SEV_MEDIUM,
				'line'     => 0,
				'snippet'  => Signatures::clean_snippet( $rel ),
			);
		}

		// ClamAV per file only through the daemon client (clamscan reloads its
		// database for every file, far too slow for a site scan), and only for
		// files that can run code.
		if ( $this->settings()->get( 'clamav_enabled', false ) && $this->clamav_daemon_available() ) {
			$kind = Signatures::kind_for( $abs );
			if ( Paths::is_executable( $abs ) || in_array( $kind, array( Signatures::KIND_PHP, Signatures::KIND_JS, Signatures::KIND_HTML ), true ) ) {
				$clam = $this->clamav_scan( $abs, true );
				if ( is_array( $clam ) ) {
					$hits = array_merge( $hits, $clam );
				}
			}
		}

		return Signatures::unique( $hits );
	}

	/**
	 * Hits for an incoming upload. Severity >= 2 means "malicious".
	 *
	 * @param string $tmp_path      Temporary file.
	 * @param string $original_name Name the visitor sent.
	 * @return array[] Hits.
	 */
	public function scan_upload( $tmp_path, $original_name ) {
		$name = (string) $original_name;
		$hits = $this->name_hits( $name );

		$tmp_path = (string) $tmp_path;
		if ( '' === $tmp_path || ! @is_file( $tmp_path ) || ! @is_readable( $tmp_path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return $hits;
		}

		$min   = $this->min_severity();
		$max   = $this->max_bytes();
		$size  = (int) @filesize( $tmp_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$kind  = Signatures::kind_for( $name );
		$clean = basename( str_replace( array( '\\', "\0" ), array( '/', '' ), $name ) );
		$hits  = array_merge( $hits, Signatures::inspect_file( $tmp_path, '', $min, $max, '' !== $clean ? $clean : 'upload.bin' ) );

		$head = $size > 0 ? (string) @file_get_contents( $tmp_path, false, null, 0, 4096 ) : ''; // phpcs:ignore

		// PHP disguised as something else (a ".pdf" or ".zip" that is really a script).
		if ( Signatures::KIND_PHP !== $kind && Signatures::looks_like_php( $head ) && ! $this->has_sig( $hits, 'image_php_code' ) ) {
			$hits[] = array(
				'sig'      => 'upload_php_disguised',
				'title'    => __( 'PHP script disguised as another file type', 'wp-cyber-security' ),
				'severity' => Store::SEV_HIGH,
				'line'     => 1,
				'snippet'  => Signatures::clean_snippet( substr( $head, 0, 120 ) ),
			);
			if ( $size <= $max ) {
				$hits = array_merge( $hits, Signatures::match( (string) @file_get_contents( $tmp_path, false, null, 0, $max ), Signatures::KIND_PHP, $min ) ); // phpcs:ignore
			}
		}

		// Images: look for PHP anywhere in the file, not only head and tail. The
		// short echo tag (for example "<?=" followed by `$_GET[0]`) runs code too; it
		// only counts when code follows it, because the three bytes "<?=" turn up
		// by chance in large images.
		if ( Signatures::KIND_IMAGE === $kind && ! $this->has_sig( $hits, 'image_php_code' ) && $size <= $max ) {
			$tag = '';
			if ( $this->file_contains( $tmp_path, '<?php' ) ) {
				$tag = '<?php';
			} elseif ( $this->file_matches( $tmp_path, '~<\?=\s{0,8}+(?:[`$@]|[a-z_][a-z0-9_]{0,40}+\s{0,8}+\()~i' ) ) {
				$tag = '<?=';
			}
			if ( '' !== $tag ) {
				$hits[] = array(
					'sig'      => 'image_php_code',
					'title'    => __( 'PHP code hidden in an image file', 'wp-cyber-security' ),
					'severity' => Store::SEV_CRITICAL,
					'line'     => 0,
					'snippet'  => $tag,
				);
			}
		}

		// SVG can carry scripts that run in the admin's browser.
		if ( 'svg' === Paths::ext( $clean ) && $size <= $max ) {
			$svg = (string) @file_get_contents( $tmp_path, false, null, 0, $max ); // phpcs:ignore
			if ( preg_match( '~<script\b|\bon[a-z]{3,20}\s*=|javascript\s*:|<foreignObject\b|<iframe\b|<embed\b~i', $svg, $m, PREG_OFFSET_CAPTURE ) ) {
				$hits[] = array(
					'sig'      => 'upload_svg_script',
					'title'    => __( 'SVG image contains scripts or event handlers', 'wp-cyber-security' ),
					'severity' => Store::SEV_HIGH,
					'line'     => Signatures::line_at( $svg, $m[0][1] ),
					'snippet'  => Signatures::snippet( $svg, $m[0][1], strlen( $m[0][0] ) ),
				);
			}
		}

		if ( $this->settings()->get( 'clamav_enabled', false ) ) {
			$clam = $this->clamav_scan( $tmp_path );
			if ( is_array( $clam ) ) {
				$hits = array_merge( $hits, $clam );
			}
		}

		$hits = Signatures::unique( $hits );
		return array_values(
			array_filter(
				$hits,
				static function ( $hit ) use ( $min ) {
					return (int) $hit['severity'] >= $min;
				}
			)
		);
	}

	/**
	 * Name based checks for uploads.
	 *
	 * @param string $name Original file name.
	 * @return array[] Hits.
	 */
	private function name_hits( $name ) {
		$hits    = array();
		$lower   = strtolower( $name );
		$base    = basename( str_replace( '\\', '/', $lower ) );
		$exec    = array_map( 'strtolower', (array) $this->settings()->get( 'exec_extensions', array() ) );
		$snippet = Signatures::clean_snippet( $name );

		if ( false !== strpos( $name, "\0" ) || false !== strpos( $lower, '%00' ) || false !== strpos( $lower, '::$data' ) || rtrim( $base, '. ' ) !== $base ) {
			$hits[] = array(
				'sig'      => 'upload_bad_name',
				'title'    => __( 'File name uses tricks to hide its real type', 'wp-cyber-security' ),
				'severity' => Store::SEV_HIGH,
				'line'     => 0,
				'snippet'  => $snippet,
			);
		}

		$parts = explode( '.', rtrim( $base, '. ' ) );
		array_shift( $parts );
		$last = $parts ? array_pop( $parts ) : '';
		foreach ( $parts as $part ) {
			if ( in_array( $part, $exec, true ) ) {
				$hits[] = array(
					'sig'      => 'upload_double_extension',
					'title'    => __( 'Double extension hides a script (for example shell.php.jpg)', 'wp-cyber-security' ),
					'severity' => Store::SEV_HIGH,
					'line'     => 0,
					'snippet'  => $snippet,
				);
				break;
			}
		}

		$exec_names = array_map( 'strtolower', (array) $this->settings()->get( 'exec_filenames', array() ) );
		if ( in_array( $last, $exec, true ) || in_array( $base, $exec_names, true ) ) {
			$hits[] = array(
				'sig'      => 'upload_executable',
				'title'    => __( 'Executable script or server configuration file', 'wp-cyber-security' ),
				'severity' => Store::SEV_HIGH,
				'line'     => 0,
				'snippet'  => $snippet,
			);
		}
		return $hits;
	}

	/**
	 * Highest severity among hits.
	 *
	 * @param array $hits Hits.
	 * @return int
	 */
	public function max_severity( array $hits ) {
		return Signatures::max_severity( $hits );
	}

	/* ------------------------------------------------------------------ */
	/* Checksums                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Verifies a file against official checksums.
	 *
	 * @param string $rel    Relative path.
	 * @param string $sha256 Known sha256 (computed when needed and empty).
	 * @param string $md5    Known md5 (computed when needed and empty).
	 * @return string match | mismatch | unknown
	 */
	public function verify( $rel, $sha256 = '', $md5 = '' ) {
		$result = $this->verify_details( $rel, $sha256, $md5 );
		return $result['verdict'];
	}

	/**
	 * Like verify() but also says which list was used and why.
	 *
	 * Files inside this plugin's own folder are checked against the
	 * checksums.json shipped with it (source "self"), whatever use_checksums
	 * says: the signature file holds the patterns as data and would otherwise
	 * flag itself. A file listed there that differs is a "mismatch" (tampered
	 * security plugin); a file not listed is "unknown_file" and is treated like
	 * any unknown file. Without checksums.json the verdict is unknown with
	 * source "self" and no reason.
	 *
	 * @param string $rel    Relative path.
	 * @param string $sha256 Known sha256.
	 * @param string $md5    Known md5.
	 * @return array { verdict: match|mismatch|unknown, source: self|core|plugin|'', reason: mismatch|unknown_file|'' }
	 */
	public function verify_details( $rel, $sha256 = '', $md5 = '' ) {
		$out = array(
			'verdict' => 'unknown',
			'source'  => '',
			'reason'  => '',
		);
		$rel = ltrim( wp_normalize_path( (string) $rel ), '/' );
		$abs = Paths::abs( $rel );

		$self_rel = $this->self_relative( $abs );
		if ( '' !== $self_rel ) {
			return $this->verify_self( $self_rel, $abs, $sha256 );
		}

		if ( ! $this->settings()->get( 'use_checksums', true ) ) {
			return $out;
		}

		$core_rel = $this->core_relative( $abs );
		if ( '' !== $core_rel ) {
			$map = $this->core_map();
			if ( is_array( $map ) ) {
				if ( isset( $map[ $core_rel ] ) ) {
					if ( '' === $md5 ) {
						$md5 = (string) @md5_file( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
					}
					if ( '' !== $md5 && hash_equals( strtolower( (string) $map[ $core_rel ] ), strtolower( $md5 ) ) ) {
						return array(
							'verdict' => 'match',
							'source'  => 'core',
							'reason'  => '',
						);
					}
					// Bundled themes and plugins in wp-content are updated on their own,
					// so a difference there is not a core mismatch.
					if ( 0 !== strpos( $core_rel, 'wp-content/' ) ) {
						return array(
							'verdict' => 'mismatch',
							'source'  => 'core',
							'reason'  => 'mismatch',
						);
					}
				} elseif ( preg_match( '~^wp-(?:admin|includes)/~', $core_rel ) ) {
					return array(
						'verdict' => 'unknown',
						'source'  => 'core',
						'reason'  => 'unknown_file',
					);
				}
			}
		}

		$slug = $this->plugin_slug_for( $rel );
		if ( '' !== $slug ) {
			$map = $this->plugin_map( $slug );
			if ( is_array( $map ) ) {
				$inner = $this->plugin_inner_path( $abs, $slug );
				if ( '' === $inner ) {
					return $out;
				}
				if ( ! isset( $map[ $inner ] ) ) {
					return array(
						'verdict' => 'unknown',
						'source'  => 'plugin',
						'reason'  => 'unknown_file',
					);
				}
				if ( '' === $sha256 ) {
					$sha256 = (string) @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				}
				$ok = '' !== $sha256 && in_array( strtolower( $sha256 ), (array) $map[ $inner ], true );
				return array(
					'verdict' => $ok ? 'match' : 'mismatch',
					'source'  => 'plugin',
					'reason'  => $ok ? '' : 'mismatch',
				);
			}
		}
		return $out;
	}

	/**
	 * Verdict for a file inside this plugin's folder.
	 *
	 * @param string $self_rel Path inside the plugin folder.
	 * @param string $abs      Absolute path.
	 * @param string $sha256   Known sha256 (computed when empty).
	 * @return array Same shape as verify_details().
	 */
	private function verify_self( $self_rel, $abs, $sha256 ) {
		$map = $this->self_map();
		if ( ! is_array( $map ) ) {
			return array(
				'verdict' => 'unknown',
				'source'  => 'self',
				'reason'  => '',
			);
		}
		if ( ! isset( $map[ $self_rel ] ) ) {
			return array(
				'verdict' => 'unknown',
				'source'  => 'self',
				'reason'  => 'unknown_file',
			);
		}
		if ( '' === (string) $sha256 ) {
			$sha256 = (string) @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		$ok = '' !== $sha256 && hash_equals( $map[ $self_rel ], strtolower( (string) $sha256 ) );
		return array(
			'verdict' => $ok ? 'match' : 'mismatch',
			'source'  => 'self',
			'reason'  => $ok ? '' : 'mismatch',
		);
	}

	/**
	 * Own checksums from checksums.json, parsed once per request.
	 *
	 * @return array|false Inner path => lowercase sha256, false when unavailable.
	 */
	public function self_map() {
		if ( null !== $this->self_map ) {
			return $this->self_map;
		}
		$this->self_map = false;
		if ( ! defined( 'WPCYBERSEC_DIR' ) ) {
			return false;
		}
		$file = trailingslashit( wp_normalize_path( WPCYBERSEC_DIR ) ) . self::SELF_CHECKSUMS;
		$size = @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size < 2 || $size > 4 * MB_IN_BYTES ) {
			return false;
		}
		$data = json_decode( (string) @file_get_contents( $file ), true ); // phpcs:ignore
		if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return false;
		}
		$map = array();
		foreach ( $data['files'] as $path => $sha ) {
			if ( ! is_string( $sha ) || ! preg_match( '~^[a-f0-9]{64}$~i', $sha ) ) {
				continue;
			}
			$path = ltrim( wp_normalize_path( (string) $path ), '/' );
			if ( '' === $path || false !== strpos( $path, '../' ) ) {
				continue;
			}
			$map[ $path ] = strtolower( $sha );
		}
		if ( $map ) {
			$this->self_map = $map;
		}
		return $this->self_map;
	}

	/**
	 * Path inside this plugin's folder, '' when the file is elsewhere.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	private function self_relative( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		foreach ( $this->self_roots() as $root ) {
			if ( 0 === strpos( $abs, $root ) ) {
				return substr( $abs, strlen( $root ) );
			}
		}
		return '';
	}

	/**
	 * This plugin's folder as given, resolved, and as seen through the plugins
	 * folder (a symlinked install), with trailing slashes.
	 *
	 * @return string[]
	 */
	private function self_roots() {
		if ( null !== $this->self_roots ) {
			return $this->self_roots;
		}
		$roots = array();
		if ( defined( 'WPCYBERSEC_DIR' ) ) {
			$roots[] = trailingslashit( wp_normalize_path( WPCYBERSEC_DIR ) );
			$real    = realpath( WPCYBERSEC_DIR );
			if ( $real ) {
				$roots[] = trailingslashit( wp_normalize_path( $real ) );
			}
		}
		if ( defined( 'WP_PLUGIN_DIR' ) && defined( 'WPCYBERSEC_BASENAME' ) ) {
			$folder = dirname( (string) WPCYBERSEC_BASENAME );
			if ( '' !== $folder && '.' !== $folder ) {
				$roots[] = trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) ) . $folder . '/';
				$real    = realpath( WP_PLUGIN_DIR . '/' . $folder );
				if ( $real ) {
					$roots[] = trailingslashit( wp_normalize_path( $real ) );
				}
			}
		}
		$this->self_roots = array_values( array_unique( $roots ) );
		return $this->self_roots;
	}

	/**
	 * Whether a relative path is a WordPress core file (wp-admin, wp-includes
	 * or a root core file).
	 *
	 * @param string $rel Relative path.
	 * @return bool
	 */
	public function is_core_path( $rel ) {
		$core_rel = $this->core_relative( Paths::abs( $rel ) );
		if ( '' === $core_rel ) {
			return false;
		}
		if ( preg_match( '~^wp-(?:admin|includes)/~', $core_rel ) ) {
			return true;
		}
		if ( false === strpos( $core_rel, '/' ) ) {
			$map = $this->settings()->get( 'use_checksums', true ) ? $this->core_map() : false;
			if ( is_array( $map ) ) {
				return isset( $map[ $core_rel ] );
			}
			return 1 === preg_match( '~^(?:index\.php|xmlrpc\.php|license\.txt|readme\.html|wp-(?:activate|blog-header|comments-post|config-sample|cron|links-opml|load|login|mail|settings|signup|trackback)\.php)$~', $core_rel );
		}
		return false;
	}

	/**
	 * Plugin folder name for a relative path, '' when the file is not inside a
	 * plugin folder (single file plugins such as hello.php return '').
	 *
	 * @param string $rel Relative path.
	 * @return string
	 */
	public function plugin_slug_for( $rel ) {
		$abs = Paths::abs( $rel );
		foreach ( $this->plugin_roots() as $root ) {
			if ( 0 === strpos( $abs, $root ) ) {
				$sub = substr( $abs, strlen( $root ) );
				$pos = strpos( $sub, '/' );
				return false === $pos ? '' : substr( $sub, 0, $pos );
			}
		}
		return '';
	}

	/**
	 * Installed version of a plugin folder ('' when unknown).
	 *
	 * @param string $slug Folder.
	 * @return string
	 */
	public function plugin_version( $slug ) {
		if ( null === $this->plugin_versions ) {
			$this->plugin_versions = array();
			if ( ! function_exists( 'get_plugins' ) && is_readable( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			if ( function_exists( 'get_plugins' ) ) {
				foreach ( (array) get_plugins() as $file => $data ) {
					$folder = dirname( (string) $file );
					if ( '.' !== $folder && ! isset( $this->plugin_versions[ $folder ] ) && ! empty( $data['Version'] ) ) {
						$this->plugin_versions[ $folder ] = (string) $data['Version'];
						$this->plugin_names[ $folder ]    = ! empty( $data['Name'] ) ? (string) $data['Name'] : $folder;
					}
				}
			}
		}
		return isset( $this->plugin_versions[ $slug ] ) ? $this->plugin_versions[ $slug ] : '';
	}

	/**
	 * Display name of a plugin folder (the folder name when unknown).
	 *
	 * @param string $slug Folder.
	 * @return string
	 */
	public function plugin_name( $slug ) {
		$this->plugin_version( $slug ); // Loads the names too.
		return isset( $this->plugin_names[ $slug ] ) ? $this->plugin_names[ $slug ] : (string) $slug;
	}

	/**
	 * Path of a file relative to the WordPress folder ('' when outside it), the
	 * form core checksums and the core SVN tags use.
	 *
	 * @param string $rel Relative path (scan root).
	 * @return string
	 */
	public function core_path( $rel ) {
		return $this->core_relative( Paths::abs( $rel ) );
	}

	/**
	 * Path of a file inside its plugin folder ('' when it is not in $slug).
	 *
	 * @param string $rel  Relative path (scan root).
	 * @param string $slug Plugin folder.
	 * @return string
	 */
	public function plugin_path( $rel, $slug ) {
		return $this->plugin_inner_path( Paths::abs( $rel ), $slug );
	}

	/**
	 * Whether a file belongs to this plugin's own folder.
	 *
	 * @param string $rel Relative path (scan root).
	 * @return bool
	 */
	public function is_own_path( $rel ) {
		return '' !== $this->self_relative( Paths::abs( $rel ) );
	}

	/**
	 * Installed WordPress version (read from version.php).
	 *
	 * @return string
	 */
	public function installed_wp_version() {
		return $this->wp_version();
	}

	/**
	 * Core checksum map for the installed version (path => md5).
	 *
	 * @return array|false
	 */
	public function core_map() {
		if ( null !== $this->core_map ) {
			return $this->core_map;
		}
		$this->core_map = false;

		$version = $this->wp_version();
		$locale  = function_exists( 'get_locale' ) ? (string) get_locale() : 'en_US';
		if ( '' === $version ) {
			return false;
		}
		$key    = self::CORE_TRANSIENT . md5( $version . '|' . $locale );
		$cached = get_site_transient( $key );
		if ( is_array( $cached ) && $cached ) {
			$this->core_map = $cached;
			return $cached;
		}
		if ( 'none' === $cached || $this->offline() ) {
			return false;
		}

		if ( ! function_exists( 'get_core_checksums' ) && is_readable( ABSPATH . 'wp-admin/includes/update.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( ! function_exists( 'get_core_checksums' ) ) {
			return false;
		}
		$sums = get_core_checksums( $version, $locale );
		if ( ( ! is_array( $sums ) || ! $sums ) && 'en_US' !== $locale ) {
			$sums = get_core_checksums( $version, 'en_US' );
		}
		if ( is_array( $sums ) && $sums ) {
			$clean = array();
			foreach ( $sums as $path => $md5 ) {
				if ( is_string( $md5 ) && preg_match( '~^[a-f0-9]{32}$~i', $md5 ) ) {
					$clean[ ltrim( wp_normalize_path( (string) $path ), '/' ) ] = strtolower( $md5 );
				}
			}
			if ( $clean ) {
				set_site_transient( $key, $clean, self::CACHE_TTL );
				$this->core_map = $clean;
				return $clean;
			}
		}
		set_site_transient( $key, 'none', self::MISS_TTL );
		return false;
	}

	/**
	 * Checksum map of a wordpress.org plugin (inner path => list of sha256),
	 * false when the plugin is not on wordpress.org, the version is unknown,
	 * or the map does not fit the installed copy (a premium build that shares
	 * the folder name of a free plugin).
	 *
	 * @param string $slug Plugin folder.
	 * @return array|false
	 */
	public function plugin_map( $slug ) {
		$slug    = (string) $slug;
		$version = $this->plugin_version( $slug );
		if ( '' === $slug || '' === $version || ! preg_match( '~^[a-z0-9._-]{1,100}$~i', $slug ) || ! preg_match( '~^[a-z0-9._+-]{1,40}$~i', $version ) ) {
			return false;
		}
		$id = $slug . '@' . $version;
		if ( array_key_exists( $id, $this->plugin_maps ) ) {
			return $this->plugin_maps[ $id ];
		}
		$this->plugin_maps[ $id ] = false;

		$key    = self::PLUGIN_TRANSIENT . md5( $id );
		$cached = get_site_transient( $key );
		$map    = false;
		if ( is_string( $cached ) && 0 === strpos( $cached, "v1\n" ) ) {
			$map = $this->unpack_map( $cached );
		} elseif ( 'none' === $cached || $this->offline() || $this->fetch_failures >= 2 ) {
			return false;
		} else {
			$map = $this->fetch_plugin_map( $slug, $version, $key );
		}
		if ( ! $map || ! $this->map_fits( $slug, $map ) ) {
			return false;
		}
		$this->plugin_maps[ $id ] = $map;
		return $map;
	}

	/**
	 * Downloads and caches a plugin checksum file.
	 *
	 * @param string $slug    Slug.
	 * @param string $version Version.
	 * @param string $key     Transient key.
	 * @return array|false
	 */
	private function fetch_plugin_map( $slug, $version, $key ) {
		$url      = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 10,
				'redirection' => 2,
			)
		);
		if ( is_wp_error( $response ) ) {
			++$this->fetch_failures;
			if ( $this->fetch_failures >= 2 ) {
				set_site_transient( self::OFFLINE_TRANSIENT, 1, self::NETWORK_ERR_TTL );
			}
			return false;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			// 404: not a wordpress.org plugin or unknown version. 5xx: try later.
			set_site_transient( $key, 'none', $code >= 500 ? self::NETWORK_ERR_TTL : self::MISS_TTL );
			return false;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			set_site_transient( $key, 'none', self::MISS_TTL );
			return false;
		}

		$map = array();
		foreach ( $data['files'] as $path => $sums ) {
			if ( ! is_array( $sums ) || ! isset( $sums['sha256'] ) ) {
				continue;
			}
			$list = array();
			foreach ( (array) $sums['sha256'] as $sha ) {
				if ( is_string( $sha ) && preg_match( '~^[a-f0-9]{64}$~i', $sha ) ) {
					$list[] = strtolower( $sha );
				}
			}
			$path = ltrim( wp_normalize_path( (string) $path ), '/' );
			if ( $list && '' !== $path && false === strpos( $path, "\t" ) && false === strpos( $path, "\n" ) ) {
				$map[ $path ] = $list;
			}
		}
		if ( ! $map ) {
			set_site_transient( $key, 'none', self::MISS_TTL );
			return false;
		}
		set_site_transient( $key, $this->pack_map( $map ), self::CACHE_TTL );
		return $map;
	}

	/**
	 * Compact text form: "v1\npath\tsha[,sha]\n..." (about half the size of a
	 * serialized array, which matters for plugins with thousands of files).
	 *
	 * @param array $map Map.
	 * @return string
	 */
	private function pack_map( array $map ) {
		$lines = array( 'v1' );
		foreach ( $map as $path => $list ) {
			$lines[] = $path . "\t" . implode( ',', $list );
		}
		return implode( "\n", $lines );
	}

	/**
	 * @param string $packed Packed map.
	 * @return array
	 */
	private function unpack_map( $packed ) {
		$map = array();
		foreach ( explode( "\n", $packed ) as $i => $line ) {
			if ( 0 === $i || '' === $line ) {
				continue;
			}
			$tab = strrpos( $line, "\t" );
			if ( false === $tab ) {
				continue;
			}
			$map[ substr( $line, 0, $tab ) ] = explode( ',', substr( $line, $tab + 1 ) );
		}
		return $map;
	}

	/**
	 * Sanity check: compares a few small files. When none of up to 8 sampled
	 * files match and at least 3 differ, the installed copy is not the
	 * wordpress.org build of that version and the map is ignored.
	 *
	 * @param string $slug Plugin folder.
	 * @param array  $map  Map.
	 * @return bool
	 */
	private function map_fits( $slug, array $map ) {
		$dir = $this->plugin_dir_for( $slug );
		if ( '' === $dir ) {
			return false;
		}
		$match    = 0;
		$mismatch = 0;
		$checked  = 0;
		foreach ( $map as $inner => $list ) {
			$file = $dir . $inner;
			$size = @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $size || $size > 262144 || ! @is_readable( $file ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			$sha = (string) @hash_file( 'sha256', $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( in_array( $sha, (array) $list, true ) ) {
				++$match;
			} else {
				++$mismatch;
			}
			if ( ++$checked >= 8 || $match >= 2 ) {
				break;
			}
		}
		return ! ( 0 === $match && $mismatch >= 3 );
	}

	/**
	 * True while wordpress.org could not be reached recently.
	 *
	 * @return bool
	 */
	private function offline() {
		return (bool) get_site_transient( self::OFFLINE_TRANSIENT );
	}

	/**
	 * Installed WordPress version, read from version.php so it is right even
	 * in the request that just updated core.
	 *
	 * @return string
	 */
	private function wp_version() {
		$file = ABSPATH . ( defined( 'WPINC' ) ? WPINC : 'wp-includes' ) . '/version.php';
		$code = @file_get_contents( $file, false, null, 0, 4096 ); // phpcs:ignore
		if ( $code && preg_match( '~\$wp_version\s*=\s*[\x27"]([^\x27"]+)[\x27"]~', $code, $m ) ) {
			return $m[1];
		}
		return isset( $GLOBALS['wp_version'] ) ? (string) $GLOBALS['wp_version'] : '';
	}

	/**
	 * Path relative to ABSPATH, '' when outside WordPress.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	private function core_relative( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		foreach ( $this->abspaths() as $root ) {
			if ( 0 === strpos( $abs, $root ) ) {
				return substr( $abs, strlen( $root ) );
			}
		}
		return '';
	}

	/**
	 * ABSPATH as given and resolved (symlinked installs), with trailing slash.
	 *
	 * @return string[]
	 */
	private function abspaths() {
		static $roots = null;
		if ( null === $roots ) {
			$roots = array( trailingslashit( wp_normalize_path( ABSPATH ) ) );
			$real  = realpath( ABSPATH );
			if ( $real ) {
				$roots[] = trailingslashit( wp_normalize_path( $real ) );
			}
			$roots = array_values( array_unique( $roots ) );
		}
		return $roots;
	}

	/**
	 * Plugin folder roots (as given and resolved), with trailing slash.
	 *
	 * @return string[]
	 */
	private function plugin_roots() {
		static $roots = null;
		if ( null === $roots ) {
			$roots = array();
			if ( defined( 'WP_PLUGIN_DIR' ) ) {
				$roots[] = trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) );
				$real    = realpath( WP_PLUGIN_DIR );
				if ( $real ) {
					$roots[] = trailingslashit( wp_normalize_path( $real ) );
				}
			}
			$roots = array_values( array_unique( $roots ) );
		}
		return $roots;
	}

	/**
	 * @param string $slug Folder.
	 * @return string Absolute folder with trailing slash, '' when missing.
	 */
	private function plugin_dir_for( $slug ) {
		foreach ( $this->plugin_roots() as $root ) {
			if ( @is_dir( $root . $slug ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return $root . $slug . '/';
			}
		}
		return '';
	}

	/**
	 * Path inside the plugin folder.
	 *
	 * @param string $abs  Absolute path.
	 * @param string $slug Folder.
	 * @return string
	 */
	private function plugin_inner_path( $abs, $slug ) {
		foreach ( $this->plugin_roots() as $root ) {
			$prefix = $root . $slug . '/';
			if ( 0 === strpos( $abs, $prefix ) ) {
				return substr( $abs, strlen( $prefix ) );
			}
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/* ClamAV                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Whether a ClamAV binary is installed and the server lets PHP run it.
	 *
	 * @return bool
	 */
	public function clamav_available() {
		return (bool) $this->clamav_binaries();
	}

	/**
	 * Details for the settings and diagnostics screens.
	 *
	 * @return array { available: bool, binary: string, daemon: bool, can_exec: bool }
	 */
	public function clamav_info() {
		$bins = $this->clamav_binaries();
		return array(
			'available' => (bool) $bins,
			'binary'    => $bins ? $bins[0] : '',
			'daemon'    => $this->clamav_daemon_available(),
			'can_exec'  => $this->can_exec(),
		);
	}

	/**
	 * Scans one file with ClamAV.
	 *
	 * @param string $path        File.
	 * @param bool   $daemon_only Only use clamdscan.
	 * @return array[]|null Hits (empty when clean), null when ClamAV is unavailable or failed.
	 */
	public function clamav_scan( $path, $daemon_only = false ) {
		$path = (string) $path;
		if ( '' === $path || ! @is_file( $path ) || ! @is_readable( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return null;
		}
		foreach ( $this->clamav_binaries() as $bin ) {
			$daemon = false !== strpos( basename( $bin ), 'clamdscan' );
			if ( $daemon_only && ! $daemon ) {
				continue;
			}
			$cmd    = escapeshellarg( $bin ) . ( $daemon ? ' --no-summary --fdpass ' : ' --no-summary --stdout ' ) . escapeshellarg( $path ) . ' 2>&1';
			$result = $this->run_command( $cmd, $daemon ? 30 : 120 );
			if ( null === $result ) {
				continue;
			}
			list( $code, $output ) = $result;
			if ( 0 === $code ) {
				return array();
			}
			if ( 1 === $code ) {
				$hits = array();
				foreach ( preg_split( '~\r?\n~', (string) $output ) as $line ) {
					if ( preg_match( '~:\s*(\S[^:]*?)\s+FOUND\s*$~', $line, $m ) ) {
						$hits[] = array(
							'sig'      => 'clamav',
							/* translators: %s: ClamAV signature name */
							'title'    => sprintf( __( 'ClamAV: %s', 'wp-cyber-security' ), Signatures::clean_snippet( $m[1] ) ),
							'severity' => Store::SEV_CRITICAL,
							'line'     => 0,
							'snippet'  => Signatures::clean_snippet( $m[1] ),
						);
					}
				}
				if ( ! $hits ) {
					$hits[] = array(
						'sig'      => 'clamav',
						'title'    => __( 'ClamAV: infected file', 'wp-cyber-security' ),
						'severity' => Store::SEV_CRITICAL,
						'line'     => 0,
						'snippet'  => '',
					);
				}
				return $hits;
			}
			// Exit code 2 (daemon not running, database error): try the next binary.
		}
		return null;
	}

	/**
	 * @return bool
	 */
	private function clamav_daemon_available() {
		foreach ( $this->clamav_binaries() as $bin ) {
			if ( false !== strpos( basename( $bin ), 'clamdscan' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Usable ClamAV binaries, the daemon client first.
	 *
	 * @return string[]
	 */
	private function clamav_binaries() {
		if ( null !== $this->clamav_bins ) {
			return $this->clamav_bins;
		}
		$this->clamav_bins = array();
		if ( ! $this->can_exec() ) {
			return array();
		}
		$candidates = array();
		$custom     = (string) $this->settings()->get( 'clamav_binary', '' );
		if ( '' !== $custom ) {
			$candidates[] = $custom;
		}
		foreach ( array( 'clamdscan', 'clamscan' ) as $name ) {
			foreach ( array( '/usr/bin/', '/usr/local/bin/', '/opt/homebrew/bin/', '/usr/sbin/', '/bin/' ) as $dir ) {
				$candidates[] = $dir . $name;
			}
		}
		foreach ( array_unique( $candidates ) as $bin ) {
			$base = basename( $bin );
			if ( 0 !== strpos( $base, 'clamdscan' ) && 0 !== strpos( $base, 'clamscan' ) ) {
				continue; // Only ever run ClamAV binaries, whatever the setting says.
			}
			if ( @is_file( $bin ) && @is_executable( $bin ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$this->clamav_bins[] = $bin;
			}
		}
		usort(
			$this->clamav_bins,
			static function ( $a, $b ) {
				return (int) ( false === strpos( basename( $a ), 'clamdscan' ) ) - (int) ( false === strpos( basename( $b ), 'clamdscan' ) );
			}
		);
		return $this->clamav_bins;
	}

	/**
	 * Whether proc_open or exec may be used.
	 *
	 * @return bool
	 */
	private function can_exec() {
		return $this->function_enabled( 'proc_open' ) || $this->function_enabled( 'exec' );
	}

	/**
	 * @param string $name Function.
	 * @return bool
	 */
	private function function_enabled( $name ) {
		if ( ! function_exists( $name ) ) {
			return false;
		}
		$disabled = array_map( 'trim', explode( ',', strtolower( (string) ini_get( 'disable_functions' ) ) ) );
		return ! in_array( strtolower( $name ), $disabled, true );
	}

	/**
	 * Runs a command with a timeout.
	 *
	 * @param string $cmd     Shell command (arguments already escaped).
	 * @param int    $timeout Seconds.
	 * @return array|null [ exit code, output ] or null on failure / timeout.
	 */
	private function run_command( $cmd, $timeout ) {
		if ( $this->function_enabled( 'proc_open' ) ) {
			$pipes = array();
			$proc  = @proc_open( $cmd, array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes ); // phpcs:ignore
			if ( ! is_resource( $proc ) ) {
				return null;
			}
			stream_set_blocking( $pipes[1], false );
			stream_set_blocking( $pipes[2], false );
			$output = '';
			$code   = null;
			$end    = microtime( true ) + $timeout;
			while ( microtime( true ) < $end ) {
				$output .= (string) stream_get_contents( $pipes[1] ) . (string) stream_get_contents( $pipes[2] );
				$status  = proc_get_status( $proc );
				if ( ! $status['running'] ) {
					$code = (int) $status['exitcode'];
					break;
				}
				usleep( 50000 );
			}
			$output .= (string) stream_get_contents( $pipes[1] ) . (string) stream_get_contents( $pipes[2] );
			fclose( $pipes[1] );
			fclose( $pipes[2] );
			if ( null === $code ) {
				@proc_terminate( $proc ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				@proc_close( $proc ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return null;
			}
			@proc_close( $proc ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return array( $code, substr( $output, 0, 65536 ) );
		}
		if ( $this->function_enabled( 'exec' ) ) {
			$lines = array();
			$code  = 0;
			@exec( $cmd, $lines, $code ); // phpcs:ignore
			return array( (int) $code, implode( "\n", array_slice( $lines, 0, 500 ) ) );
		}
		return null;
	}

	/* ------------------------------------------------------------------ */
	/* Helpers                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * @return Settings
	 */
	private function settings() {
		return wpcybersec()->settings;
	}

	/**
	 * @return int 1..3
	 */
	private function min_severity() {
		return max( 1, min( 3, (int) $this->settings()->get( 'min_severity', 1 ) ) );
	}

	/**
	 * @return int Bytes.
	 */
	public function max_bytes() {
		return max( 1, (int) $this->settings()->get( 'max_file_mb', 10 ) ) * 1048576;
	}

	/**
	 * @param array[] $hits Hits.
	 * @param string  $sig  Signature id.
	 * @return bool
	 */
	private function has_sig( array $hits, $sig ) {
		foreach ( $hits as $hit ) {
			if ( isset( $hit['sig'] ) && $sig === $hit['sig'] ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $abs Path.
	 * @return bool
	 */
	private function is_php_name( $abs ) {
		return in_array( Paths::ext( $abs ), Signatures::php_extensions(), true );
	}

	/**
	 * True for files under a custom uploads folder that the path rule
	 * (wp-content/uploads) does not cover.
	 *
	 * @param string $abs Path.
	 * @return bool
	 */
	private function in_custom_uploads( $abs ) {
		static $base = null;
		if ( null === $base ) {
			$base = '';
			if ( function_exists( 'wp_upload_dir' ) ) {
				$dirs = wp_upload_dir( null, false );
				if ( ! empty( $dirs['basedir'] ) ) {
					$base = trailingslashit( wp_normalize_path( $dirs['basedir'] ) );
				}
			}
			if ( false !== strpos( $base, '/wp-content/uploads/' ) ) {
				$base = ''; // Covered by the path rule.
			}
		}
		return '' !== $base && 0 === strpos( $abs, $base );
	}

	/**
	 * "Silence is golden" style index files.
	 *
	 * @param string $abs Path.
	 * @return bool
	 */
	private function is_harmless_stub( $abs ) {
		$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 400 ) {
			return false;
		}
		$tiny = (string) @file_get_contents( $abs ); // phpcs:ignore
		return false === strpos( $tiny, '<?' ) || (bool) preg_match( '~^\s*<\?php\s*(?://[^\n]*\n?|#[^\n]*\n?|/\*.*?\*/|\s+)*(?:\?>\s*)?$~s', $tiny );
	}

	/**
	 * Regex search of a file in 1 MB chunks (with a small overlap so a match
	 * across a chunk border is still found).
	 *
	 * @param string $path    File.
	 * @param string $pattern PCRE (must only match short strings, under 128 bytes).
	 * @return bool
	 */
	private function file_matches( $path, $pattern ) {
		$handle = @fopen( $path, 'rb' ); // phpcs:ignore
		if ( ! $handle ) {
			return false;
		}
		$carry = '';
		$found = false;
		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, 1048576 ); // phpcs:ignore
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			$data = $carry . $chunk;
			if ( 0 !== @preg_match( $pattern, $data ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$found = true; // A match, or a PCRE error (fail closed).
				break;
			}
			$carry = substr( $data, -128 );
		}
		fclose( $handle ); // phpcs:ignore
		return $found;
	}

	/**
	 * Case-insensitive search of a file in 1 MB chunks.
	 *
	 * @param string $path   File.
	 * @param string $needle Needle (ASCII).
	 * @return bool
	 */
	private function file_contains( $path, $needle ) {
		$handle = @fopen( $path, 'rb' ); // phpcs:ignore
		if ( ! $handle ) {
			return false;
		}
		$needle = strtolower( $needle );
		$carry  = '';
		$found  = false;
		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, 1048576 ); // phpcs:ignore
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			if ( false !== strpos( strtolower( $carry . $chunk ), $needle ) ) {
				$found = true;
				break;
			}
			$carry = substr( $chunk, - ( strlen( $needle ) - 1 ) );
		}
		fclose( $handle ); // phpcs:ignore
		return $found;
	}
}
