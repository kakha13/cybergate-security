<?php
/**
 * Stored copies of file versions, used to show what changed in a file.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Content-addressed, gzip compressed copies of the versions of PHP and
 * configuration files the plugin trusted or reported, so the Reports page can
 * show exactly what changed (a git diff like view) instead of only "the file
 * was modified".
 *
 * Layout: <data_dir>/snapshots/<k[0:2]>/<k[2:4]>/<k>.gz (mode 0600), where
 * k = HMAC-SHA256( sha256 of the content, random per-site key ). The key means
 * a leaked fingerprint (the reports, alert emails and webhooks show SHA-256
 * values) can never be turned into a download address on a server that ignores
 * the .htaccess deny rules (nginx). On a multisite network every site but the
 * main one keeps its copies in snapshots/site-<blog id>/ (each site has its
 * own key and tables, and prunes only its own folder).
 *
 * Files that hold secrets are never copied as they are: wp-config.php, .env,
 * .ini and similar names (is_secret_name()), and any other file in which
 * Diff::redact() finds a password, key or token, are stored already redacted
 * (REDACTED_MAGIC, a JSON header with the real sha256, the fingerprints of the
 * hidden values and the sha256 of the redacted text, then the redacted text),
 * so even someone who has the database and can download the folder never
 * reads a password from a copy. The changes view only ever shows redacted
 * text, so nothing is lost.
 *
 * What is copied: executable names (Paths::is_executable: PHP, .htaccess,
 * .user.ini, ...), configuration files and .js/.html/.svg files, at most
 * snapshot_max_kb, never binary content (a NUL byte in the first 8 KB). Files
 * that match an official WordPress.org checksum are skipped by store_trusted():
 * their original can be downloaded and verified again (Originals).
 *
 * Every read checks the SHA-256 of the decompressed content (of the redacted
 * text for a redacted copy).
 */
class Snapshots {

	/** Folder inside the data folder. */
	const DIR = 'snapshots';

	/** Random HMAC key for file names (not autoloaded). */
	const KEY_OPTION = 'wpcybersec_snapshot_key';

	/**
	 * "done:<generation>" once a whole-site scan copied the files trusted
	 * before copies existed, "pending:<generation>" while that is still to do.
	 * Every reset raises the generation, so a scan that was running during a
	 * reset does not mark the new backfill done.
	 */
	const BACKFILL_OPTION = 'wpcybersec_snapshot_backfill';

	/** Last top-level folder prune() finished, so a large store is pruned over several days. */
	const CURSOR_OPTION = 'wpcybersec_snapshot_prune_cursor';

	/** Cached stats(). */
	const STATS_TRANSIENT = 'wpcybersec_snapshot_stats';

	/** Hard cap for one copy (also for downloaded originals). */
	const HARD_MAX = 4194304;

	/** Name based extras besides executable names. */
	const CONFIG_NAMES    = array( '.htaccess', '.user.ini', 'php.ini', 'web.config', 'wp-config.php' );
	const TEXT_EXTENSIONS = array( 'js', 'mjs', 'html', 'htm', 'svg' );

	/** Unreferenced copies younger than this are kept (a running scan may not have saved its rows yet). */
	const GRACE = DAY_IN_SECONDS;

	/** First line of a copy stored redacted. */
	const REDACTED_MAGIC = "WPCS-REDACTED/1\n";

	/**
	 * Content that may hold a password, key or token, so it is run through
	 * Diff::redact() before it is stored (a cheap test; redact() decides).
	 */
	const SECRET_HINT = '/define\s*+\(\s*+[\'"][A-Za-z0-9_]*(?:PASSWORD|PASS|SECRET|TOKEN|_KEY|_SALT|AUTH)|(?:pass(?:word|wd)?|pwd|secret|api_?key|token|credential)[\'"]?\s*+(?:=>|\.?=|:)\s*+[\'"][^\'"\s]{3}|^[ \t]*+(?:export[ \t]++)?[A-Za-z0-9_]*(?:PASSWORD|PASS|SECRET|TOKEN|KEY)[ \t]*+=[ \t]*+\S|SetEnv\s++\S*+|PRIVATE KEY-----|\b(?:AKIA|ASIA)[0-9A-Z]{16}|\b(?:sk|rk)_live_|\bxox[abposr]-|\bSG\.[\w\-]{16}|\bgh[pousr]_[A-Za-z0-9]{30}|\bAIza[\w\-]{35}|:\/\/[^\s:\/@"\']++:[^\s\/@"\']++@|new\s++\\\\?(?:wpdb|mysqli|PDO)\s*+\(|mysqli?_(?:real_)?connect\s*+\(|putenv\s*+\(|Bearer\s/im';

	/** Legacy copies of secret files re-stored redacted per prune() run. */
	const HARDEN_PER_RUN = 200;

	/** Work limits for one prune() run. */
	const PRUNE_SECONDS = 8.0;
	const PRUNE_FILES   = 20000;

	/** @var string|null HMAC key for this request. */
	private $key = null;

	/** @var bool Whether the folder was created and protected in this request. */
	private $ready = false;

	/**
	 * Hooks: re-copy trusted files when copies are switched on or allowed to be larger.
	 */
	public function register() {
		add_action( 'wpcybersec_settings_updated', array( $this, 'on_settings_updated' ), 10, 2 );
	}

	/**
	 * @param array $new New settings.
	 * @param array $old Previous settings.
	 */
	public function on_settings_updated( $new, $old ) {
		$new_on  = ! empty( $new['snapshots'] );
		$old_on  = ! empty( $old['snapshots'] );
		$new_max = isset( $new['snapshot_max_kb'] ) ? (int) $new['snapshot_max_kb'] : 0;
		$old_max = isset( $old['snapshot_max_kb'] ) ? (int) $old['snapshot_max_kb'] : 0;
		if ( ( $new_on && ! $old_on ) || ( $new_on && $new_max > $old_max ) ) {
			$this->reset_backfill();
		}
	}

	/* ------------------------------------------------------------------ */
	/* Policy                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * @return bool Whether copies are taken (setting on and zlib available).
	 */
	public function enabled() {
		return function_exists( 'gzencode' ) && (bool) wpcybersec()->settings->get( 'snapshots', true );
	}

	/**
	 * @return int Largest file copied, in bytes.
	 */
	public function max_bytes() {
		$kb = (int) wpcybersec()->settings->get( 'snapshot_max_kb', 256 );
		return min( self::HARD_MAX, max( 16, $kb ) * 1024 );
	}

	/**
	 * Whether the kind of file is copied (by name only, no disk access).
	 *
	 * @param string $name File name or path.
	 * @return bool
	 */
	public static function is_diffable_name( $name ) {
		$name = (string) $name;
		if ( '' === $name ) {
			return false;
		}
		$base = strtolower( basename( wp_normalize_path( $name ) ) );
		if ( in_array( $base, self::CONFIG_NAMES, true ) || in_array( Paths::ext( $base ), self::TEXT_EXTENSIONS, true ) ) {
			return true;
		}
		return Paths::is_executable( $base );
	}

	/**
	 * Cheap check before reading a file: copies on, copyable name, small enough.
	 *
	 * @param string $abs  Path.
	 * @param int    $size Size in bytes (-1 to read it).
	 * @return bool
	 */
	public function wants( $abs, $size = -1 ) {
		if ( ! $this->enabled() || ! self::is_diffable_name( $abs ) ) {
			return false;
		}
		$size = (int) $size;
		if ( $size < 0 ) {
			$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $size ) {
				return false;
			}
		}
		return (int) $size <= $this->max_bytes();
	}

	/**
	 * Binary content: a NUL byte in the first 8 KB.
	 *
	 * @param string $content Content.
	 * @return bool
	 */
	public static function is_binary( $content ) {
		return false !== strpos( substr( (string) $content, 0, 8192 ), "\0" );
	}

	/**
	 * @param string $sha Value.
	 * @return bool Whether it is a lowercase or uppercase sha256 hex string.
	 */
	public static function is_sha( $sha ) {
		return is_string( $sha ) && 1 === preg_match( '/^[a-f0-9]{64}$/i', $sha );
	}

	/**
	 * Names of files that hold secrets: wp-config.php (and copies such as
	 * wp-config.php.bak), .env files, .ini and similar configuration. Their
	 * copies are always stored redacted, and excerpts of them are redacted
	 * more strictly.
	 *
	 * @param string $name File name or path.
	 * @return bool
	 */
	public static function is_secret_name( $name ) {
		$base = strtolower( basename( wp_normalize_path( (string) $name ) ) );
		if ( '' === $base ) {
			return false;
		}
		if ( 0 === strpos( $base, 'wp-config' ) || 0 === strpos( $base, '.env' ) || '.env' === substr( $base, -4 ) ) {
			return true;
		}
		if ( in_array( $base, array( '.user.ini', 'php.ini', 'web.config', '.htpasswd', '.my.cnf', 'auth.json' ), true ) ) {
			return true;
		}
		return in_array( Paths::ext( $base ), array( 'ini', 'env', 'cnf', 'conf', 'pem', 'key' ), true );
	}

	/* ------------------------------------------------------------------ */
	/* Store and read                                                      */
	/* ------------------------------------------------------------------ */

	/**
	 * Copies a file when it qualifies (copies on, copyable name, at most
	 * snapshot_max_kb, not binary). Files that hold secrets are stored
	 * redacted (see the class comment). When the copy exists nothing is read;
	 * its time is refreshed so prune() keeps it for another GRACE period.
	 *
	 * @param string $abs Absolute path.
	 * @param string $sha Known sha256 of the content ('' to compute it).
	 * @return bool True when a copy of $sha (or of the current content when $sha is empty) exists afterwards.
	 */
	public function store( $abs, $sha = '' ) {
		$abs = (string) $abs;
		$sha = strtolower( (string) $sha );
		if ( ! $this->enabled() || ! self::is_diffable_name( $abs ) ) {
			return false;
		}
		if ( self::is_sha( $sha ) && $this->has( $sha ) ) {
			$this->refresh( $sha, $abs );
			if ( $this->has( $sha ) ) {
				return true;
			}
		}
		if ( ! @is_file( $abs ) || ! @is_readable( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$max  = $this->max_bytes();
		$size = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > $max ) {
			return false;
		}
		$content = @file_get_contents( $abs, false, null, 0, $max + 1 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		if ( ! is_string( $content ) || strlen( $content ) > $max || self::is_binary( $content ) ) {
			return false;
		}
		$real = hash( 'sha256', $content );
		if ( $this->has( $real ) ) {
			$this->refresh( $real, $abs );
		}
		if ( ! $this->has( $real ) ) {
			$payload = $this->payload( $real, $content, $abs );
			if ( null === $payload || ! $this->write( $real, $payload ) ) {
				return false;
			}
		}
		// The file changed after it was fingerprinted: that version is kept too,
		// but the one asked for is still missing.
		return '' === $sha || hash_equals( $sha, $real );
	}

	/**
	 * Copies a file that is trusted now, unless it matches an official
	 * WordPress.org checksum (that original can be downloaded when needed).
	 *
	 * @param string     $abs    Path.
	 * @param string     $sha    Known sha256.
	 * @param array|null $verify Scanner::verify_details() result.
	 * @return bool
	 */
	public function store_trusted( $abs, $sha, $verify = null ) {
		if ( is_array( $verify ) && isset( $verify['verdict'], $verify['source'] ) && 'match' === $verify['verdict'] && in_array( $verify['source'], array( 'core', 'plugin' ), true ) ) {
			return false;
		}
		return $this->store( $abs, $sha );
	}

	/**
	 * Stores content that did not come from a file on this site (a verified
	 * official original). Not bound to the "snapshots" setting: it is a cache.
	 *
	 * @param string $content Content.
	 * @return string sha256, '' when it was not stored.
	 */
	public function put_content( $content ) {
		$content = (string) $content;
		if ( ! function_exists( 'gzencode' ) || strlen( $content ) > self::HARD_MAX || self::is_binary( $content ) ) {
			return '';
		}
		$sha = hash( 'sha256', $content );
		return $this->write( $sha, $content ) ? $sha : '';
	}

	/**
	 * @param string $sha sha256.
	 * @return bool
	 */
	public function has( $sha ) {
		return self::is_sha( $sha ) && @is_file( $this->path_for( $sha ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Text of a stored version (the redacted text for a copy stored redacted).
	 *
	 * @param string $sha sha256.
	 * @return string|null Null when missing, unreadable or corrupt.
	 */
	public function get( $sha ) {
		$entry = $this->get_entry( $sha );
		return null === $entry ? null : $entry['text'];
	}

	/**
	 * A stored version, checked against its sha256.
	 *
	 * @param string $sha sha256.
	 * @return array|null { text: string, redacted: bool, found: array (name => fingerprint
	 *                    of the hidden values, Diff::redact()), key: string (Diff::fingerprint_key_id()
	 *                    when they were taken) }, null when missing, unreadable or corrupt.
	 */
	public function get_entry( $sha ) {
		$sha = strtolower( (string) $sha );
		if ( ! self::is_sha( $sha ) || ! function_exists( 'gzdecode' ) ) {
			return null;
		}
		$path = $this->path_for( $sha );
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 2 * self::HARD_MAX ) {
			return null;
		}
		$gz = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		if ( ! is_string( $gz ) ) {
			return null;
		}
		$content = @gzdecode( $gz, 2 * self::HARD_MAX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( is_string( $content ) ) {
			$entry = self::parse_redacted( $content, $sha );
			if ( null !== $entry ) {
				return $entry;
			}
			// A file of the site may itself start with the marker: then it is a plain copy.
			if ( strlen( $content ) <= self::HARD_MAX && hash_equals( $sha, hash( 'sha256', $content ) ) ) {
				return array(
					'text'     => $content,
					'redacted' => false,
					'found'    => array(),
					'key'      => '',
				);
			}
		}
		Fs::delete( $path ); // corrupt or truncated copy.
		return null;
	}

	/**
	 * Reads a copy stored redacted.
	 *
	 * @param string $content Decompressed copy.
	 * @param string $sha     sha256 of the real content it stands for.
	 * @return array|null get_entry() shape, null when it is not a valid redacted copy of $sha.
	 */
	private static function parse_redacted( $content, $sha ) {
		$magic = strlen( self::REDACTED_MAGIC );
		if ( 0 !== strncmp( $content, self::REDACTED_MAGIC, $magic ) ) {
			return null;
		}
		$eol = strpos( $content, "\n", $magic );
		if ( false === $eol || $eol - $magic > 262144 ) {
			return null;
		}
		$head = json_decode( (string) substr( $content, $magic, $eol - $magic ), true );
		$text = (string) substr( $content, $eol + 1 );
		if ( ! is_array( $head ) || ! isset( $head['sha256'], $head['body'] ) || ! is_string( $head['sha256'] ) || ! is_string( $head['body'] )
			|| ! hash_equals( $sha, strtolower( $head['sha256'] ) ) || ! hash_equals( strtolower( $head['body'] ), hash( 'sha256', $text ) ) ) {
			return null;
		}
		$found = array();
		foreach ( isset( $head['found'] ) && is_array( $head['found'] ) ? $head['found'] : array() as $name => $print ) {
			if ( is_string( $print ) ) {
				$found[ (string) $name ] = $print;
			}
		}
		return array(
			'text'     => $text,
			'redacted' => true,
			'found'    => $found,
			'key'      => isset( $head['key'] ) && is_string( $head['key'] ) ? $head['key'] : '',
		);
	}

	/**
	 * What is written for a file: the content itself, or for a file that
	 * holds secrets, the redacted copy (see the class comment).
	 *
	 * @param string $sha     sha256 of $content.
	 * @param string $content Content.
	 * @param string $name    File name or path.
	 * @return string|null Null when a redacted copy could not be built (nothing is stored then).
	 */
	private function payload( $sha, $content, $name ) {
		$secret = self::is_secret_name( $name );
		if ( ! $secret && 0 === preg_match( self::SECRET_HINT, $content ) ) {
			return $content;
		}
		$found = array();
		$text  = Diff::redact( $content, basename( wp_normalize_path( (string) $name ) ), $found );
		if ( ! $found && ! $secret ) {
			return $content;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- exact bytes, no WordPress filters.
		$head = json_encode(
			array(
				'sha256' => $sha,
				'body'   => hash( 'sha256', $text ),
				'key'    => Diff::fingerprint_key_id(),
				'found'  => (object) $found,
			),
			JSON_UNESCAPED_SLASHES | ( defined( 'JSON_INVALID_UTF8_SUBSTITUTE' ) ? JSON_INVALID_UTF8_SUBSTITUTE : 0 )
		);
		if ( ! is_string( $head ) || false !== strpos( $head, "\n" ) ) {
			return null;
		}
		return self::REDACTED_MAGIC . $head . "\n" . $text;
	}

	/**
	 * An existing copy is needed again: its time is refreshed (prune() keeps
	 * it another GRACE period), and a plain copy of a file that holds secrets,
	 * made by an earlier version of the plugin, is replaced by a redacted one.
	 *
	 * @param string $sha  sha256.
	 * @param string $name File name or path ('' when unknown).
	 */
	private function refresh( $sha, $name = '' ) {
		Fs::touch( $this->path_for( $sha ) );
		if ( '' !== (string) $name && self::is_secret_name( $name ) ) {
			$this->harden( $sha, $name );
		}
	}

	/**
	 * Replaces a plain copy of a file that holds secrets with a redacted one.
	 *
	 * @param string $sha  sha256.
	 * @param string $name File name or path.
	 * @return bool Whether a plain copy was replaced.
	 */
	private function harden( $sha, $name ) {
		$entry = $this->get_entry( $sha );
		if ( null === $entry || $entry['redacted'] ) {
			return false;
		}
		$payload = $this->payload( strtolower( (string) $sha ), $entry['text'], $name );
		if ( null === $payload ) {
			// Never keep the plain copy of a secret file.
			Fs::delete( $this->path_for( $sha ) );
			return true;
		}
		return $payload !== $entry['text'] && $this->write( $sha, $payload, true );
	}

	/**
	 * When a version was first stored (unix time, 0 when missing).
	 *
	 * @param string $sha sha256.
	 * @return int
	 */
	public function stored_at( $sha ) {
		if ( ! self::is_sha( $sha ) ) {
			return 0;
		}
		$time = @filemtime( $this->path_for( $sha ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return false === $time ? 0 : (int) $time;
	}

	/**
	 * Writes one compressed copy atomically (temp file + rename).
	 *
	 * @param string $sha     sha256 the copy stands for.
	 * @param string $content What to store (payload()).
	 * @param bool   $replace Replace an existing copy.
	 * @return bool
	 */
	private function write( $sha, $content, $replace = false ) {
		$path = $this->path_for( $sha );
		if ( ! $replace && @is_file( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			Fs::touch( $path ); // needed again: keep it past the next prune().
			return true;
		}
		if ( ! $this->ensure_root() ) {
			return false;
		}
		$dir = dirname( $path );
		if ( ! @is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$gz = gzencode( $content, 6 );
		if ( false === $gz ) {
			return false;
		}
		$tmp = $dir . '/.' . substr( basename( $path, '.gz' ), 0, 12 ) . '-' . substr( md5( uniqid( 'wpcs', true ) ), 0, 8 ) . '.tmp';
		if ( false === @file_put_contents( $tmp, $gz ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
			Fs::delete( $tmp );
			return false;
		}
		Fs::chmod( $tmp, 0600 );
		if ( ! Fs::replace( $tmp, $path ) ) {
			if ( $replace && Fs::delete( $path ) && Fs::replace( $tmp, $path ) ) { // Windows does not rename over a file.
				return true;
			}
			Fs::delete( $tmp );
			return ! $replace && @is_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- written by another process meanwhile.
		}
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Paths and key                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Folder of this site's copies (no trailing slash): snapshots/, or
	 * snapshots/site-<blog id>/ for a site of a network other than the main one.
	 *
	 * @return string
	 */
	public function root() {
		$root = wpcybersec()->storage->path( self::DIR );
		if ( function_exists( 'is_multisite' ) && is_multisite() && ! is_main_site() ) {
			$root .= '/site-' . (int) get_current_blog_id();
		}
		return $root;
	}

	/**
	 * File name stem for a version (the keyed hash, not the sha256 itself).
	 *
	 * @param string $sha sha256.
	 * @return string 64 hex chars.
	 */
	public function name_for( $sha ) {
		return hash_hmac( 'sha256', strtolower( (string) $sha ), $this->key() );
	}

	/**
	 * @param string $sha sha256.
	 * @return string Absolute path of the copy.
	 */
	public function path_for( $sha ) {
		$name = $this->name_for( $sha );
		return $this->root() . '/' . substr( $name, 0, 2 ) . '/' . substr( $name, 2, 2 ) . '/' . $name . '.gz';
	}

	/**
	 * Random per-site key, created on first use.
	 *
	 * @return string
	 */
	private function key() {
		if ( null !== $this->key ) {
			return $this->key;
		}
		$key = get_option( self::KEY_OPTION, '' );
		if ( ! is_string( $key ) || ! preg_match( '/^[a-f0-9]{64}$/', $key ) ) {
			try {
				$key = bin2hex( random_bytes( 32 ) );
			} catch ( \Throwable $e ) {
				$key = hash( 'sha256', wp_generate_password( 64, true, true ) . uniqid( '', true ) );
			}
			if ( ! add_option( self::KEY_OPTION, $key, '', 'no' ) ) {
				// Another request created it first: use that one.
				wp_cache_delete( self::KEY_OPTION, 'options' );
				$stored = get_option( self::KEY_OPTION, '' );
				if ( is_string( $stored ) && preg_match( '/^[a-f0-9]{64}$/', $stored ) ) {
					$key = $stored;
				} else {
					update_option( self::KEY_OPTION, $key, false );
				}
			}
		}
		$this->key = $key;
		return $key;
	}

	/**
	 * Creates the folder and its deny files once per request.
	 *
	 * @return bool
	 */
	private function ensure_root() {
		if ( $this->ready ) {
			return true;
		}
		$storage = wpcybersec()->storage;
		if ( is_wp_error( $storage->ensure() ) ) {
			return false;
		}
		$root = $this->root();
		if ( ! @is_dir( $root ) && ! wp_mkdir_p( $root ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		$storage->protect( $root );
		if ( self::DIR !== basename( $root ) ) {
			$storage->protect( dirname( $root ) );
		}
		$this->ready = true;
		return true;
	}

	/* ------------------------------------------------------------------ */
	/* Backfill (copies of files trusted before copies were taken)         */
	/* ------------------------------------------------------------------ */

	/**
	 * Whether scans should also copy unchanged trusted files (once, after the
	 * feature was switched on or the size limit raised).
	 *
	 * @return bool
	 */
	public function needs_backfill() {
		list( $done ) = $this->backfill_state();
		return $this->enabled() && ! $done;
	}

	/**
	 * Generation of the backfill (raised by every reset). A scan remembers it
	 * when it starts and passes it to backfill_done().
	 *
	 * @return int
	 */
	public function backfill_generation() {
		list( , $generation ) = $this->backfill_state();
		return $generation;
	}

	/**
	 * A whole-site scan copied every trusted file. Ignored when the backfill
	 * was reset after that scan started (copies deleted, limit raised).
	 *
	 * @param int|null $generation backfill_generation() when the scan started (null: any).
	 * @return bool Whether it was marked done.
	 */
	public function backfill_done( $generation = null ) {
		wp_cache_delete( self::BACKFILL_OPTION, 'options' );
		list( , $current ) = $this->backfill_state();
		if ( null !== $generation && (int) $generation !== $current ) {
			return false;
		}
		update_option( self::BACKFILL_OPTION, 'done:' . $current, false );
		return true;
	}

	/**
	 * The next scan copies unchanged trusted files again.
	 */
	public function reset_backfill() {
		wp_cache_delete( self::BACKFILL_OPTION, 'options' );
		list( , $generation ) = $this->backfill_state();
		update_option( self::BACKFILL_OPTION, 'pending:' . ( $generation + 1 ), false );
	}

	/**
	 * @return array { 0: bool done, 1: int generation }
	 */
	private function backfill_state() {
		$value = get_option( self::BACKFILL_OPTION, '' );
		if ( is_string( $value ) && preg_match( '/^(done|pending):(\d{1,9})$/', $value, $m ) ) {
			return array( 'done' === $m[1], (int) $m[2] );
		}
		if ( 'done' === $value ) {
			// Copies from before site folders existed were shared by every site
			// of a network (each pruned the others' copies): a site other than
			// the main one copies its files again, into its own folder.
			return array( ! ( function_exists( 'is_multisite' ) && is_multisite() && ! is_main_site() ), 0 );
		}
		return array( false, 0 );
	}

	/* ------------------------------------------------------------------ */
	/* Housekeeping                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Number and total size of the stored copies (cached for an hour).
	 *
	 * @param bool $fresh Recount now.
	 * @return array { files: int, bytes: int }
	 */
	public function stats( $fresh = false ) {
		if ( ! $fresh ) {
			$cached = get_transient( self::STATS_TRANSIENT );
			if ( is_array( $cached ) && isset( $cached['files'], $cached['bytes'] ) ) {
				return array(
					'files' => (int) $cached['files'],
					'bytes' => (int) $cached['bytes'],
				);
			}
		}
		$stats = array(
			'files' => 0,
			'bytes' => 0,
		);
		foreach ( $this->copy_files() as $file ) {
			++$stats['files'];
			$size            = @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$stats['bytes'] += false === $size ? 0 : (int) $size;
			if ( $stats['files'] >= 500000 ) {
				break;
			}
		}
		set_transient( self::STATS_TRANSIENT, $stats, HOUR_IN_SECONDS );
		return $stats;
	}

	/**
	 * Deletes every stored copy. While copies are on, the next whole-site scan
	 * copies the trusted files again.
	 *
	 * @return int Files deleted.
	 */
	public function clear() {
		$root    = $this->root();
		$deleted = 0;
		if ( preg_match( '/^(?:' . self::DIR . '|site-\d+)$/', basename( $root ) ) && @is_dir( $root ) && ! is_link( $root ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			foreach ( $this->top_dirs( $root ) as $top ) {
				$deleted += $this->delete_tree( $root . '/' . $top );
			}
		}
		delete_transient( self::STATS_TRANSIENT );
		delete_option( self::CURSOR_OPTION );
		$this->reset_backfill();
		return $deleted;
	}

	/**
	 * Deletes copies no manifest row and no file/threat report refers to (its
	 * sha256, details.previous_sha256 or details.base_sha256). Runs daily from
	 * 'wpcybersec_maintenance'; a large store is walked over several runs.
	 *
	 * @param float $seconds   Time budget.
	 * @param int   $max_files Files to look at in this run.
	 * @return array { checked: int, deleted: int, complete: bool, hardened: int }
	 */
	public function prune( $seconds = self::PRUNE_SECONDS, $max_files = self::PRUNE_FILES ) {
		$result = array(
			'checked'  => 0,
			'deleted'  => 0,
			'complete' => true,
			'hardened' => 0,
		);
		$root = $this->root();
		if ( ! @is_dir( $root ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			delete_option( self::CURSOR_OPTION );
			return $result;
		}

		$deadline = microtime( true ) + max( 1.0, (float) $seconds );
		$secret   = array();
		$keep     = $this->referenced_names( $secret );
		$cursor   = (string) get_option( self::CURSOR_OPTION, '' );

		// Plain copies of wp-config.php and other secret files made by an
		// earlier version of the plugin are replaced with redacted ones.
		foreach ( array_slice( $secret, 0, self::HARDEN_PER_RUN, true ) as $sha => $name ) {
			if ( $this->harden( (string) $sha, $name ) ) {
				++$result['hardened'];
			}
		}
		$cutoff  = time() - self::GRACE;
		$tmp_cut = time() - HOUR_IN_SECONDS;

		foreach ( $this->top_dirs( $root ) as $top ) {
			if ( '' !== $cursor && strcmp( $top, $cursor ) <= 0 ) {
				continue;
			}
			foreach ( $this->top_dirs( $root . '/' . $top ) as $sub ) {
				$dir     = $root . '/' . $top . '/' . $sub;
				$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$left    = 0;
				foreach ( (array) $entries as $entry ) {
					if ( '.' === $entry || '..' === $entry || '' === (string) $entry ) {
						continue;
					}
					$file = $dir . '/' . $entry;
					++$result['checked'];
					$mtime = (int) @filemtime( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
					if ( '.tmp' === substr( $entry, -4 ) ) {
						if ( $mtime < $tmp_cut && Fs::delete( $file ) ) {
							continue;
						}
					} elseif ( preg_match( '/^([a-f0-9]{64})\.gz$/', $entry, $m ) && ! isset( $keep[ substr( $m[1], 0, 32 ) ] ) && $mtime < $cutoff ) {
						if ( Fs::delete( $file ) ) {
							++$result['deleted'];
							continue;
						}
					}
					++$left;
				}
				if ( 0 === $left ) {
					Fs::rmdir( $dir );
				}
			}
			Fs::rmdir( $root . '/' . $top ); // only succeeds when empty.
			$cursor = $top;
			if ( $result['checked'] >= $max_files || microtime( true ) >= $deadline ) {
				$result['complete'] = false;
				break;
			}
		}

		if ( $result['complete'] ) {
			delete_option( self::CURSOR_OPTION );
		} else {
			update_option( self::CURSOR_OPTION, $cursor, false );
		}
		if ( $result['deleted'] ) {
			delete_transient( self::STATS_TRANSIENT );
			wpcybersec()->logger->log(
				'snapshots_pruned',
				sprintf(
					/* translators: %s: number of files */
					_n( 'Deleted %s stored file copy that no report or trusted file needs any more.', 'Deleted %s stored file copies that no report or trusted file needs any more.', $result['deleted'], 'cybergate-security' ),
					number_format_i18n( $result['deleted'] )
				),
				$result
			);
		}
		return $result;
	}

	/**
	 * Name prefixes (32 hex chars of the keyed name) of every version still
	 * referenced by the manifest or by a file/threat report.
	 *
	 * @param array $secret Receives sha256 => file name of the versions of files that hold secrets.
	 * @return array prefix => true
	 */
	private function referenced_names( array &$secret = array() ) {
		global $wpdb;
		$keep = array();

		$table = Store::table( 'manifest' );
		$last  = '';
		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is Store::table(): $wpdb->prefix plus a fixed name.
			$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT path_hash, path, sha256 FROM {$table} WHERE path_hash > %s ORDER BY path_hash LIMIT 5000", $last ), ARRAY_A );
			foreach ( $rows as $row ) {
				$last = (string) $row['path_hash'];
				if ( self::is_sha( $row['sha256'] ) && self::is_diffable_name( (string) $row['path'] ) ) {
					$keep[ substr( $this->name_for( $row['sha256'] ), 0, 32 ) ] = true;
					if ( self::is_secret_name( (string) $row['path'] ) ) {
						$secret[ strtolower( (string) $row['sha256'] ) ] = basename( (string) $row['path'] );
					}
				}
			}
		} while ( count( $rows ) >= 5000 );

		$table   = Store::table( 'items' );
		$last_id = 0;
		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is Store::table(): $wpdb->prefix plus a fixed name.
			$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT id, path, sha256, details FROM {$table} WHERE id > %d AND type IN (%s, %s) ORDER BY id LIMIT 1000", $last_id, Store::TYPE_FILE, Store::TYPE_THREAT ), ARRAY_A );
			foreach ( $rows as $row ) {
				$last_id = (int) $row['id'];
				$shas    = array( (string) $row['sha256'] );
				$details = json_decode( (string) $row['details'], true );
				if ( is_array( $details ) ) {
					foreach ( array( 'previous_sha256', 'base_sha256' ) as $key ) {
						if ( ! empty( $details[ $key ] ) ) {
							$shas[] = (string) $details[ $key ];
						}
					}
				}
				$path = isset( $row['path'] ) ? (string) $row['path'] : '';
				foreach ( $shas as $sha ) {
					if ( self::is_sha( $sha ) ) {
						$keep[ substr( $this->name_for( $sha ), 0, 32 ) ] = true;
						if ( '' !== $path && self::is_secret_name( $path ) ) {
							$secret[ strtolower( $sha ) ] = basename( $path );
						}
					}
				}
			}
		} while ( count( $rows ) >= 1000 );

		return $keep;
	}

	/**
	 * Two-hex-digit folder names inside a folder, sorted.
	 *
	 * @param string $dir Folder.
	 * @return string[]
	 */
	private function top_dirs( $dir ) {
		$out = array();
		foreach ( (array) @scandir( $dir ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( preg_match( '/^[a-f0-9]{2}$/', (string) $entry ) && @is_dir( $dir . '/' . $entry ) && ! is_link( $dir . '/' . $entry ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$out[] = (string) $entry;
			}
		}
		sort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * Every stored copy (generator over the two folder levels).
	 *
	 * @return \Generator|string[]
	 */
	private function copy_files() {
		$root = $this->root();
		if ( ! @is_dir( $root ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return;
		}
		foreach ( $this->top_dirs( $root ) as $top ) {
			foreach ( $this->top_dirs( $root . '/' . $top ) as $sub ) {
				$dir = $root . '/' . $top . '/' . $sub;
				foreach ( (array) @scandir( $dir ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					if ( '.gz' === substr( (string) $entry, -3 ) ) {
						yield $dir . '/' . $entry;
					}
				}
			}
		}
	}

	/**
	 * Recursive delete that never follows symlinks.
	 *
	 * @param string $path File or folder.
	 * @return int Files deleted.
	 */
	private function delete_tree( $path ) {
		if ( is_link( $path ) || @is_file( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return Fs::delete( $path ) ? 1 : 0;
		}
		if ( ! @is_dir( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return 0;
		}
		$count = 0;
		foreach ( (array) @scandir( $path ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( '.' === $entry || '..' === $entry || '' === (string) $entry ) {
				continue;
			}
			$count += $this->delete_tree( $path . '/' . $entry );
		}
		Fs::rmdir( $path );
		return $count;
	}
}
