<?php
/**
 * Path helpers shared by scanner, monitor and gates.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Relative paths are always relative to the scan root, use forward slashes,
 * and never start with a slash. Example: "wp-content/plugins/foo/foo.php".
 *
 * Scan set: a whole-site scan walks the scan root plus the WordPress folders
 * that lie outside it (scan_set()): ABSPATH, WP_CONTENT_DIR, WP_PLUGIN_DIR,
 * WPMU_PLUGIN_DIR and the uploads folder in full, the home folder (WordPress
 * in a subfolder, Bedrock's web/) at its top level only, and a wp-config.php
 * one folder above ABSPATH. Every folder is resolved with realpath() and
 * dropped when another folder of the set already covers it, so no file is
 * listed twice. Files outside the scan root keep their absolute path as the
 * manifest key (rel() returns it), which is stable and unique.
 */
class Paths {

	/** @var array|null scan_set() cache, keyed by the scan root it was built for. */
	private static $set = null;

	/** @var string|null Real data folder path with a trailing slash ('' when unknown). */
	private static $data_real = null;

	/**
	 * Folder the scanner walks, with a trailing slash.
	 *
	 * @return string
	 */
	public static function scan_root() {
		$settings = wpcybersec()->settings;
		$mode     = $settings->get( 'scan_root', 'abspath' );
		$root     = ABSPATH;

		if ( 'parent' === $mode ) {
			$parent = dirname( untrailingslashit( ABSPATH ) );
			if ( @is_readable( $parent ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$root = $parent;
			}
		} elseif ( 'custom' === $mode ) {
			$custom = $settings->get( 'scan_root_custom', '' );
			if ( $custom && @is_dir( $custom ) && @is_readable( $custom ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$root = $custom;
			}
		}

		$real = realpath( $root );
		return trailingslashit( wp_normalize_path( $real ? $real : $root ) );
	}

	/**
	 * Folders and files a whole-site scan covers. The first entry is always
	 * the scan root.
	 *
	 * Each entry: path (absolute, realpath, folders with a trailing slash),
	 * depth ('all' walks the folder, 'top' lists only its own files, 'file' is
	 * one file), kind (root | wordpress | content | plugins | mu-plugins |
	 * uploads | home | config) and alias (how files inside are named relative
	 * to the WordPress folder, for exclusions; '' for none).
	 *
	 * @return array[]
	 */
	public static function scan_set() {
		$root = self::scan_root();
		if ( is_array( self::$set ) && isset( self::$set[ $root ] ) ) {
			return self::$set[ $root ];
		}

		$set = array(
			array(
				'path'  => $root,
				'depth' => 'all',
				'kind'  => 'root',
				'alias' => '',
			),
		);

		// Candidates, most general first, so a folder inside another one of the
		// set is dropped (WP_PLUGIN_DIR inside WP_CONTENT_DIR, for example).
		$candidates = array(
			array( ABSPATH, 'wordpress', '' ),
			array( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : '', 'content', 'wp-content/' ),
			array( defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : '', 'plugins', 'wp-content/plugins/' ),
			array( defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '', 'mu-plugins', 'wp-content/mu-plugins/' ),
			array( self::uploads_basedir(), 'uploads', 'wp-content/uploads/' ),
		);
		$full = array( $root );
		foreach ( $candidates as $candidate ) {
			$dir = self::real_dir( $candidate[0] );
			if ( '' === $dir || self::covered( $dir, $full ) ) {
				continue;
			}
			$full[] = $dir;
			$set[]  = array(
				'path'  => $dir,
				'depth' => 'all',
				'kind'  => $candidate[1],
				'alias' => $candidate[2],
			);
		}

		// The home folder (index.php and .htaccess when WordPress lives in a
		// subfolder): only its own files, never its subfolders, so a parent web
		// root that also holds other sites is not walked.
		$home = self::home_dir();
		if ( '' !== $home && ! self::covered( $home, $full ) ) {
			$set[] = array(
				'path'  => $home,
				'depth' => 'top',
				'kind'  => 'home',
				'alias' => '',
			);
		}

		// wp-config.php one folder above ABSPATH (WordPress loads it from there).
		$config = class_exists( __NAMESPACE__ . '\\Config_Editor' ) ? Config_Editor::path() : '';
		if ( '' !== $config ) {
			$real   = realpath( $config );
			$config = wp_normalize_path( $real ? $real : $config );
			$tops   = array();
			foreach ( $set as $entry ) {
				if ( 'top' === $entry['depth'] ) {
					$tops[] = $entry['path'];
				}
			}
			if ( ! self::covered( $config, $full ) && ! in_array( trailingslashit( wp_normalize_path( dirname( $config ) ) ), $tops, true ) ) {
				$set[] = array(
					'path'  => $config,
					'depth' => 'file',
					'kind'  => 'config',
					'alias' => '',
				);
			}
		}

		/**
		 * Filters the folders and files a whole-site scan covers. Entries must
		 * keep the shape described in Paths::scan_set(); the first one (the scan
		 * root) must stay first.
		 *
		 * @param array[] $set  Scan set.
		 * @param string  $root Scan root.
		 */
		$filtered = function_exists( 'apply_filters' ) ? apply_filters( 'wpcybersec_scan_set', $set, $root ) : $set;
		if ( is_array( $filtered ) && isset( $filtered[0]['path'] ) && $filtered[0]['path'] === $root ) {
			$set = array_values( $filtered );
		}

		if ( ! is_array( self::$set ) ) {
			self::$set = array();
		}
		self::$set[ $root ] = $set;
		return $set;
	}

	/**
	 * Entries of scan_set() other than the scan root.
	 *
	 * @return array[]
	 */
	public static function extra_roots() {
		return array_slice( self::scan_set(), 1 );
	}

	/**
	 * Drops the cached scan set (tests, settings changes in the same request).
	 */
	public static function reset() {
		self::$set       = null;
		self::$data_real = null;
	}

	/**
	 * Whether a file or folder is covered by a whole-site scan.
	 *
	 * @param string $abs Absolute path (resolved or not).
	 * @return bool
	 */
	public static function in_scope( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		if ( '' === $abs ) {
			return false;
		}
		$real = realpath( $abs );
		$abs  = $real ? wp_normalize_path( $real ) : $abs;
		return '' !== self::scope_entry( $abs );
	}

	/**
	 * Whether a folder lies inside a fully walked folder of the scan set (a
	 * folder update rebaselines and path-limited scans may use).
	 *
	 * @param string $abs_dir Absolute folder (realpath).
	 * @return bool
	 */
	public static function in_full_scope( $abs_dir ) {
		$dir = trailingslashit( wp_normalize_path( (string) $abs_dir ) );
		foreach ( self::scan_set() as $entry ) {
			if ( 'all' === $entry['depth'] && 0 === strpos( $dir, $entry['path'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Kind of the scan set entry that covers a resolved path ('' when none).
	 *
	 * @param string $abs Absolute resolved path.
	 * @return string
	 */
	public static function scope_entry( $abs ) {
		$abs = wp_normalize_path( (string) $abs );
		foreach ( self::scan_set() as $entry ) {
			if ( 'all' === $entry['depth'] && ( 0 === strpos( $abs, $entry['path'] ) || trailingslashit( $abs ) === $entry['path'] ) ) {
				return $entry['kind'];
			}
			if ( 'top' === $entry['depth'] && trailingslashit( wp_normalize_path( dirname( $abs ) ) ) === $entry['path'] ) {
				return $entry['kind'];
			}
			if ( 'file' === $entry['depth'] && $abs === $entry['path'] ) {
				return $entry['kind'];
			}
		}
		return '';
	}

	/**
	 * WordPress folders that lie outside the configured scan root and are
	 * scanned as well (for the settings and dashboard note).
	 *
	 * @return array[] { path, kind, depth }
	 */
	public static function outside_root() {
		$out = array();
		foreach ( self::extra_roots() as $entry ) {
			$out[] = array(
				'path'  => untrailingslashit( $entry['path'] ),
				'kind'  => $entry['kind'],
				'depth' => $entry['depth'],
			);
		}
		return $out;
	}

	/**
	 * Name of a file outside the scan root relative to the WordPress folder
	 * (WP_CONTENT_DIR/cache/x.php gives "wp-content/cache/x.php"), '' when
	 * the file is not in a folder of the scan set that has such a name.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	public static function alias( $abs ) {
		$abs  = wp_normalize_path( (string) $abs );
		$best = '';
		$len  = 0;
		foreach ( self::extra_roots() as $entry ) {
			if ( 'all' !== $entry['depth'] || 0 !== strpos( $abs, $entry['path'] ) || strlen( $entry['path'] ) <= $len ) {
				continue;
			}
			if ( '' === $entry['alias'] && 'wordpress' !== $entry['kind'] ) {
				continue;
			}
			$len  = strlen( $entry['path'] );
			$best = $entry['alias'] . substr( $abs, $len );
		}
		return $best;
	}

	/**
	 * @param string $dir Folder (may be '' or missing).
	 * @return string Real folder with a trailing slash, '' when it is not a readable folder.
	 */
	private static function real_dir( $dir ) {
		$dir = (string) $dir;
		if ( '' === $dir || ! @is_dir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return '';
		}
		$real = realpath( $dir );
		return trailingslashit( wp_normalize_path( $real ? $real : $dir ) );
	}

	/**
	 * @param string   $path  Resolved path (folders with a trailing slash).
	 * @param string[] $roots Fully walked folders with a trailing slash.
	 * @return bool Whether one of the folders contains the path (or is it).
	 */
	private static function covered( $path, array $roots ) {
		foreach ( $roots as $root ) {
			if ( 0 === strpos( $path, $root ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Uploads base folder of this site ('' when unknown).
	 *
	 * @return string
	 */
	private static function uploads_basedir() {
		if ( ! function_exists( 'wp_upload_dir' ) ) {
			return '';
		}
		$dirs = wp_upload_dir( null, false );
		return ! empty( $dirs['basedir'] ) ? (string) $dirs['basedir'] : '';
	}

	/**
	 * Folder that serves the site's front page when it is not ABSPATH
	 * (WordPress in a subfolder, Bedrock's web/). Worked out from the home and
	 * site URLs like get_home_path(), without $_SERVER (which is wrong under
	 * cron and the CLI), and confirmed by an index.php that loads
	 * wp-blog-header.php one folder above ABSPATH.
	 *
	 * @return string Real folder with a trailing slash, '' when it is ABSPATH or unknown.
	 */
	public static function home_dir() {
		$abspath = trailingslashit( wp_normalize_path( ABSPATH ) );
		$found   = '';
		if ( function_exists( 'get_option' ) ) {
			$home = (string) wp_parse_url( (string) get_option( 'home' ), PHP_URL_PATH );
			$site = (string) wp_parse_url( (string) get_option( 'siteurl' ), PHP_URL_PATH );
			$home = trim( $home, '/' );
			$site = trim( $site, '/' );
			if ( $site !== $home && ( '' === $home || 0 === strpos( $site . '/', $home . '/' ) ) ) {
				$sub  = trim( '' === $home ? $site : substr( $site, strlen( $home ) ), '/' );
				$tail = '/' . $sub . '/';
				if ( '' !== $sub && strlen( $abspath ) > strlen( $tail ) && strtolower( substr( $abspath, -strlen( $tail ) ) ) === strtolower( $tail ) ) {
					$found = substr( $abspath, 0, -strlen( $tail ) + 1 );
				}
			}
		}
		if ( '' === $found ) {
			$parent = trailingslashit( wp_normalize_path( dirname( untrailingslashit( $abspath ) ) ) );
			$index  = $parent . 'index.php';
			if ( $parent !== $abspath && @is_file( $index ) && @filesize( $index ) < 8192 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$code = (string) @file_get_contents( $index ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				if ( false !== strpos( $code, 'wp-blog-header.php' ) ) {
					$found = $parent;
				}
			}
		}
		$found = self::real_dir( $found );
		$real  = self::real_dir( $abspath );
		return $found === $real ? '' : $found;
	}

	/**
	 * @param string $abs Absolute path.
	 * @return string Path relative to the scan root, or the normalized absolute path when outside it.
	 */
	public static function rel( $abs ) {
		$abs  = wp_normalize_path( $abs );
		$root = self::scan_root();
		if ( 0 === strpos( $abs, $root ) ) {
			return ltrim( substr( $abs, strlen( $root ) ), '/' );
		}
		// The scan lists files by their real folder (a symlinked ABSPATH or
		// uploads folder), so a path given through a link gets the same key.
		// The file name itself is kept: a symlinked file is listed by its own name.
		if ( self::is_absolute( $abs ) && false === strpos( $abs, '/../' ) ) {
			$dir = realpath( dirname( $abs ) );
			if ( $dir ) {
				$real = trailingslashit( wp_normalize_path( $dir ) ) . basename( $abs );
				if ( 0 === strpos( $real, $root ) ) {
					return ltrim( substr( $real, strlen( $root ) ), '/' );
				}
				return $real;
			}
		}
		return $abs;
	}

	/**
	 * @param string $rel Relative (or absolute) path.
	 * @return string Absolute path.
	 */
	public static function abs( $rel ) {
		$rel = wp_normalize_path( $rel );
		if ( self::is_absolute( $rel ) ) {
			return $rel;
		}
		return self::scan_root() . ltrim( $rel, '/' );
	}

	/**
	 * @param string $path Path.
	 * @return bool
	 */
	public static function is_absolute( $path ) {
		return '' !== $path && ( '/' === $path[0] || preg_match( '#^[a-zA-Z]:/#', $path ) );
	}

	/**
	 * Manifest primary key for a relative path.
	 *
	 * @param string $rel Relative path.
	 * @return string 40 hex chars.
	 */
	public static function hash( $rel ) {
		return sha1( $rel );
	}

	/**
	 * Lowercase last extension. ".htaccess" gives "htaccess", "a.tar.gz" gives "gz".
	 *
	 * @param string $name File name or path.
	 * @return string
	 */
	public static function ext( $name ) {
		$base = basename( $name );
		$pos  = strrpos( $base, '.' );
		return false === $pos ? '' : strtolower( substr( $base, $pos + 1 ) );
	}

	/**
	 * True for server-executable files, including disguised names such as
	 * "shell.php.jpg" or "x.PHTML", and config files like .htaccess.
	 *
	 * @param string $name File name or path.
	 * @return bool
	 */
	public static function is_executable( $name ) {
		$settings = wpcybersec()->settings;
		$base     = strtolower( basename( $name ) );
		if ( in_array( $base, array_map( 'strtolower', (array) $settings->get( 'exec_filenames', array() ) ), true ) ) {
			return true;
		}
		$exts  = (array) $settings->get( 'exec_extensions', array() );
		$parts = explode( '.', $base );
		array_shift( $parts ); // Drop the name before the first dot.
		foreach ( $parts as $part ) {
			if ( in_array( $part, $exts, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a relative path is excluded from scanning. The plugin's own data
	 * directory is always excluded.
	 *
	 * @param string $rel Relative path (files or folders; folders may end with "/").
	 * @return bool
	 */
	public static function is_excluded( $rel ) {
		$rel     = wp_normalize_path( (string) $rel );
		$rel_dir = rtrim( $rel, '/' ) . '/';
		$data    = self::data_rel();
		if ( '' !== $data && 0 === strpos( $rel_dir, $data ) ) {
			return true;
		}
		if ( self::is_absolute( $rel ) ) {
			// A file outside the scan root: the exclusions are written relative to
			// the WordPress folder ("wp-content/cache/"), so they are also tested
			// against the name the file has there (WP_CONTENT_DIR files as
			// "wp-content/...", plugins as "wp-content/plugins/...").
			$alias = self::alias( $rel );
			if ( '' !== $alias && self::matches_exclusions( $alias ) ) {
				return true;
			}
		}
		return self::matches_exclusions( $rel );
	}

	/**
	 * The plugin's data folder as a relative path (scan root) with a trailing
	 * slash. Both sides are resolved with realpath(), so a data folder reached
	 * through a symlink (or given with "..") is still recognised.
	 *
	 * @return string
	 */
	private static function data_rel() {
		if ( null === self::$data_real ) {
			self::$data_real = '';
			$dir             = function_exists( 'wpcybersec' ) && wpcybersec()->storage ? (string) wpcybersec()->storage->data_dir() : '';
			if ( '' !== $dir ) {
				$real            = realpath( $dir );
				self::$data_real = trailingslashit( wp_normalize_path( $real ? $real : $dir ) );
			}
		}
		if ( '' === self::$data_real ) {
			return '';
		}
		return trailingslashit( self::rel( untrailingslashit( self::$data_real ) ) );
	}

	/**
	 * Whether a path matches one of the exclusion patterns.
	 *
	 * @param string $rel Relative path (or absolute for files outside the scan root).
	 * @return bool
	 */
	private static function matches_exclusions( $rel ) {
		$rel_dir = rtrim( $rel, '/' ) . '/';
		foreach ( (array) wpcybersec()->settings->get( 'exclusions', array() ) as $pattern ) {
			$pattern = ltrim( wp_normalize_path( trim( $pattern ) ), '/' );
			if ( '' === $pattern ) {
				continue;
			}
			if ( false !== strpos( $pattern, '*' ) || false !== strpos( $pattern, '?' ) ) {
				if ( fnmatch( $pattern, rtrim( $rel, '/' ) ) || fnmatch( $pattern, basename( rtrim( $rel, '/' ) ) ) ) {
					return true;
				}
				continue;
			}
			$pattern_dir = rtrim( $pattern, '/' ) . '/';
			if ( rtrim( $rel, '/' ) === rtrim( $pattern, '/' ) || 0 === strpos( $rel_dir, $pattern_dir ) ) {
				return true;
			}
			// A bare name ("error_log") matches that name in every folder.
			if ( false === strpos( $pattern, '/' ) && basename( rtrim( $rel, '/' ) ) === $pattern ) {
				return true;
			}
		}
		return false;
	}
}
