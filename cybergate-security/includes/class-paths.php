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
 */
class Paths {

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
	 * @param string $abs Absolute path.
	 * @return string Path relative to the scan root, or the normalized absolute path when outside it.
	 */
	public static function rel( $abs ) {
		$abs  = wp_normalize_path( $abs );
		$root = self::scan_root();
		if ( 0 === strpos( $abs, $root ) ) {
			return ltrim( substr( $abs, strlen( $root ) ), '/' );
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
		static $data_rel = null;
		if ( null === $data_rel ) {
			$data_rel = trailingslashit( self::rel( wpcybersec()->storage->data_dir() ) );
		}
		$rel_dir = rtrim( $rel, '/' ) . '/';
		if ( 0 === strpos( $rel_dir, $data_rel ) ) {
			return true;
		}

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
