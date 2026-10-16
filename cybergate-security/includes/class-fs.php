<?php
/**
 * Small filesystem helper on top of the WordPress filesystem API.
 *
 * The plugin works on local files only (quarantine, data folder, .htaccess,
 * .user.ini, wp-config.php backups), always as the PHP user, so it uses
 * WP_Filesystem_Direct directly instead of WP_Filesystem(), which could pick
 * an FTP or SSH transport and ask for credentials in the middle of a scan.
 *
 * Every method returns false (or does nothing) on failure and never emits a
 * PHP warning: callers decide what a failure means.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Static wrappers so call sites stay one readable line.
 */
final class Fs {

	/** @var \WP_Filesystem_Direct|null */
	private static $direct = null;

	/**
	 * The shared direct filesystem instance.
	 *
	 * @return \WP_Filesystem_Direct
	 */
	public static function direct() {
		if ( null === self::$direct ) {
			if ( ! class_exists( 'WP_Filesystem_Direct', false ) ) {
				require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
				require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
			}
			self::$direct = new \WP_Filesystem_Direct( null );
		}
		return self::$direct;
	}

	/**
	 * Deletes a file or a symlink (never a folder).
	 *
	 * @param string $file Path.
	 * @return bool True when nothing is left at $file afterwards.
	 */
	public static function delete( $file ) {
		$file = (string) $file;
		if ( '' === $file ) {
			return false;
		}
		wp_delete_file( $file );
		return ! @file_exists( $file ) && ! @is_link( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Removes an empty folder. Files and symlinks are left alone, like rmdir() does.
	 *
	 * @param string $dir Folder.
	 * @return bool
	 */
	public static function rmdir( $dir ) {
		$dir = (string) $dir;
		if ( '' === $dir || @is_link( $dir ) || ! @is_dir( $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		return self::direct()->rmdir( $dir, false );
	}

	/**
	 * Creates a folder (and missing parents).
	 *
	 * @param string   $dir  Folder.
	 * @param int|null $mode Permissions for $dir itself, or null for the WordPress default.
	 * @return bool
	 */
	public static function mkdir( $dir, $mode = null ) {
		if ( ! wp_mkdir_p( (string) $dir ) ) {
			return false;
		}
		if ( null !== $mode ) {
			self::chmod( $dir, $mode );
		}
		return true;
	}

	/**
	 * Changes permissions of one file or folder (not recursive).
	 *
	 * @param string $path Path.
	 * @param int    $mode Octal mode, for example 0600. 0 (for example a failed fileperms()) changes nothing.
	 * @return bool
	 */
	public static function chmod( $path, $mode ) {
		$mode = (int) $mode;
		if ( $mode <= 0 ) {
			return false; // WP_Filesystem would fall back to FS_CHMOD_FILE, which is only defined after WP_Filesystem().
		}
		return (bool) @self::direct()->chmod( (string) $path, $mode, false ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * @param string $path File or folder.
	 * @return bool
	 */
	public static function is_writable( $path ) {
		return self::direct()->is_writable( (string) $path );
	}

	/**
	 * Sets the modification time (and the access time to the same value, like touch( $file, $time ) does).
	 *
	 * @param string $file Path.
	 * @param int    $time Unix time, 0 for now.
	 * @return bool
	 */
	public static function touch( $file, $time = 0 ) {
		$time = $time ? (int) $time : time();
		return (bool) @self::direct()->touch( (string) $file, $time, $time ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Moves a file to a path that does not exist yet: rename, or copy and
	 * delete across disks. Never overwrites. Fails (and leaves no copy behind)
	 * when the source cannot be removed, so a move never ends with two files.
	 *
	 * @param string $from Source.
	 * @param string $to   Destination.
	 * @return bool
	 */
	public static function move( $from, $to ) {
		$from = (string) $from;
		$to   = (string) $to;
		if ( ! @self::direct()->move( $from, $to, false ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		if ( @file_exists( $from ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			self::delete( $to ); // Copied, but the original could not be deleted.
			return false;
		}
		return true;
	}

	/**
	 * Atomically replaces $target with $tmp (same folder): readers see either
	 * the old or the new file, never a missing or half written one.
	 *
	 * @param string $tmp    Fully written temporary file next to $target.
	 * @param string $target File to replace (may not exist yet).
	 * @return bool
	 */
	public static function replace( $tmp, $target ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename, WordPress.PHP.NoSilencedErrors -- atomic replace: WP_Filesystem::move() deletes the target first, which leaves a moment without .htaccess, .user.ini or wp-config.php.
		return @rename( (string) $tmp, (string) $target );
	}
}
