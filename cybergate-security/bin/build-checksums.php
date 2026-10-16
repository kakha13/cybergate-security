<?php
/**
 * CyberGate Security - writes checksums.json for the plugin's own files.
 *
 * Run it after every change to the plugin and before every release:
 *
 *   php bin/build-checksums.php
 *
 * The scanner verifies files inside the plugin folder against this list
 * (Scanner::verify_details(), source "self"): a listed file with the same
 * sha256 is trusted without a signature scan (the signature file holds the
 * malware patterns as data and would otherwise flag itself), a listed file that
 * differs is reported as a tampered security plugin, and a file that is not
 * listed is treated like any unknown file.
 *
 * Output: <plugin>/checksums.json =
 *   { "version": "<plugin version>", "files": { "<path inside the plugin>": "<sha256>", ... } }
 * Every file is listed except checksums.json itself, .DS_Store files and
 * version control folders (.git, .svn, .hg). Symlinked folders are not followed.
 *
 * Refuses to run over the web.
 *
 * @package WPCyberSecurity
 */

// This file is a CLI entry point, not a plugin include: no ABSPATH guard.

if ( 'cli' !== PHP_SAPI ) {
	http_response_code( 403 );
	header( 'Content-Type: text/plain; charset=utf-8' );
	echo "This script can only be run from the command line.\n";
	exit( 1 );
}

$wpcybersec_dir = str_replace( '\\', '/', dirname( __DIR__ ) );
// --dir=PATH hashes another copy of the plugin (the release build stages one).
foreach ( array_slice( (array) $argv, 1 ) as $wpcybersec_arg ) {
	if ( 0 === strpos( $wpcybersec_arg, '--dir=' ) ) {
		$wpcybersec_real = realpath( substr( $wpcybersec_arg, 6 ) );
		if ( false === $wpcybersec_real || ! is_file( $wpcybersec_real . '/cybergate-security.php' ) ) {
			fwrite( STDERR, "Not a plugin folder: " . substr( $wpcybersec_arg, 6 ) . "\n" );
			exit( 1 );
		}
		$wpcybersec_dir = str_replace( '\\', '/', $wpcybersec_real );
	}
}
$wpcybersec_output = $wpcybersec_dir . '/checksums.json';

/**
 * Plugin version: WPCYBERSEC_VERSION when loaded inside WordPress, otherwise
 * the "Version:" header of the main plugin file.
 *
 * @param string $dir Plugin folder.
 * @return string
 */
function wpcybersec_checksums_version( $dir ) {
	if ( defined( 'WPCYBERSEC_VERSION' ) ) {
		return (string) WPCYBERSEC_VERSION;
	}
	$head = @file_get_contents( $dir . '/cybergate-security.php', false, null, 0, 8192 ); // phpcs:ignore
	if ( is_string( $head ) && preg_match( '~^[ \t/*#@]*Version:[ \t]*([^\s]+)~mi', $head, $m ) ) {
		return $m[1];
	}
	return '';
}

/**
 * Every file under $dir, relative paths with forward slashes.
 *
 * @param string $dir Plugin folder.
 * @return string[]
 */
function wpcybersec_checksums_files( $dir ) {
	$skip_dirs = array( '.git', '.svn', '.hg' );
	$files     = array();
	$stack     = array( '' );
	while ( $stack ) {
		$rel_dir = array_pop( $stack );
		$abs_dir = '' === $rel_dir ? $dir : $dir . '/' . $rel_dir;
		$entries = @scandir( $abs_dir ); // phpcs:ignore
		if ( false === $entries ) {
			fwrite( STDERR, "Cannot read folder: $abs_dir\n" );
			exit( 1 );
		}
		foreach ( $entries as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$rel = '' === $rel_dir ? $entry : $rel_dir . '/' . $entry;
			$abs = $dir . '/' . $rel;
			if ( is_dir( $abs ) ) {
				if ( ! is_link( $abs ) && ! in_array( $entry, $skip_dirs, true ) ) {
					$stack[] = $rel;
				}
				continue;
			}
			if ( ! is_file( $abs ) || '.DS_Store' === $entry || 'checksums.json' === $rel ) {
				continue;
			}
			$files[] = $rel;
		}
	}
	sort( $files, SORT_STRING );
	return $files;
}

$wpcybersec_map = array();
foreach ( wpcybersec_checksums_files( $wpcybersec_dir ) as $wpcybersec_rel ) {
	$wpcybersec_sha = hash_file( 'sha256', $wpcybersec_dir . '/' . $wpcybersec_rel );
	if ( ! is_string( $wpcybersec_sha ) ) {
		fwrite( STDERR, "Cannot read file: $wpcybersec_rel\n" );
		exit( 1 );
	}
	$wpcybersec_map[ $wpcybersec_rel ] = $wpcybersec_sha;
}

$wpcybersec_json = json_encode(
	array(
		'version' => wpcybersec_checksums_version( $wpcybersec_dir ),
		'files'   => (object) $wpcybersec_map,
	),
	JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
);
if ( ! is_string( $wpcybersec_json ) ) {
	fwrite( STDERR, 'Could not encode the checksum list: ' . json_last_error_msg() . "\n" );
	exit( 1 );
}

// Write through a temp file so the scanner never reads half a list.
$wpcybersec_tmp = $wpcybersec_output . '.' . getmypid() . '.tmp';
if ( false === file_put_contents( $wpcybersec_tmp, $wpcybersec_json . "\n" ) || ! rename( $wpcybersec_tmp, $wpcybersec_output ) ) { // phpcs:ignore
	@unlink( $wpcybersec_tmp ); // phpcs:ignore
	fwrite( STDERR, "Could not write $wpcybersec_output\n" );
	exit( 1 );
}

fwrite( STDOUT, sprintf( "Wrote %s (%d files).\n", $wpcybersec_output, count( $wpcybersec_map ) ) );
exit( 0 );
