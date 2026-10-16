<?php
/**
 * WP Cyber Security - standalone cron runner.
 *
 * Runs a scan to completion without WP-CLI, for real system cron:
 *
 *   * / 15 * * * *  /usr/bin/php /path/to/wp-content/plugins/wp-cyber-security/bin/cron.php >/dev/null 2>&1
 *
 * Usage:
 *   php bin/cron.php [--full | --baseline] [--no-malware] [--wp=/abs/path/to/wordpress]
 *
 * Options:
 *   --full        Full malware scan (re-scans unchanged files too).
 *   --baseline    Rebuild the trusted baseline.
 *   --no-malware  Skip malware signatures (file change detection only).
 *   --wp=PATH     WordPress root (where wp-load.php lives). Default: walk up
 *                 from this file, then try the current directory.
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

error_reporting( E_ALL & ~E_DEPRECATED & ~E_NOTICE );

/**
 * Parses CLI arguments.
 *
 * @param array $argv Arguments.
 * @return array
 */
function wpcybersec_cron_args( array $argv ) {
	$opts = array(
		'mode'    => 'incremental',
		'malware' => true,
		'wp'      => '',
		'quiet'   => false,
	);
	foreach ( array_slice( $argv, 1 ) as $arg ) {
		if ( '--full' === $arg ) {
			$opts['mode'] = 'full';
		} elseif ( '--baseline' === $arg ) {
			$opts['mode'] = 'baseline';
		} elseif ( '--no-malware' === $arg ) {
			$opts['malware'] = false;
		} elseif ( '--quiet' === $arg || '-q' === $arg ) {
			$opts['quiet'] = true;
		} elseif ( 0 === strpos( $arg, '--wp=' ) ) {
			$opts['wp'] = substr( $arg, 5 );
		} elseif ( '--help' === $arg || '-h' === $arg ) {
			echo "Usage: php bin/cron.php [--full|--baseline] [--no-malware] [--wp=/abs/path]\n";
			exit( 0 );
		}
	}
	return $opts;
}

/**
 * Finds wp-load.php: an explicit --wp path, then walking up from this file,
 * then walking up from the current working directory.
 *
 * @param string $explicit --wp value.
 * @return string|false Absolute path to wp-load.php.
 */
function wpcybersec_find_wp_load( $explicit ) {
	if ( '' !== $explicit ) {
		$explicit = rtrim( str_replace( '\\', '/', $explicit ), '/' );
		foreach ( array( $explicit . '/wp-load.php', $explicit ) as $candidate ) {
			if ( is_file( $candidate ) && 'wp-load.php' === basename( $candidate ) ) {
				return $candidate;
			}
		}
		fwrite( STDERR, "wp-load.php not found under --wp=$explicit\n" );
		exit( 1 );
	}

	$starts = array( __DIR__, getcwd() ? getcwd() : __DIR__ );
	foreach ( $starts as $start ) {
		$dir = str_replace( '\\', '/', $start );
		for ( $i = 0; $i < 12 && '' !== $dir && '/' !== $dir; $i++ ) {
			if ( is_file( $dir . '/wp-load.php' ) ) {
				return $dir . '/wp-load.php';
			}
			$parent = dirname( $dir );
			if ( $parent === $dir ) {
				break;
			}
			$dir = $parent;
		}
	}
	return false;
}

$options  = wpcybersec_cron_args( $argv );
$wp_load  = wpcybersec_find_wp_load( $options['wp'] );

if ( ! $wp_load ) {
	fwrite( STDERR, "Could not locate wp-load.php. Pass --wp=/path/to/wordpress.\n" );
	exit( 1 );
}

// Tell WordPress not to load the theme; this is a back-end task.
if ( ! defined( 'WP_USE_THEMES' ) ) {
	define( 'WP_USE_THEMES', false );
}
if ( ! defined( 'DOING_CRON' ) ) {
	define( 'DOING_CRON', true );
}
// Minimal server vars so WordPress boots cleanly from the command line.
$_SERVER['HTTP_HOST']   = isset( $_SERVER['HTTP_HOST'] ) ? $_SERVER['HTTP_HOST'] : 'localhost';
$_SERVER['REQUEST_URI'] = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '/';
$_SERVER['REQUEST_METHOD'] = 'GET';

require $wp_load;

if ( ! function_exists( 'wpcybersec' ) ) {
	fwrite( STDERR, "WP Cyber Security is not active on this site.\n" );
	exit( 1 );
}

$plugin = wpcybersec();
if ( ! $plugin->is_booted() ) {
	$plugin->boot();
}

$job    = $plugin->scan_job;
$status = $job->status();

if ( in_array( $status['state'], array( 'enumerating', 'processing', 'finishing' ), true ) ) {
	// Another runner (or the cron chain) is active: continue it instead of refusing.
	// Ticks are serialized by a lock, so this waits while another runner works.
	if ( ! $options['quiet'] ) {
		fwrite( STDOUT, "A scan is already running; continuing it.\n" );
	}
} else {
	$id = $job->start(
		array(
			'mode'    => $options['mode'],
			'malware' => $options['malware'],
			'trigger' => 'cli',
			'force'   => true,
		)
	);
	if ( is_wp_error( $id ) ) {
		fwrite( STDERR, 'Could not start the scan: ' . $id->get_error_message() . "\n" );
		exit( 1 );
	}
}

$last_line = '';
$progress  = $options['quiet'] ? null : static function ( $s ) use ( &$last_line ) {
	$line = sprintf(
		'[%s] %s - %d/%d files, %d new, %d modified, %d threats',
		$s['state'],
		isset( $s['percent'] ) ? $s['percent'] . '%' : '',
		$s['files_done'],
		$s['files_total'],
		$s['new'],
		$s['modified'],
		$s['threats']
	);
	if ( $line !== $last_line ) {
		fwrite( STDOUT, $line . "\n" );
		$last_line = $line;
	}
};

$final = $job->run_to_completion( $progress );

// Lets the settings offer "switch off visitor-triggered cron" once real cron is proven to run.
update_option( 'wpcybersec_cli_cron_at', time(), false );

$summary = sprintf(
	"WP Cyber Security %s scan %s: %d files checked, %d new, %d modified, %d deleted, %d threats, %d quarantined, %d skipped.\n",
	$final['mode'] ? $final['mode'] : $options['mode'],
	$final['state'],
	$final['files_done'],
	$final['new'],
	$final['modified'],
	$final['deleted'],
	$final['threats'],
	$final['quarantined'],
	$final['skipped']
);
fwrite( STDOUT, $summary );
if ( 'failed' === $final['state'] && '' !== (string) $final['message'] ) {
	fwrite( STDERR, 'Reason: ' . $final['message'] . "\n" );
}

// Non-zero exit when the scan failed, so cron wrappers can alert.
exit( 'failed' === $final['state'] ? 1 : 0 );
