<?php
/**
 * WP Cyber Security - standalone cron runner.
 *
 * Runs a scan to completion without WP-CLI, for real system cron:
 *
 *   * / 15 * * * *  /usr/bin/php /path/to/wp-content/plugins/wp-cyber-security/bin/cron.php >/dev/null 2>&1
 *
 * Usage:
 *   php bin/cron.php [--full | --baseline] [--no-malware] [--isolated] [--wp=/abs/path/to/wordpress]
 *
 * Options:
 *   --full        Full malware scan (re-scans unchanged files too).
 *   --baseline    Rebuild the trusted baseline.
 *   --no-malware  Skip malware signatures (file change detection only).
 *   --isolated    Clean-room scan: other plugins and the theme are not loaded,
 *                 so a compromised one cannot hook into WordPress and hide
 *                 files from the scanner. Only for this process: nothing is
 *                 deactivated (see wpcybersec_cron_isolate()). mu-plugins and
 *                 drop-ins (db.php, object-cache.php, advanced-cache.php) still
 *                 load; they are listed so you can check them yourself.
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
		'quiet'    => false,
		'isolated' => false,
	);
	foreach ( array_slice( $argv, 1 ) as $arg ) {
		if ( '--full' === $arg ) {
			$opts['mode'] = 'full';
		} elseif ( '--baseline' === $arg ) {
			$opts['mode'] = 'baseline';
		} elseif ( '--no-malware' === $arg ) {
			$opts['malware'] = false;
		} elseif ( '--isolated' === $arg ) {
			$opts['isolated'] = true;
		} elseif ( '--quiet' === $arg || '-q' === $arg ) {
			$opts['quiet'] = true;
		} elseif ( 0 === strpos( $arg, '--wp=' ) ) {
			$opts['wp'] = substr( $arg, 5 );
		} elseif ( '--help' === $arg || '-h' === $arg ) {
			echo "Usage: php bin/cron.php [--full|--baseline] [--no-malware] [--isolated] [--wp=/abs/path]\n";
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

/**
 * Whether an active_plugins entry is this plugin (compared by real path, so a
 * look-alike "other-folder/wp-cyber-security.php" never counts).
 *
 * @param mixed  $entry     Entry of active_plugins (or a key of active_sitewide_plugins).
 * @param string $self_main Real path of this plugin's main file.
 * @return bool
 */
function wpcybersec_cron_is_self( $entry, $self_main ) {
	if ( ! is_string( $entry ) || '' === $entry || ! defined( 'WP_PLUGIN_DIR' ) || '' === $self_main ) {
		return false;
	}
	$real = realpath( WP_PLUGIN_DIR . '/' . $entry );
	return false !== $real && $real === $self_main;
}

/**
 * Clean-room mode, set up before wp-load.php: pre-registers filters through
 * the $wp_filter global (WordPress turns them into WP_Hook objects with
 * WP_Hook::build_preinitialized_hooks() when plugin.php loads), so that
 *
 *   - option_active_plugins and site_option_active_sitewide_plugins return
 *     only this plugin: no other plugin file is included;
 *   - template_directory and stylesheet_directory point to a folder without
 *     functions.php: wp-settings.php includes a theme's functions.php only when
 *     the file exists in those folders, so no theme code runs;
 *   - writes of those options are refused for this process, so nothing ever
 *     saves the filtered lists (no plugin or theme is deactivated).
 *
 * mu-plugins and drop-ins cannot be skipped this way; main code lists them.
 */
function wpcybersec_cron_isolate() {
	global $wp_filter;
	if ( ! isset( $wp_filter ) || ! is_array( $wp_filter ) ) {
		$wp_filter = array(); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	}
	$self_main = (string) realpath( dirname( __DIR__ ) . '/wp-cyber-security.php' );
	$no_theme  = __DIR__ . '/isolated-no-theme'; // Does not exist: no functions.php to include.

	$only_self = static function ( $plugins ) use ( $self_main ) {
		$out = array();
		foreach ( (array) $plugins as $plugin ) {
			if ( wpcybersec_cron_is_self( $plugin, $self_main ) ) {
				$out[] = $plugin;
			}
		}
		return $out;
	};
	$only_self_network = static function ( $plugins ) use ( $self_main ) {
		$out = array();
		foreach ( (array) $plugins as $plugin => $time ) {
			if ( wpcybersec_cron_is_self( $plugin, $self_main ) ) {
				$out[ $plugin ] = $time;
			}
		}
		return $out;
	};
	$theme_dir = static function () use ( $no_theme ) {
		return $no_theme;
	};
	$keep_old = static function ( $value, $old_value ) {
		unset( $value );
		return $old_value; // update_option() stops when the new value equals the old one.
	};

	$add = static function ( $hook, $callback, $args ) use ( &$wp_filter ) {
		$wp_filter[ $hook ][ PHP_INT_MAX ][] = array(
			'function'      => $callback,
			'accepted_args' => $args,
		);
	};
	$add( 'option_active_plugins', $only_self, 1 );
	$add( 'site_option_active_sitewide_plugins', $only_self_network, 1 );
	$add( 'template_directory', $theme_dir, 1 );
	$add( 'stylesheet_directory', $theme_dir, 1 );
	foreach ( array( 'pre_update_option_active_plugins', 'pre_update_site_option_active_sitewide_plugins', 'pre_update_option_template', 'pre_update_option_stylesheet' ) as $hook ) {
		$add( $hook, $keep_old, 2 );
	}
}

/**
 * Real paths of code an isolated run must not have included: every plugin
 * except this one (symlinked plugin folders resolved too) and every theme.
 *
 * @return string[] Included files that belong to another plugin or a theme.
 */
function wpcybersec_cron_foreign_code() {
	$self  = (string) realpath( dirname( __DIR__ ) );
	$roots = array();
	$dirs  = array( WP_PLUGIN_DIR );
	if ( function_exists( 'search_theme_directories' ) ) {
		foreach ( (array) search_theme_directories() as $theme ) {
			if ( isset( $theme['theme_root'] ) ) {
				$dirs[] = $theme['theme_root'];
			}
		}
	}
	$dirs[] = function_exists( 'get_theme_root' ) ? get_theme_root() : WP_CONTENT_DIR . '/themes';
	foreach ( array_unique( $dirs ) as $dir ) {
		$real = realpath( $dir );
		if ( ! $real ) {
			continue;
		}
		$roots[] = $real;
		foreach ( (array) @scandir( $real ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( '.' === $entry || '..' === $entry || '' === (string) $entry ) {
				continue;
			}
			$target = realpath( $real . '/' . $entry );
			if ( $target ) {
				$roots[] = $target; // Symlinked plugin or theme folders live elsewhere.
			}
		}
	}
	$foreign = array();
	foreach ( get_included_files() as $file ) {
		$file = (string) realpath( $file );
		if ( '' === $file || $file === $self || 0 === strpos( $file, $self . '/' ) ) {
			continue;
		}
		foreach ( $roots as $root ) {
			if ( $file === $root || 0 === strpos( $file, rtrim( $root, '/' ) . '/' ) ) {
				$foreign[] = $file; // This plugin's own files were skipped above.
				break;
			}
		}
	}
	return array_values( array_unique( $foreign ) );
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
if ( $options['isolated'] ) {
	fwrite( STDOUT, "Isolated scan: other plugins and the theme are not loaded.\n" );
	wpcybersec_cron_isolate();
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

if ( $options['isolated'] ) {
	// Proof that the isolation held, and what could not be isolated.
	$wpcybersec_foreign = wpcybersec_cron_foreign_code();
	if ( $wpcybersec_foreign ) {
		fwrite( STDERR, 'Isolation failed: code of other plugins or themes was loaded (' . count( $wpcybersec_foreign ) . " files), for example:\n" );
		foreach ( array_slice( $wpcybersec_foreign, 0, 10 ) as $wpcybersec_file ) {
			fwrite( STDERR, '  ' . $wpcybersec_file . "\n" );
		}
		fwrite( STDERR, "This usually means an mu-plugin or drop-in loads them. Check those first; the scan was not run.\n" );
		exit( 2 );
	}
	global $wpdb;
	$wpcybersec_stored = maybe_unserialize( $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", 'active_plugins' ) ) ); // phpcs:ignore WordPress.DB
	$wpcybersec_loaded = wp_get_active_and_valid_plugins();
	fwrite(
		STDOUT,
		sprintf(
			"Active plugins on this site: %d. Loaded for this scan: %d (%s). Code from other plugins or themes loaded: none.\n",
			is_array( $wpcybersec_stored ) ? count( array_unique( array_filter( $wpcybersec_stored, 'is_string' ) ) ) : 0,
			count( $wpcybersec_loaded ),
			implode( ', ', array_map( 'plugin_basename', $wpcybersec_loaded ) )
		)
	);
	$wpcybersec_mu = function_exists( 'wp_get_mu_plugins' ) ? wp_get_mu_plugins() : array();
	fwrite(
		STDOUT,
		sprintf( 'mu-plugins still load: %d found', count( $wpcybersec_mu ) )
		. ( $wpcybersec_mu ? ' (' . implode( ', ', array_map( 'basename', $wpcybersec_mu ) ) . '). They cannot be switched off for a scan; review them yourself.' : '.' ) . "\n"
	);
	$wpcybersec_dropins = array();
	foreach ( array( 'db.php' => true, 'object-cache.php' => true, 'advanced-cache.php' => defined( 'WP_CACHE' ) && WP_CACHE, 'sunrise.php' => is_multisite() && defined( 'SUNRISE' ) && SUNRISE ) as $wpcybersec_name => $wpcybersec_loads ) {
		if ( $wpcybersec_loads && is_file( WP_CONTENT_DIR . '/' . $wpcybersec_name ) ) {
			$wpcybersec_dropins[] = $wpcybersec_name;
		}
	}
	if ( $wpcybersec_dropins ) {
		fwrite( STDOUT, 'Drop-ins still load: ' . implode( ', ', $wpcybersec_dropins ) . ". Review them yourself.\n" );
	}
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
