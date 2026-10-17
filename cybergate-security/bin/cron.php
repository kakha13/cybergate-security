<?php
/**
 * CyberGate Security - standalone cron runner.
 *
 * Runs a scan to completion without WP-CLI, for real system cron:
 *
 *   * / 15 * * * *  /usr/bin/php /path/to/wp-content/plugins/cybergate-security/bin/cron.php >/dev/null 2>&1
 *
 * Usage:
 *   php bin/cron.php [--full | --baseline] [--no-malware] [--isolated] [--wp=/abs/path/to/wordpress] [--url=https://example.com/]
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
 *   --url=URL     Site address WordPress loads as. Needed on multisite when
 *                 wp-config.php does not define DOMAIN_CURRENT_SITE in a
 *                 plain define() line; without a matching address WordPress
 *                 stops while loading (reported, exit code 1).
 *
 * Runs with the CLI binary, or php-cgi started from a shell or cron (use
 * php-cgi -q to hide its HTTP headers). Refuses to run over the web.
 *
 * @package WPCyberSecurity
 */

// A command line entry point that loads WordPress itself, so ABSPATH is not
// defined yet: refuse to run over the web.
if ( ! defined( 'ABSPATH' ) ) {
	// php-cgi (cgi-fcgi) run from a shell or cron is fine; a web request carries REQUEST_METHOD or REMOTE_ADDR.
	$wpcybersec_shell_cgi = in_array( PHP_SAPI, array( 'cgi-fcgi', 'cgi' ), true ) && empty( $_SERVER['REQUEST_METHOD'] ) && empty( $_SERVER['REMOTE_ADDR'] ) && empty( $_SERVER['GATEWAY_INTERFACE'] );
	if ( 'cli' !== PHP_SAPI && ! $wpcybersec_shell_cgi ) {
		http_response_code( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo "This script can only be run from the command line.\n";
		exit( 1 );
	}
}

// Keeps cron mail readable: deprecation notices of other plugins are not scan results.
error_reporting( E_ALL & ~E_DEPRECATED & ~E_NOTICE ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.prevent_path_disclosure_error_reporting, PluginCheck.CodeAnalysis.PHPErrorReporting.DirectErrorReportingCall -- command line only (checked above), never a web request.

// php-cgi does not define the CLI stream constants.
if ( ! defined( 'STDOUT' ) ) {
	define( 'STDOUT', fopen( 'php://stdout', 'w' ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- command line output stream.
}
if ( ! defined( 'STDERR' ) ) {
	define( 'STDERR', fopen( 'php://stderr', 'w' ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- command line error stream.
}

/**
 * Writes a line to standard output or standard error.
 *
 * @param string   $text   Text, including the line break.
 * @param resource $stream STDOUT or STDERR.
 */
function wpcybersec_cron_print( $text, $stream = STDOUT ) {
	fwrite( $stream, $text ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- command line output, not a file.
}

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
		'url'      => '',
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
		} elseif ( 0 === strpos( $arg, '--url=' ) ) {
			$opts['url'] = substr( $arg, 6 );
		} elseif ( '--help' === $arg || '-h' === $arg ) {
			echo "Usage: php bin/cron.php [--full|--baseline] [--no-malware] [--isolated] [--wp=/abs/path] [--url=https://example.com/]\n";
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
		wpcybersec_cron_print( "wp-load.php not found under --wp=$explicit\n", STDERR );
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
 * look-alike "other-folder/cybergate-security.php" never counts).
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
	$self_main = (string) realpath( dirname( __DIR__ ) . '/cybergate-security.php' );
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

/**
 * Request host and path for WordPress: --url, else the network's main site
 * from wp-config.php on multisite (DOMAIN_CURRENT_SITE / PATH_CURRENT_SITE),
 * else localhost. Without a matching host, multisite stops while loading
 * (no site found) before any scan runs.
 *
 * @param string $url     --url value.
 * @param string $wp_load Path to wp-load.php.
 * @return array { host, path, https }
 */
function wpcybersec_cron_target( $url, $wp_load ) {
	if ( '' !== $url ) {
		if ( false === strpos( $url, '://' ) ) {
			$url = 'http://' . $url;
		}
		$parts = parse_url( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- WordPress is not loaded yet.
		if ( is_array( $parts ) && ! empty( $parts['host'] ) ) {
			return array(
				'host'  => $parts['host'] . ( ! empty( $parts['port'] ) ? ':' . (int) $parts['port'] : '' ),
				'path'  => isset( $parts['path'] ) && '' !== $parts['path'] ? $parts['path'] : '/',
				'https' => isset( $parts['scheme'] ) && 'https' === strtolower( $parts['scheme'] ),
			);
		}
		wpcybersec_cron_print( "Invalid --url=$url\n", STDERR );
		exit( 1 );
	}
	// wp-config.php is next to wp-load.php or one folder up (same rule as wp-load.php).
	$dir    = dirname( $wp_load );
	$config = '';
	if ( is_file( $dir . '/wp-config.php' ) ) {
		$config = $dir . '/wp-config.php';
	} elseif ( is_file( dirname( $dir ) . '/wp-config.php' ) && ! is_file( dirname( $dir ) . '/wp-settings.php' ) ) {
		$config = dirname( $dir ) . '/wp-config.php';
	}
	$code   = '' !== $config ? (string) @file_get_contents( $config ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
	$target = array(
		'host'  => 'localhost',
		'path'  => '/',
		'https' => false,
	);
	if ( '' !== $code && preg_match( '/define\(\s*[\'"]DOMAIN_CURRENT_SITE[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/', $code, $m ) ) {
		$target['host'] = $m[1];
		if ( preg_match( '/define\(\s*[\'"]PATH_CURRENT_SITE[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\s*\)/', $code, $p ) && '' !== $p[1] ) {
			$target['path'] = $p[1];
		}
	}
	return $target;
}

/**
 * Shutdown check: WordPress exited while loading (multisite without a
 * matching address redirects and stops), so nothing was scanned. Say so and
 * fail, instead of exiting 0 silently.
 */
function wpcybersec_cron_shutdown() {
	if ( ! empty( $GLOBALS['wpcybersec_cron_booted'] ) ) {
		return;
	}
	$hint = ! empty( $GLOBALS['wpcybersec_cron_url_given'] ) ? '' : ' On multisite pass the network address: --url=https://example.com/';
	wpcybersec_cron_print( 'WordPress stopped while loading, so no scan ran.' . $hint . "\n", STDERR );
	exit( 1 );
}

$wpcybersec_options = wpcybersec_cron_args( isset( $argv ) && is_array( $argv ) ? $argv : ( isset( $_SERVER['argv'] ) && is_array( $_SERVER['argv'] ) ? $_SERVER['argv'] : array() ) );
$wpcybersec_wp_load = wpcybersec_find_wp_load( $wpcybersec_options['wp'] );

if ( ! $wpcybersec_wp_load ) {
	wpcybersec_cron_print( "Could not locate wp-load.php. Pass --wp=/path/to/wordpress.\n", STDERR );
	exit( 1 );
}

// Tell WordPress not to load the theme; this is a back-end task.
if ( ! defined( 'WP_USE_THEMES' ) ) {
	define( 'WP_USE_THEMES', false ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- WordPress core constant.
}
if ( ! defined( 'DOING_CRON' ) ) {
	define( 'DOING_CRON', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- WordPress core constant.
}
if ( $wpcybersec_options['isolated'] ) {
	wpcybersec_cron_print( "Isolated scan: other plugins and the theme are not loaded.\n" );
	wpcybersec_cron_isolate();
}

// Minimal server vars so WordPress boots cleanly from the command line.
$wpcybersec_target = wpcybersec_cron_target( $wpcybersec_options['url'], $wpcybersec_wp_load );
if ( '' !== $wpcybersec_options['url'] || ! isset( $_SERVER['HTTP_HOST'] ) ) {
	$_SERVER['HTTP_HOST']   = $wpcybersec_target['host'];
	$_SERVER['SERVER_NAME'] = preg_replace( '/:\d+$/', '', $wpcybersec_target['host'] );
}
if ( '' !== $wpcybersec_options['url'] || ! isset( $_SERVER['REQUEST_URI'] ) ) {
	$_SERVER['REQUEST_URI'] = $wpcybersec_target['path'];
}
if ( $wpcybersec_target['https'] ) {
	$_SERVER['HTTPS'] = 'on';
}
$_SERVER['REQUEST_METHOD'] = 'GET';

// WordPress may exit while loading (multisite: no site for this address).
$GLOBALS['wpcybersec_cron_booted']    = false;
$GLOBALS['wpcybersec_cron_url_given'] = '' !== $wpcybersec_options['url'];
register_shutdown_function( 'wpcybersec_cron_shutdown' );

require $wpcybersec_wp_load;
$GLOBALS['wpcybersec_cron_booted'] = true;

if ( ! function_exists( 'wpcybersec' ) ) {
	wpcybersec_cron_print( "CyberGate Security is not active on this site.\n", STDERR );
	exit( 1 );
}

$wpcybersec_plugin = wpcybersec();
if ( ! $wpcybersec_plugin->is_booted() ) {
	$wpcybersec_plugin->boot();
}

if ( $wpcybersec_options['isolated'] ) {
	// Proof that the isolation held, and what could not be isolated.
	$wpcybersec_foreign = wpcybersec_cron_foreign_code();
	if ( $wpcybersec_foreign ) {
		wpcybersec_cron_print( 'Isolation failed: code of other plugins or themes was loaded (' . count( $wpcybersec_foreign ) . " files), for example:\n", STDERR );
		foreach ( array_slice( $wpcybersec_foreign, 0, 10 ) as $wpcybersec_file ) {
			wpcybersec_cron_print( '  ' . $wpcybersec_file . "\n", STDERR );
		}
		wpcybersec_cron_print( "This usually means an mu-plugin or drop-in loads them. Check those first; the scan was not run.\n", STDERR );
		exit( 2 );
	}
	global $wpdb;
	$wpcybersec_stored = maybe_unserialize( $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", 'active_plugins' ) ) ); // phpcs:ignore WordPress.DB
	$wpcybersec_loaded = wp_get_active_and_valid_plugins();
	if ( is_multisite() && function_exists( 'wp_get_active_network_plugins' ) ) {
		// Network-activated plugins load from the network list, not from active_plugins.
		$wpcybersec_loaded = array_values( array_unique( array_merge( $wpcybersec_loaded, wp_get_active_network_plugins() ) ) );
		$wpcybersec_net    = maybe_unserialize( $wpdb->get_var( $wpdb->prepare( "SELECT meta_value FROM {$wpdb->sitemeta} WHERE meta_key = %s AND site_id = %d", 'active_sitewide_plugins', get_current_network_id() ) ) ); // phpcs:ignore WordPress.DB
		$wpcybersec_stored = array_merge( is_array( $wpcybersec_stored ) ? $wpcybersec_stored : array(), is_array( $wpcybersec_net ) ? array_keys( $wpcybersec_net ) : array() );
	}
	wpcybersec_cron_print(
		sprintf(
			"Active plugins on this site: %d. Loaded for this scan: %d (%s). Code from other plugins or themes loaded: none.\n",
			is_array( $wpcybersec_stored ) ? count( array_unique( array_filter( $wpcybersec_stored, 'is_string' ) ) ) : 0,
			count( $wpcybersec_loaded ),
			implode( ', ', array_map( 'plugin_basename', $wpcybersec_loaded ) )
		)
	);
	$wpcybersec_mu = function_exists( 'wp_get_mu_plugins' ) ? wp_get_mu_plugins() : array();
	wpcybersec_cron_print(
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
		wpcybersec_cron_print( 'Drop-ins still load: ' . implode( ', ', $wpcybersec_dropins ) . ". Review them yourself.\n" );
	}
}

$wpcybersec_job    = $wpcybersec_plugin->scan_job;
$wpcybersec_status = $wpcybersec_job->status();

if ( in_array( $wpcybersec_status['state'], array( 'enumerating', 'processing', 'finishing' ), true ) ) {
	// Another runner (or the cron chain) is active: continue it instead of refusing.
	// Ticks are serialized by a lock, so this waits while another runner works.
	if ( ! $wpcybersec_options['quiet'] ) {
		wpcybersec_cron_print( "A scan is already running; continuing it.\n" );
	}
} else {
	$wpcybersec_id = $wpcybersec_job->start(
		array(
			'mode'    => $wpcybersec_options['mode'],
			'malware' => $wpcybersec_options['malware'],
			'trigger' => 'cli',
			'force'   => true,
		)
	);
	if ( is_wp_error( $wpcybersec_id ) ) {
		wpcybersec_cron_print( 'Could not start the scan: ' . $wpcybersec_id->get_error_message() . "\n", STDERR );
		exit( 1 );
	}
}

$wpcybersec_last_line = '';
$wpcybersec_progress  = $wpcybersec_options['quiet'] ? null : static function ( $s ) use ( &$wpcybersec_last_line ) {
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
	if ( $line !== $wpcybersec_last_line ) {
		wpcybersec_cron_print( $line . "\n" );
		$wpcybersec_last_line = $line;
	}
};

$wpcybersec_final = $wpcybersec_job->run_to_completion( $wpcybersec_progress );

// Lets the settings offer "switch off visitor-triggered cron" once real cron is proven to run.
update_option( 'wpcybersec_cli_cron_at', time(), false );

$wpcybersec_summary = sprintf(
	"CyberGate Security %s scan %s: %d files checked, %d new, %d modified, %d deleted, %d threats, %d quarantined, %d skipped.\n",
	$wpcybersec_final['mode'] ? $wpcybersec_final['mode'] : $wpcybersec_options['mode'],
	$wpcybersec_final['state'],
	$wpcybersec_final['files_done'],
	$wpcybersec_final['new'],
	$wpcybersec_final['modified'],
	$wpcybersec_final['deleted'],
	$wpcybersec_final['threats'],
	$wpcybersec_final['quarantined'],
	$wpcybersec_final['skipped']
);
wpcybersec_cron_print( $wpcybersec_summary );
if ( 'failed' === $wpcybersec_final['state'] && '' !== (string) $wpcybersec_final['message'] ) {
	wpcybersec_cron_print( 'Reason: ' . $wpcybersec_final['message'] . "\n", STDERR );
}

// Non-zero exit when the scan failed, so cron wrappers can alert.
exit( 'failed' === $wpcybersec_final['state'] ? 1 : 0 );
