<?php
/**
 * Official original versions of WordPress core and wordpress.org plugin files.
 *
 * @package WPCyberSecurity
 */

namespace WPCyberSecurity;

defined( 'ABSPATH' ) || exit;

/**
 * Downloads the released version of a file so a changed core or plugin file
 * can be compared with it, and accepts it ONLY when it matches the official
 * checksum the scanner already trusts:
 *
 *   core    https://core.svn.wordpress.org/tags/<wp version>/<path>
 *           md5 must equal get_core_checksums() for that path.
 *   plugin  https://plugins.svn.wordpress.org/<slug>/tags/<version>/<path>
 *           (trunk only when that tag does not exist); sha256 must be listed in
 *           https://downloads.wordpress.org/plugin-checksums/<slug>/<version>.json.
 *
 * This plugin's own files have no remote original. Accepted originals are kept
 * in Snapshots (put_content); a failed lookup is remembered for 6 hours (1 hour
 * after a network error, for the whole network), a successful one for a week
 * (per site: on a multisite network each site keeps its own copies).
 */
class Originals {

	const CORE_URL   = 'https://core.svn.wordpress.org/tags/%1$s/%2$s';
	const PLUGIN_URL = 'https://plugins.svn.wordpress.org/%1$s/%2$s/%3$s';

	const MISS_PREFIX = 'wpcybersec_orig_miss_';
	const HIT_PREFIX  = 'wpcybersec_orig_hit_';

	const MISS_TTL  = 6 * HOUR_IN_SECONDS;
	const ERROR_TTL = HOUR_IN_SECONDS;
	const HIT_TTL   = WEEK_IN_SECONDS;
	const TIMEOUT   = 10;

	/**
	 * Where the official original of a file comes from, without downloading it.
	 *
	 * @param string $rel Relative path (scan root).
	 * @return array|null { source: core|plugin, slug, version, path, label, md5, sha256 (list), urls }
	 */
	public function locate( $rel ) {
		$rel     = ltrim( wp_normalize_path( (string) $rel ), '/' );
		$scanner = wpcybersec()->scanner;
		if ( '' === $rel || ! $scanner || ! wpcybersec()->settings->get( 'use_checksums', true ) || $scanner->is_own_path( $rel ) ) {
			return null;
		}

		if ( $scanner->is_core_path( $rel ) ) {
			$path    = $scanner->core_path( $rel );
			$version = $scanner->installed_wp_version();
			$map     = $scanner->core_map();
			if ( '' === $path || ! self::valid_version( $version ) || ! is_array( $map ) || empty( $map[ $path ] ) ) {
				return null;
			}
			return array(
				'source'  => 'core',
				'slug'    => '',
				'version' => $version,
				'path'    => $path,
				/* translators: %s: WordPress version */
				'label'   => sprintf( __( 'Official WordPress %s file', 'cybergate-security' ), $version ),
				'md5'     => strtolower( (string) $map[ $path ] ),
				'sha256'  => array(),
				'urls'    => array( sprintf( self::CORE_URL, rawurlencode( $version ), self::encode_path( $path ) ) ),
			);
		}

		$slug = $scanner->plugin_slug_for( $rel );
		if ( '' === $slug ) {
			return null;
		}
		$map  = $scanner->plugin_map( $slug );
		$path = $scanner->plugin_path( $rel, $slug );
		if ( ! is_array( $map ) || '' === $path || empty( $map[ $path ] ) ) {
			return null;
		}
		$version = $scanner->plugin_version( $slug );
		if ( ! self::valid_version( $version ) || ! preg_match( '~^[a-z0-9._-]{1,100}$~i', $slug ) ) {
			return null;
		}
		$name = $scanner->plugin_name( $slug );
		return array(
			'source'  => 'plugin',
			'slug'    => $slug,
			'version' => $version,
			'path'    => $path,
			/* translators: 1: plugin name, 2: version */
			'label'   => sprintf( __( 'Official %1$s %2$s file', 'cybergate-security' ), $name, $version ),
			'md5'     => '',
			'sha256'  => array_map( 'strtolower', (array) $map[ $path ] ),
			'urls'    => array(
				sprintf( self::PLUGIN_URL, rawurlencode( $slug ), 'tags/' . rawurlencode( $version ), self::encode_path( $path ) ),
				sprintf( self::PLUGIN_URL, rawurlencode( $slug ), 'trunk', self::encode_path( $path ) ),
			),
		);
	}

	/**
	 * Version of WordPress or of the plugin a file belongs to as installed now,
	 * without touching the network: a remembered original (details.base_sha256)
	 * is only reused while this still equals the version it was fetched for.
	 *
	 * @param string $rel    Relative path (scan root).
	 * @param string $source core | plugin (details.base_source).
	 * @return string '' when unknown.
	 */
	public function installed_version( $rel, $source ) {
		$scanner = wpcybersec()->scanner;
		if ( ! $scanner ) {
			return '';
		}
		if ( 'core' === $source ) {
			return (string) $scanner->installed_wp_version();
		}
		if ( 'plugin' === $source ) {
			$slug = $scanner->plugin_slug_for( ltrim( wp_normalize_path( (string) $rel ), '/' ) );
			return '' === $slug ? '' : (string) $scanner->plugin_version( $slug );
		}
		return '';
	}

	/**
	 * The verified official original of a file.
	 *
	 * @param string $rel           Relative path (scan root).
	 * @param bool   $allow_network False to never touch the network (returns null).
	 * @return array|null { content, sha256, label, source, version, url }
	 */
	public function fetch( $rel, $allow_network = true ) {
		if ( ! $allow_network ) {
			return null; // locate() itself may download checksum lists.
		}
		$loc = $this->locate( $rel );
		if ( ! $loc ) {
			return null;
		}
		$snapshots = wpcybersec()->snapshots;
		$key       = md5( $loc['source'] . '|' . $loc['slug'] . '|' . $loc['version'] . '|' . $loc['path'] );

		// The copy lives in this site's Snapshots folder, so the hit is remembered per site.
		$hit = get_transient( self::HIT_PREFIX . $key );
		if ( Snapshots::is_sha( $hit ) ) {
			$content = $snapshots->get( $hit );
			if ( null !== $content && self::accept( $loc, $content ) ) {
				return self::result( $loc, $content, $hit, '' );
			}
			delete_transient( self::HIT_PREFIX . $key );
		}
		if ( get_site_transient( self::MISS_PREFIX . $key ) ) {
			return null;
		}

		$last = count( $loc['urls'] ) - 1;
		foreach ( $loc['urls'] as $i => $url ) {
			$response = wp_remote_get(
				$url,
				array(
					'timeout'             => self::TIMEOUT,
					'redirection'         => 2,
					'limit_response_size' => Snapshots::HARD_MAX + 1,
				)
			);
			if ( is_wp_error( $response ) ) {
				set_site_transient( self::MISS_PREFIX . $key, 1, self::ERROR_TTL );
				return null;
			}
			$code = (int) wp_remote_retrieve_response_code( $response );
			if ( 404 === $code && $i < $last ) {
				continue; // The tag does not exist: try trunk.
			}
			if ( 200 !== $code ) {
				set_site_transient( self::MISS_PREFIX . $key, 1, $code >= 500 ? self::ERROR_TTL : self::MISS_TTL );
				return null;
			}
			$content = (string) wp_remote_retrieve_body( $response );
			if ( strlen( $content ) > Snapshots::HARD_MAX || ! self::accept( $loc, $content ) ) {
				// Not the released file (wrong tag, trunk moved on, or tampered in transit).
				set_site_transient( self::MISS_PREFIX . $key, 1, self::MISS_TTL );
				return null;
			}
			$sha = $snapshots->put_content( $content );
			if ( '' !== $sha ) {
				set_transient( self::HIT_PREFIX . $key, $sha, self::HIT_TTL );
			}
			return self::result( $loc, $content, '' !== $sha ? $sha : hash( 'sha256', $content ), $url );
		}
		set_site_transient( self::MISS_PREFIX . $key, 1, self::MISS_TTL );
		return null;
	}

	/**
	 * Whether downloaded content is the official file.
	 *
	 * @param array  $loc     locate() result.
	 * @param string $content Content.
	 * @return bool
	 */
	public static function accept( array $loc, $content ) {
		if ( 'core' === $loc['source'] ) {
			return '' !== $loc['md5'] && hash_equals( $loc['md5'], md5( (string) $content ) );
		}
		return $loc['sha256'] && in_array( hash( 'sha256', (string) $content ), $loc['sha256'], true );
	}

	/**
	 * @param array  $loc     locate() result.
	 * @param string $content Content.
	 * @param string $sha     sha256.
	 * @param string $url     Download address ('' from the cache).
	 * @return array
	 */
	private static function result( array $loc, $content, $sha, $url ) {
		return array(
			'content' => (string) $content,
			'sha256'  => (string) $sha,
			'label'   => (string) $loc['label'],
			'source'  => (string) $loc['source'],
			'version' => (string) $loc['version'],
			'url'     => (string) $url,
		);
	}

	/**
	 * @param string $version Version string.
	 * @return bool
	 */
	private static function valid_version( $version ) {
		return is_string( $version ) && 1 === preg_match( '~^[a-z0-9._+-]{1,40}$~i', $version );
	}

	/**
	 * URL-encodes each segment of a relative path.
	 *
	 * @param string $path Path with forward slashes.
	 * @return string
	 */
	private static function encode_path( $path ) {
		return implode( '/', array_map( 'rawurlencode', explode( '/', ltrim( (string) $path, '/' ) ) ) );
	}
}
