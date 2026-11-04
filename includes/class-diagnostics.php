<?php
/** Bounded HTTP observations; upstream avoidance is verified separately in server logs. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Diagnostics {
	const OPTION = 'quard_last_test';
	const SCHEMA = 5;

	public static function request_url( $url, $method = 'GET', $cookie = '', $timeout = 3 ) {
		return wp_remote_request( $url, array( 'method' => $method, 'timeout' => $timeout, 'redirection' => 0, 'limit_response_size' => 262144, 'headers' => array( 'Accept' => 'text/html', 'Cookie' => $cookie, 'User-Agent' => 'Quard-Diagnostics/' . QUARD_VERSION ) ) );
	}

	public static function request( $query = '', $method = 'GET', $cookie = '' ) {
		return self::request_url( home_url( '/' ) . $query, $method, $cookie );
	}

	public static function status() {
		try { $hash = Plugin::adapter()->fingerprint(); } catch ( \RuntimeException $e ) { return array( 'label' => __( 'Not tested — adapter unavailable', 'quard' ), 'match' => false, 'verified' => false, 'seen' => '', 'enabled' => '', 'error' => $e->getMessage() ); }
		// No cached success: every displayed verification requires a fresh observation.
		$r = self::request_url( home_url( '/' ), 'HEAD', '', 1.5 );
		$seen = is_wp_error( $r ) ? '' : (string) wp_remote_retrieve_header( $r, 'x-quard-policy' );
		$enabled = is_wp_error( $r ) ? '' : (string) wp_remote_retrieve_header( $r, 'x-quard-enabled' );
		$last = get_option( self::OPTION, array() );
		$code = is_wp_error( $r ) ? 0 : wp_remote_retrieve_response_code( $r );
		$match = hash_equals( $hash, $seen ) && $enabled === ( Plugin::policy()['enabled'] ? 'on' : 'off' );
		$verified = 200 === $code && $match && isset( $last['schema'], $last['hash'], $last['time'] ) && self::SCHEMA === $last['schema'] && ! empty( $last['passed'] ) && hash_equals( $hash, $last['hash'] ) && time() - $last['time'] < DAY_IN_SECONDS;
		$cache_risk = 'apache' === Deployment::detect()['engine'] && Deployment::cache_modules();
		if ( $cache_risk ) { $verified = false; }
		if ( ! $seen || ! $code ) {
			$label = __( 'Server integration unverified', 'quard' );
		} elseif ( ! $match ) {
			$label = __( 'Configuration update required', 'quard' );
		} elseif ( ! Plugin::policy()['enabled'] ) {
			$label = __( 'Disabled on server', 'quard' );
		} elseif ( $cache_risk ) {
			$label = __( 'Apache cache profile not qualified', 'quard' );
		} elseif ( $verified ) {
			$label = __( 'Protection verified by HTTP probes', 'quard' );
		} else {
			$label = __( 'Configuration observed — run Test Protection', 'quard' );
		}
		return array( 'label' => $label, 'match' => $match, 'verified' => $verified, 'seen' => $seen, 'enabled' => $enabled, 'error' => is_wp_error( $r ) ? $r->get_error_message() : '' );
	}

	public static function cookie_headers( $r ) {
		$headers = wp_remote_retrieve_header( $r, 'set-cookie' );
		return is_array( $headers ) ? implode( "\n", $headers ) : (string) $headers;
	}

	/** Validate only Quard's cookie; unrelated cookies may legitimately have a Domain. */
	public static function navigation_cookie_valid( $headers, $enabled, $https, $lifetime ) {
		$cookies = array();
		foreach ( preg_split( '/\r\n|\r|\n/', (string) $headers ) as $line ) {
			// Set-Cookie must not be folded: a second clearance cookie is ambiguous.
			if ( preg_match( '/,\s*quard_nav=/', $line ) ) { return false; }
			if ( 0 === strpos( ltrim( $line ), 'quard_nav=' ) ) { $cookies[] = trim( $line ); }
		}
		if ( ! $enabled ) { return ! $cookies; }
		if ( 1 !== count( $cookies ) ) { return false; }
		$parts = explode( ';', $cookies[0] );
		if ( 'quard_nav=1' !== array_shift( $parts ) ) { return false; }
		$attributes = array();
		foreach ( $parts as $part ) {
			$pair = explode( '=', trim( $part ), 2 );
			$name = strtolower( trim( $pair[0] ) );
			if ( '' === $name || array_key_exists( $name, $attributes ) ) { return false; }
			$attributes[ $name ] = isset( $pair[1] ) ? trim( $pair[1] ) : true;
		}
		return ! isset( $attributes['domain'] )
			&& isset( $attributes['path'], $attributes['max-age'], $attributes['httponly'], $attributes['samesite'] )
			&& '/' === $attributes['path'] && (string) ( $lifetime * 60 ) === $attributes['max-age']
			&& true === $attributes['httponly'] && 'lax' === strtolower( (string) $attributes['samesite'] )
			&& ( $https ? isset( $attributes['secure'] ) && true === $attributes['secure'] : ! isset( $attributes['secure'] ) );
	}

	/** Preserve duplicate query pairs; do not collapse them with parse_str. */
	private static function query_pairs( $query, $drop_page_one = false ) {
		$pairs = array();
		foreach ( '' === $query ? array() : explode( '&', $query ) as $pair ) {
			$bits = explode( '=', $pair, 2 );
			$key = urldecode( $bits[0] );
			$value = isset( $bits[1] ) ? urldecode( $bits[1] ) : '';
			if ( $drop_page_one && 'page' === $key && '1' === $value ) {
				continue;
			}
			$pairs[ $key ][] = $value;
		}
		ksort( $pairs, SORT_STRING );
		return $pairs;
	}

	/** Only same-origin/same-path canonicalization, retaining every query pair. */
	public static function canonical_target_allowed( $from, $to, $drop_page_one = false ) {
		$a = wp_parse_url( $from );
		$b = wp_parse_url( $to );
		if ( ! is_array( $a ) || ! is_array( $b ) || isset( $b['user'] ) || isset( $b['pass'] ) || isset( $b['fragment'] ) ) {
			return false;
		}
		foreach ( array( 'scheme', 'host', 'port' ) as $key ) {
			if ( ( isset( $a[ $key ] ) ? $a[ $key ] : '' ) !== ( isset( $b[ $key ] ) ? $b[ $key ] : '' ) ) {
				return false;
			}
		}
		$path_a = isset( $a['path'] ) ? $a['path'] : '/';
		$path_b = isset( $b['path'] ) ? $b['path'] : '/';
		if ( rtrim( $path_a, '/' ) !== rtrim( $path_b, '/' ) ) {
			return false;
		}
		return self::query_pairs( isset( $a['query'] ) ? $a['query'] : '', $drop_page_one ) === self::query_pairs( isset( $b['query'] ) ? $b['query'] : '' );
	}

	/** Stable WordPress page/archive classes help reject a 200 login/challenge page. */
	public static function page_identity( $body ) {
		if ( ! preg_match( '/<body\b[^>]*\bclass=["\x27]([^"\x27]*)/i', $body, $match ) ) {
			return array();
		}
		$ids = array();
		foreach ( preg_split( '/\s+/', $match[1] ) as $class ) {
			if ( preg_match( '/\A(?:home|blog|page-id-\d+|postid-\d+|term-\d+|tax-[a-z0-9_-]+|post-type-archive-[a-z0-9_-]+)\z/', $class ) ) {
				$ids[] = $class;
			}
		}
		sort( $ids );
		return $ids;
	}

	/** Inspect one response and at most one specifically permitted canonical redirect. */
	public static function allowed_reply( $r, $url, $method, $cookie, $hash, $enabled, $drop_page_one = false ) {
		$observations = array();
		$cookies = '';
		for ( $hop = 0; $hop < 2; ++$hop ) {
			if ( is_wp_error( $r ) ) {
				return array( 'passed' => false, 'detail' => $r->get_error_message(), 'identity' => array(), 'cookies' => $cookies );
			}
			$code = wp_remote_retrieve_response_code( $r );
			$seen = (string) wp_remote_retrieve_header( $r, 'x-quard-policy' );
			$state = (string) wp_remote_retrieve_header( $r, 'x-quard-enabled' );
			$cookies .= self::cookie_headers( $r ) . "\n";
			$observations[] = sprintf( 'HTTP %d %s', $code, $url );
			if ( ! hash_equals( $hash, $seen ) || $state !== ( $enabled ? 'on' : 'off' ) ) {
				break;
			}
			if ( 200 === $code ) {
				$type = (string) wp_remote_retrieve_header( $r, 'content-type' );
				return array( 'passed' => (bool) preg_match( '~^text/html(?:;|$)~i', $type ), 'detail' => implode( ' → ', $observations ), 'identity' => self::page_identity( wp_remote_retrieve_body( $r ) ), 'cookies' => $cookies );
			}
			if ( 0 !== $hop || ! in_array( $code, array( 301, 302, 307, 308 ), true ) ) {
				break;
			}
			$location = (string) wp_remote_retrieve_header( $r, 'location' );
			$target = $location ? \WP_Http::make_absolute_url( $location, $url ) : '';
			if ( ! $target || ! self::canonical_target_allowed( $url, $target, $drop_page_one ) ) {
				$observations[] = 'Rejected redirect: ' . $location;
				break;
			}
			$url = $target;
			$r = self::request_url( $url, $method, $cookie );
		}
		return array( 'passed' => false, 'detail' => implode( ' → ', $observations ) . '; unexpected response, target or policy', 'identity' => array(), 'cookies' => $cookies );
	}

	public static function run() {
		$started = microtime( true );
		$p = Plugin::policy();
		try { $hash = Plugin::adapter()->fingerprint(); } catch ( \RuntimeException $e ) { return array( 'schema' => self::SCHEMA, 'time' => time(), 'hash' => '', 'passed' => false, 'rows' => array( array( 'label' => __( 'Server adapter', 'quard' ), 'result' => 'NOT TESTED', 'detail' => $e->getMessage() ) ) ); }
		$rows = array();
		$home = home_url( '/' );
		$home_reply = self::request_url( $home );
		$home_baseline = self::allowed_reply( $home_reply, $home, 'GET', '', $hash, $p['enabled'] );
		$home_cookie = self::navigation_cookie_valid( $home_baseline['cookies'], $p['enabled'], 'https' === wp_parse_url( $home, PHP_URL_SCHEME ), $p['lifetime'] );
		$rows[] = array( 'label' => __( 'Literal homepage GET and navigation cookie', 'quard' ), 'result' => $home_baseline['passed'] && $home_cookie ? 'PASS' : 'FAIL', 'detail' => $home_baseline['detail'] . ( $home_cookie ? '' : '; homepage clearance missing or malformed' ) );
		$recovery = array( 'result' => 'NOT TESTED', 'detail' => __( 'Native navigation recovery is not advertised. This does not attest cache/expiry or real menu browsing.', 'quard' ) );
		if ( ! is_wp_error( $home_reply ) && 'nginx' === wp_remote_retrieve_header( $home_reply, 'x-quard-navigation' ) ) {
			$origin = wp_parse_url( $home, PHP_URL_SCHEME ) . '://' . wp_parse_url( $home, PHP_URL_HOST );
			$port = wp_parse_url( $home, PHP_URL_PORT );
			if ( $port ) { $origin .= ':' . $port; }
			$r = wp_remote_request( $origin . Nginx::NAVIGATION_PATH, array( 'method' => 'POST', 'timeout' => 2, 'redirection' => 0, 'limit_response_size' => 1024, 'headers' => array( 'Origin' => $origin, 'X-Quard-Navigation' => '1', 'Cookie' => '' ) ) );
			$ok = ! is_wp_error( $r ) && 204 === wp_remote_retrieve_response_code( $r ) && hash_equals( $hash, (string) wp_remote_retrieve_header( $r, 'x-quard-policy' ) ) && false !== strpos( (string) wp_remote_retrieve_header( $r, 'cache-control' ), 'no-store' ) && self::navigation_cookie_valid( self::cookie_headers( $r ), $p['enabled'], 'https' === wp_parse_url( $home, PHP_URL_SCHEME ), $p['lifetime'] );
			$recovery = array( 'result' => $ok ? 'PASS' : 'FAIL', 'detail' => __( 'Same-origin native renewal HTTP probe. Browser menu interaction and upstream avoidance require independent evidence.', 'quard' ) );
			$rows[] = array( 'label' => __( 'Native navigation renewal HTTP probe', 'quard' ), 'result' => $recovery['result'], 'detail' => $recovery['detail'] );
		}
		// Prefer the configured shop archive when available; never hardcode a storefront path.
		$url = function_exists( 'wc_get_page_permalink' ) ? wc_get_page_permalink( 'shop' ) : home_url( '/' );
		if ( wp_parse_url( $url, PHP_URL_HOST ) !== wp_parse_url( home_url(), PHP_URL_HOST ) || wp_parse_url( $url, PHP_URL_SCHEME ) !== wp_parse_url( home_url(), PHP_URL_SCHEME ) ) {
			$url = home_url( '/' );
		}
		$baseline = $url === $home ? $home_baseline : self::allowed_reply( self::request_url( $url ), $url, 'GET', '', $hash, $p['enabled'] );
		$set = $baseline['cookies'];
		$cookie_ok = self::navigation_cookie_valid( $set, $p['enabled'], 'https' === wp_parse_url( $url, PHP_URL_SCHEME ), $p['lifetime'] );
		$rows[] = array( 'label' => __( 'Navigation baseline and cookie attributes', 'quard' ), 'result' => $baseline['passed'] && $cookie_ok ? 'PASS' : 'FAIL', 'detail' => $baseline['detail'] . ( $cookie_ok ? '' : '; missing or unexpected clearance cookie' ) );
		if ( $baseline['passed'] && $cookie_ok ) {
			$name = ! empty( $p['exact'] ) ? $p['exact'][0] : ( ! empty( $p['prefixes'] ) ? rtrim( $p['prefixes'][0], '*' ) . 'probe' : '' );
			if ( ! $name ) {
				$rows[] = array( 'label' => __( 'Protected parameter rules', 'quard' ), 'result' => 'FAIL', 'detail' => __( 'No protected rules are configured.', 'quard' ) );
			} else {
				$test_uri = (string) wp_parse_url( $url, PHP_URL_PATH ) . '?' . $name . '=1';
				$test_class = Policy::classify( $p, $test_uri );
				if ( $p['enabled'] && ( $test_class['excluded'] || $test_class['exception'] ) ) {
					$rows[] = array( 'label' => __( 'Cold-denial qualification', 'quard' ), 'result' => 'NOT TESTED', 'detail' => __( 'The diagnostic route is excluded or directly excepted. Qualify protection on another configured route.', 'quard' ) );
				}
				$probes = array( array( __( 'Cleared filtered navigation', 'quard' ), array( $name => '1' ), 'GET', 'quard_nav=1', true ), array( __( 'Cold filtered navigation', 'quard' ), array( $name => '1' ), 'GET', '', false ), array( __( 'Cold filter HEAD', 'quard' ), array( $name => '1' ), 'HEAD', '', false ), array( __( 'Forged operational key', 'quard' ), array( $name => '1', 'rest_route' => 'x', 'add-to-cart' => '0', 'wc-ajax' => 'whatever' ), 'HEAD', '', false ), array( __( 'Standalone orderby behavior', 'quard' ), array( 'orderby' => 'rating' ), 'HEAD', '', false ), array( __( 'Tracking and canonical pagination', 'quard' ), array( 'utm_source' => 'quard', 'page' => '1' ), 'HEAD', '', false ) );
				foreach ( $probes as $probe ) {
					// With protection disabled, forged REST/AJAX keys reach application routing
					// and may correctly return 404. They are only a denial assertion when enabled.
					if ( ! $p['enabled'] && isset( $probe[1]['rest_route'] ) ) { continue; }
					if ( microtime( true ) - $started > 18 ) {
						$rows[] = array( 'label' => $probe[0], 'result' => 'NOT TESTED', 'detail' => __( 'Diagnostic time budget reached. Retry when the site responds normally.', 'quard' ) );
						break;
					}
					$target = add_query_arg( $probe[1], $url );
					$c = Policy::classify( $p, (string) wp_parse_url( $target, PHP_URL_PATH ) . '?' . (string) wp_parse_url( $target, PHP_URL_QUERY ) );
					$blocked = $p['enabled'] && $c['protected'] && ! $c['excluded'] && ! $c['exception'] && ! $probe[3];
					$r = self::request_url( $target, $probe[2], $probe[3] );
					if ( $blocked ) {
						$pass = ! is_wp_error( $r ) && $p['response'] === wp_remote_retrieve_response_code( $r ) && hash_equals( $hash, (string) wp_remote_retrieve_header( $r, 'x-quard-policy' ) ) && 'on' === wp_remote_retrieve_header( $r, 'x-quard-enabled' ) && false === strpos( self::cookie_headers( $r ), 'quard_nav=' );
						$detail = is_wp_error( $r ) ? $r->get_error_message() : sprintf( 'HTTP %d; expected %d with matching policy', wp_remote_retrieve_response_code( $r ), $p['response'] );
					} else {
						$a = self::allowed_reply( $r, $target, $probe[2], $probe[3], $hash, $p['enabled'], isset( $probe[1]['page'] ) );
						$pass = $a['passed'] && false === strpos( $a['cookies'], 'quard_nav=' );
						$detail = $a['detail'];
						if ( $probe[4] && ( ! $baseline['identity'] || $baseline['identity'] !== $a['identity'] ) ) {
							$pass = false;
							$detail .= '; WordPress page/archive identity missing or differs from baseline';
						}
					}
					$rows[] = array( 'label' => $probe[0], 'result' => $pass ? 'PASS' : 'FAIL', 'detail' => $detail );
				}
			}
		}
		if ( 'apache' === Deployment::detect()['engine'] && Deployment::cache_modules() ) {
			$rows[] = array( 'label' => __( 'Apache cache HIT qualification', 'quard' ), 'result' => 'NOT TESTED', 'detail' => __( 'A cache module is loaded. Ordinary probes cannot qualify cached denial, cookie issuance or WordPress cache-key isolation. Automatic cached deployment remains disabled.', 'quard' ) );
		}
		$result = array( 'schema' => self::SCHEMA, 'time' => time(), 'hash' => $hash, 'passed' => ! array_diff( array_column( $rows, 'result' ), array( 'PASS' ) ), 'rows' => $rows );
		$result['browser_journey'] = array( 'result' => 'NOT TESTED', 'detail' => __( 'HTTP probes do not click real menu links. Qualify literal homepage, two actual menu clicks, expiry and history with the operator browser acceptance test.', 'quard' ) );
		$result['navigation_recovery'] = $recovery;
		if ( false === get_option( self::OPTION, false ) ) {
			add_option( self::OPTION, $result, '', false );
		} else {
			update_option( self::OPTION, $result, false );
		}
		return $result;
	}
}
