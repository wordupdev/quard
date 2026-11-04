<?php
/** Canonical, server-independent policy and restricted pattern language. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Policy {
	const EXACT = array( 'min_price', 'max_price', 'rating_filter', 'min_rating' );
	const PREFIXES = array( 'filter_*', 'query_type_*' );
	const PATHS = array( '/wp-admin/*', '/wp-login.php', '/wp-json/*', '/wp-cron.php', '/xmlrpc.php', '/wc-api/*', '/cart/*', '/checkout/*', '/my-account/*', '/order-pay/*', '/order-received/*', '/.well-known/*', '/cgi-bin/*' );
	// Cookie issuance exclusions only. These names never authorize a protected request.
	const NO_CLEARANCE_KEYS = array( 'rest_route', 'wc-ajax', 'wc-api', 'add-to-cart', 'remove_item', 'undo_item', 'cancel_order', 'pay_for_order', 'order_again', 'download_file' );
	const COOKIE_VALUE = '(?:^|;\s*)quard_nav=1(?:;|$)';
	const COOKIE_DUPLICATE = '(?:^|;\s*)quard_nav=[^;]*(?:;[^;]*)*;\s*quard_nav=';

	/** Shared by native rules and script eligibility, never PHP enforcement or issuance. */
	public static function has_clearance( $header ) {
		return (bool) preg_match( '~' . self::COOKIE_VALUE . '~', $header ) && ! preg_match( '~' . self::COOKIE_DUPLICATE . '~', $header );
	}

	public static function defaults() {
		return array( 'enabled' => false, 'mode' => 'balanced', 'lifetime' => 30, 'response' => 403, 'exact' => self::EXACT, 'prefixes' => self::PREFIXES, 'excluded' => array(), 'exceptions' => array() );
	}

	/** Reject unsupported syntax instead of converting dangerous input into a different rule. */
	public static function normalize( $input ) {
		if ( ! is_array( $input ) ) {
			throw new \InvalidArgumentException( __( 'Settings must be a structured policy.', 'quard' ) );
		}
		$p = array_merge( self::defaults(), $input );
		if ( ! in_array( $p['enabled'], array( false, true, 0, 1, '0', '1' ), true ) ) {
			throw new \InvalidArgumentException( __( 'Enable protection must be on or off.', 'quard' ) );
		}
		$p['enabled'] = (bool) $p['enabled'];
		foreach ( array( 'mode' => array( 'balanced', 'strict', 'custom' ), 'lifetime' => array( '5', '15', '30', '60' ), 'response' => array( '403', '410', '429' ) ) as $key => $values ) {
			if ( ! is_scalar( $p[ $key ] ) || ! in_array( (string) $p[ $key ], $values, true ) ) {
				throw new \InvalidArgumentException( __( 'Unsupported protection setting.', 'quard' ) );
			}
		}
		$p['lifetime'] = (int) $p['lifetime'];
		$p['response'] = (int) $p['response'];
		foreach ( array( 'exact', 'prefixes', 'excluded', 'exceptions' ) as $key ) {
			$lines = $p[ $key ];
			if ( is_string( $lines ) ) {
				if ( strlen( $lines ) > 12000 ) {
					throw new \InvalidArgumentException( __( 'Rule input is too long.', 'quard' ) );
				}
				$lines = preg_split( '/\R/', $lines );
			}
			if ( ! is_array( $lines ) || count( $lines ) > 100 ) {
				throw new \InvalidArgumentException( __( 'Use at most 100 rules per field.', 'quard' ) );
			}
			$clean = array();
			foreach ( $lines as $line ) {
				if ( ! is_string( $line ) ) {
					throw new \InvalidArgumentException( __( 'Each rule must be text.', 'quard' ) );
				}
				$line = trim( $line );
				if ( '' === $line ) {
					continue;
				}
				$pattern = 'exact' === $key ? '/\A[a-z][a-z0-9_-]{0,63}\z/D' : '/\A[a-z][a-z0-9_-]{0,62}\*\z/D';
				if ( in_array( $key, array( 'excluded', 'exceptions' ), true ) ) {
					$pattern = '/\A\/[a-zA-Z0-9_\/.~-]*(?:\/\*)?\z/D';
				}
				if ( strlen( $line ) > 200 || ! preg_match( $pattern, $line ) || false !== strpos( $line, '..' ) || false !== strpos( $line, '//' ) || '/*' === $line ) {
					throw new \InvalidArgumentException( sprintf( __( 'Invalid rule: %s. Use parameter names, trailing prefix*, or /path/ and /path/* only.', 'quard' ), substr( $line, 0, 200 ) ) );
				}
				$clean[] = $line;
			}
			$p[ $key ] = array_values( array_unique( $clean ) );
			sort( $p[ $key ], SORT_STRING );
		}
		return array_intersect_key( $p, self::defaults() );
	}

	public static function effective( array $p, array $site_paths = array() ) {
		$p = self::normalize( $p );
		if ( 'custom' !== $p['mode'] ) {
			$p['exact'] = array_merge( $p['exact'], self::EXACT );
			$p['prefixes'] = array_merge( $p['prefixes'], self::PREFIXES );
		}
		if ( 'strict' === $p['mode'] ) {
			$p['exact'][] = 'orderby';
		}
		$p['excluded'] = array_merge( self::PATHS, $site_paths, $p['excluded'] );
		foreach ( array( 'exact', 'prefixes', 'excluded', 'exceptions' ) as $key ) {
			$p[ $key ] = array_values( array_unique( $p[ $key ] ) );
			sort( $p[ $key ], SORT_STRING );
		}
		$p['no_clearance_keys'] = self::NO_CLEARANCE_KEYS;
		return $p;
	}

	/** Match both literal ASCII and percent-encoded query names, including PHP's dot/space normalization. */
	public static function literal( $text, $parameter = false ) {
		$out = '';
		foreach ( str_split( $text ) as $c ) {
			$out .= $parameter && '_' === $c ? '(?:_|[.+]|%5f|%2e|%20)' : '(?:' . preg_quote( $c, '~' ) . '|%' . bin2hex( $c ) . ')';
		}
		return $out;
	}

	public static function query_pattern( array $exact, array $prefixes = array() ) {
		$names = array();
		foreach ( $exact as $name ) {
			$names[] = self::literal( $name, true );
		}
		foreach ( $prefixes as $name ) {
			$names[] = self::literal( substr( $name, 0, -1 ), true ) . '[^=&]*';
		}
		return $names ? '(?:^|&)(?:[+]|%20)*(?:' . implode( '|', $names ) . ')(?:=|&|$|\[|%5b|%00)' : '(?!)';
	}

	public static function path_pattern( array $paths ) {
		$rules = array();
		foreach ( $paths as $path ) {
			if ( '/*' === substr( $path, -2 ) ) {
				$rules[] = self::literal( substr( $path, 0, -2 ) ) . '(?:/|%2f|$)';
			} else {
				$rules[] = self::literal( $path ) . '$';
			}
		}
		return $rules ? '^(?:' . implode( '|', $rules ) . ')' : '(?!)';
	}

	/** Diagnostic classification uses the same generated expressions as Nginx, never $_GET after rewrites. */
	public static function classify( array $p, $request_uri ) {
		$parts = explode( '?', $request_uri, 2 );
		$args = isset( $parts[1] ) ? $parts[1] : '';
		$protected = (bool) preg_match( '~' . self::query_pattern( $p['exact'], $p['prefixes'] ) . '~i', $args );
		$excluded = (bool) preg_match( '~' . self::path_pattern( $p['excluded'] ) . '~i', $parts[0] );
		$exception = (bool) preg_match( '~' . self::path_pattern( $p['exceptions'] ) . '~i', $parts[0] );
		return array( 'protected' => $protected, 'excluded' => $excluded, 'exception' => $exception, 'operational' => (bool) preg_match( '~' . self::query_pattern( $p['no_clearance_keys'] ) . '~i', $args ) );
	}
}
