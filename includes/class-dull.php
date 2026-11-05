<?php
/** Independent, normalized bot/query policy. No request hook or PHP blocking. */
namespace Quard;
defined( 'ABSPATH' ) || exit;
final class Dull {
	const OPTION = 'quard_dull_settings';
	public static function defaults() {
		return array( 'enabled' => false, 'bots' => array( 'bingbot', 'claudebot', 'facebookexternalhit', 'googlebot', 'gptbot', 'oai-searchbot' ), 'strings' => array( 'filter_*', 'max_price', 'min_price', 'orderby', 'query_type_*' ), 'excluded' => array(), 'response' => 403, 'permanent_ack' => false, 'verified_enabled' => false, 'families' => array_keys( Crawler::sources() ) );
	}
	private static function lines( $value, $max ) {
		if ( is_string( $value ) ) { if ( strlen( $value ) > 12000 ) { throw new \InvalidArgumentException( __( 'Dull Knife input is too long.', 'quard' ) ); } $value = preg_split( '/\R/', $value ); }
		if ( ! is_array( $value ) || count( $value ) > $max ) { throw new \InvalidArgumentException( __( 'Dull Knife rule count exceeded.', 'quard' ) ); }
		$out = array();
		foreach ( $value as $line ) { if ( ! is_string( $line ) ) { throw new \InvalidArgumentException( __( 'Each Dull Knife rule must be text.', 'quard' ) ); } $line = trim( $line ); if ( '' !== $line ) { $out[] = $line; } }
		return $out;
	}
	public static function normalize( $input ) {
		if ( ! is_array( $input ) || array_diff_key( $input, self::defaults() ) ) { throw new \InvalidArgumentException( __( 'Unsupported Dull Knife settings.', 'quard' ) ); }
		$s = array_merge( self::defaults(), $input );
		foreach ( array( 'enabled', 'verified_enabled', 'permanent_ack' ) as $key ) {
			if ( ! in_array( $s[ $key ], array( true, false, 0, 1, '0', '1' ), true ) ) { throw new \InvalidArgumentException( __( 'Use valid Dull Knife switches.', 'quard' ) ); } $s[ $key ] = (bool) $s[ $key ];
		}
		if ( ! is_scalar( $s['response'] ) || ! in_array( (string) $s['response'], array( '403', '404', '410' ), true ) ) { throw new \InvalidArgumentException( __( 'Dull Knife supports only 403, 404 or 410.', 'quard' ) ); }
		$s['response'] = (int) $s['response'];
		if ( 410 === $s['response'] && ! $s['permanent_ack'] ) { throw new \InvalidArgumentException( __( '410 requires explicit acknowledgment of permanent-removal and status-cloaking/indexing risk.', 'quard' ) ); }
		$s['bots'] = self::lines( $s['bots'], 50 );
		foreach ( $s['bots'] as &$token ) { if ( ! preg_match( '/\A[a-zA-Z][a-zA-Z0-9_-]{1,63}\z/D', $token ) ) { throw new \InvalidArgumentException( __( 'Use plain crawler UA tokens, not regex, spaces or directives.', 'quard' ) ); } $token = strtolower( $token ); } unset( $token );
		$s['strings'] = self::lines( $s['strings'], 100 ); $exact = array(); $prefixes = array();
		foreach ( $s['strings'] as $line ) { if ( '*' === substr( $line, -1 ) ) { $prefixes[] = $line; } else { $exact[] = $line; } }
		$rules = Policy::normalize( array( 'mode' => 'custom', 'exact' => $exact, 'prefixes' => $prefixes, 'excluded' => self::lines( $s['excluded'], 100 ) ) );
		$s['strings'] = array_merge( $rules['exact'], $rules['prefixes'] ); $s['excluded'] = $rules['excluded'];
		$s['families'] = self::lines( $s['families'], 7 ); // Six fixed families plus the form's empty sentinel.
		foreach ( $s['families'] as $family ) { if ( ! isset( Crawler::sources()[ $family ] ) ) { throw new \InvalidArgumentException( __( 'This crawler has no qualified UA/IP family mapping.', 'quard' ) ); } }
		foreach ( array( 'bots', 'strings', 'excluded', 'families' ) as $key ) { $s[ $key ] = array_values( array_unique( $s[ $key ] ) ); sort( $s[ $key ], SORT_STRING ); }
		if ( $s['enabled'] && ( ! $s['bots'] || ! $s['strings'] ) ) { throw new \InvalidArgumentException( __( 'Enabled Dull Knife requires bot tokens and dynamic parameter rules.', 'quard' ) ); }
		if ( $s['verified_enabled'] && ! $s['families'] ) { throw new \InvalidArgumentException( __( 'Select at least one supported crawler family.', 'quard' ) ); }
		return $s;
	}
	public static function settings() {
		try { return self::normalize( get_option( self::OPTION, self::defaults() ) ); }
		catch ( \InvalidArgumentException $e ) { throw new \RuntimeException( 'Stored Dull Knife settings are invalid; export refused. ' . $e->getMessage() ); }
	}
	public static function active() { $s = self::settings(); return $s['enabled'] || $s['verified_enabled']; }
	public static function guard( $input ) {
		try { $s = self::normalize( $input ); if ( ( $s['enabled'] || $s['verified_enabled'] ) && class_exists( 'Quard\\Throttle' ) && 'off' !== Throttle::requested()['mode'] ) { throw new \InvalidArgumentException( __( 'Keep optional throttling Off before preparing Dull/crawler rules; combined deployment is not qualified.', 'quard' ) ); } return $s; }
		catch ( \InvalidArgumentException $e ) {
			if ( defined( 'WP_CLI' ) && WP_CLI && 'cli' === PHP_SAPI ) { \WP_CLI::error( $e->getMessage() ); }
			add_settings_error( 'quard_dull', 'quard_dull_invalid', $e->getMessage(), 'error' ); return self::settings();
		}
	}
	public static function budget_guard( $input ) {
		if ( is_array( $input ) && isset( $input['mode'] ) && 'off' !== $input['mode'] && self::active() ) {
			$message = __( 'Dull/crawler policy and optional throttling are not qualified together. Keep throttling Off.', 'quard' );
			if ( defined( 'WP_CLI' ) && WP_CLI && 'cli' === PHP_SAPI ) { \WP_CLI::error( $message ); }
			add_settings_error( 'quard_throttle', 'quard_knives_budget', $message, 'error' ); return Throttle::requested();
		}
		return $input;
	}
	public static function sanitize( $input ) {
		if ( ! current_user_can( 'manage_options' ) ) { return self::settings(); }
		$s = self::guard( $input );
		if ( function_exists( 'wp_set_option_autoload' ) ) { wp_set_option_autoload( self::OPTION, false ); }
		return $s;
	}
	public static function effective( array $s, array $sharp ) {
		$exact = array(); $prefixes = array(); foreach ( $s['strings'] as $key ) { if ( '*' === substr( $key, -1 ) ) { $prefixes[] = $key; } else { $exact[] = $key; } }
		$paths = array_merge( $sharp['excluded'], $sharp['exceptions'], $s['excluded'], array( '/robots.txt', '/wp-sitemap.xml', '/sitemap.xml' ) ); $paths = array_values( array_unique( $paths ) ); sort( $paths, SORT_STRING );
		return array( 'exact' => $exact, 'prefixes' => $prefixes, 'excluded' => $paths, 'exceptions' => array(), 'no_clearance_keys' => Policy::NO_CLEARANCE_KEYS );
	}
	public static function classify( array $s, array $sharp, $uri, $method, $ua ) {
		$q = self::effective( $s, $sharp ); $parts = explode( '?', $uri, 2 ); $args = isset( $parts[1] ) ? $parts[1] : ''; $c = array( 'protected' => false, 'excluded' => false );
		foreach ( $q['exact'] as $key ) { $c['protected'] = $c['protected'] || preg_match( '~' . Policy::query_pattern( array( $key ) ) . '~i', $args ); }
		foreach ( $q['prefixes'] as $key ) { $c['protected'] = $c['protected'] || preg_match( '~' . Policy::query_pattern( array(), array( $key ) ) . '~i', $args ); }
		foreach ( $q['excluded'] as $path ) { $c['excluded'] = $c['excluded'] || preg_match( '~' . Policy::path_pattern( array( $path ) ) . '~i', $parts[0] ); }
		$bot = false; foreach ( $s['bots'] as $token ) { if ( false !== stripos( $ua, $token ) ) { $bot = true; } }
		return $s['enabled'] && in_array( $method, array( 'GET', 'HEAD' ), true ) && $bot && $c['protected'] && ! $c['excluded'];
	}
	public static function adapt( $base, $engine ) {
		if ( ! self::active() ) { return $base; }
		if ( class_exists( 'Quard\\Throttle' ) && 'off' !== Throttle::requested()['mode'] ) { throw new \RuntimeException( __( 'Dull/crawler exports require optional throttling Off; this combination is not qualified.', 'quard' ) ); }
		if ( 'nginx' !== $engine ) { throw new \RuntimeException( __( 'Dull Knife and trusted crawler exemptions are Nginx-only in 0.3.0-dev. No Apache/LiteSpeed exemption is generated.', 'quard' ) ); }
		return new KnivesNginx( $base, Plugin::policy(), self::settings() );
	}
}
