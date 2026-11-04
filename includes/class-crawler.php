<?php
/** Operator-published public CIDRs. No DNS/HTTP on the request path. */
namespace Quard;
defined( 'ABSPATH' ) || exit;
final class Crawler {
	public static function sources() {
		return array( 'bingbot' => 'https://www.bing.com/toolbox/bingbot.json', 'chatgpt-user' => 'https://openai.com/chatgpt-user.json', 'googlebot' => 'https://developers.google.com/crawling/ipranges/common-crawlers.json', 'gptbot' => 'https://openai.com/gptbot.json', 'oai-adsbot' => 'https://openai.com/adsbot.json', 'oai-searchbot' => 'https://openai.com/searchbot.json' );
	}
	public static function ua_pattern( $family ) {
		$token = 'googlebot' === $family ? 'Googlebot(?:-(?:Image|News|Video))?' : preg_quote( $family, '~' );
		return '(?:^|[^a-z0-9_-])' . $token . '(?:/|[^a-z0-9_-]|$)';
	}
	public static function path() {
		$root = realpath( ABSPATH ); $host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		return dirname( $root ) . '/.quard-crawlers/' . substr( hash( 'sha256', $host . '|' . $root ), 0, 16 ) . '.json';
	}
	public static function cidr_valid( $cidr ) {
		if ( ! is_string( $cidr ) || ! preg_match( '/\A([0-9a-fA-F:.]+)\/([0-9]{1,3})\z/D', $cidr, $m ) || false === ( $ip = @inet_pton( $m[1] ) ) ) { return false; }
		$bits = 8 * strlen( $ip ); $prefix = (int) $m[2];
		if ( $prefix < ( 32 === $bits ? 8 : 16 ) || $prefix > $bits || ! filter_var( $m[1], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) { return false; }
		// PHP's reserved-address filter omits some documentation/multicast ranges.
		if ( 128 === $bits ) {
			if ( ( ord( $ip[0] ) & 0xe0 ) !== 0x20 || substr( $ip, 0, 4 ) === substr( inet_pton( '2001:db8::' ), 0, 4 ) ) { return false; }
		} else {
			$octets = array_values( unpack( 'C4', $ip ) );
			if ( $octets[0] >= 224 || ( 100 === $octets[0] && $octets[1] >= 64 && $octets[1] <= 127 ) || in_array( substr( $ip, 0, 3 ), array( substr( inet_pton( '192.0.2.0' ), 0, 3 ), substr( inet_pton( '198.51.100.0' ), 0, 3 ), substr( inet_pton( '203.0.113.0' ), 0, 3 ) ), true ) ) { return false; }
		}
		for ( $i = $prefix; $i < $bits; ++$i ) { if ( ord( $ip[ intdiv( $i, 8 ) ] ) & ( 1 << ( 7 - $i % 8 ) ) ) { return false; } }
		return true;
	}
	public static function contains( $ip, $cidr ) {
		if ( ! self::cidr_valid( $cidr ) ) { return false; } $a = @inet_pton( $ip ); list( $address, $prefix ) = explode( '/', $cidr ); $b = inet_pton( $address );
		if ( false === $a || strlen( $a ) !== strlen( $b ) ) { return false; }
		for ( $i = 0; $i < (int) $prefix; ++$i ) { if ( ( ord( $a[ intdiv( $i, 8 ) ] ) ^ ord( $b[ intdiv( $i, 8 ) ] ) ) & ( 1 << ( 7 - $i % 8 ) ) ) { return false; } } return true;
	}
	public static function load() {
		$bad = array( 'valid' => false, 'fresh' => false, 'reason' => 'Missing, unreadable or invalid operator snapshot: new exports grant no exemption. Review any previously loaded rules.', 'families' => array(), 'from' => 0, 'until' => 0, 'address' => 'remote_addr' ); $path = self::path(); clearstatcache( true );
		if ( ! is_file( $path ) || is_link( $path ) || is_link( dirname( $path ) ) || realpath( $path ) !== $path || 0 !== @fileowner( $path ) || 0 !== @fileowner( dirname( $path ) ) || 0640 !== ( @fileperms( $path ) & 0777 ) || 0750 !== ( @fileperms( dirname( $path ) ) & 0777 ) || @filesize( $path ) > 1000000 ) { return $bad; }
		$d = json_decode( (string) @file_get_contents( $path ), true );
		if ( ! is_array( $d ) || ! isset( $d['schema'], $d['site'], $d['root'], $d['from'], $d['until'], $d['families'], $d['address'], $d['direct_attested'] ) || 1 !== $d['schema'] || $d['site'] !== strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) || $d['root'] !== realpath( ABSPATH ) || true !== $d['direct_attested'] || ! is_int( $d['from'] ) || ! is_int( $d['until'] ) || $d['from'] < 1 || $d['until'] <= $d['from'] || $d['until'] - $d['from'] > 86400 || $d['from'] > time() + 5 || ! in_array( $d['address'], array( 'realip_remote_addr', 'remote_addr' ), true ) || ! is_array( $d['families'] ) || count( $d['families'] ) > 6 ) { return $bad; }
		foreach ( $d['families'] as $family => $data ) {
			if ( ! isset( self::sources()[ $family ], $data['url'], $data['sha256'], $data['creation'], $data['cidrs'] ) || self::sources()[ $family ] !== $data['url'] || ! is_string( $data['sha256'] ) || ! preg_match( '/\A[a-f0-9]{64}\z/D', $data['sha256'] ) || ! is_string( $data['creation'] ) || ! is_array( $data['cidrs'] ) || ! $data['cidrs'] || count( $data['cidrs'] ) > 5000 ) { return $bad; }
			foreach ( $data['cidrs'] as $cidr ) { if ( ! self::cidr_valid( $cidr ) ) { return $bad; } }
		}
		$d['valid'] = true; $d['fresh'] = $d['from'] <= time() && time() < $d['until']; $d['reason'] = $d['fresh'] ? 'Fresh official snapshot; UA plus original socket address required. No real crawler visit is attested.' : 'Expired snapshot: no new exemption. Inspect loaded native expiry; refresh, export and redeploy.';
		return $d;
	}
	/** Compact decimal interval regex for native $msec; independent of server timezone. */
	public static function time_pattern( $from, $until ) {
		$parts = array(); $last = $until - 1;
		while ( $from <= $last ) {
			$unit = 1; $digits = 0;
			while ( 0 === $from % ( $unit * 10 ) && $from + $unit * 10 - 1 <= $last ) { $unit *= 10; ++$digits; }
			$parts[] = (string) intdiv( $from, $unit ) . ( $digits ? '[0-9]{' . $digits . '}' : '' ); $from += $unit;
		}
		return '^(?:' . implode( '|', $parts ) . ')[.][0-9]+$';
	}
	public static function verified( array $snapshot, array $families, $ip, $ua, $when = null ) {
		$when = null === $when ? time() : $when;
		if ( empty( $snapshot['valid'] ) || $when < $snapshot['from'] || $when >= $snapshot['until'] ) { return false; }
		$matches = array(); foreach ( self::sources() as $family => $url ) { if ( preg_match( '~' . self::ua_pattern( $family ) . '~i', $ua ) ) { $matches[] = $family; } }
		if ( 1 !== count( $matches ) || ! in_array( $matches[0], $families, true ) || empty( $snapshot['families'][ $matches[0] ] ) ) { return false; }
		foreach ( $snapshot['families'][ $matches[0] ]['cidrs'] as $cidr ) { if ( self::contains( $ip, $cidr ) ) { return true; } } return false;
	}
}
