<?php
/** Read-only operator evidence. No server commands, privileged writes or request accounting. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Capability {
	const SCHEMA = 1;

	public static function contract() {
		return hash( 'sha256', hash_file( 'sha256', __FILE__ ) . hash_file( 'sha256', __DIR__ . '/class-throttle.php' ) );
	}

	public static function path() {
		$root = realpath( ABSPATH );
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		return dirname( $root ? $root : rtrim( ABSPATH, '/\\' ) ) . '/.quard-capabilities/' . substr( hash( 'sha256', $host . '|' . $root ), 0, 16 ) . '.json';
	}

	private static function unknown( $reason, $time = 0 ) {
		return array( 'state' => 'unknown', 'reason_code' => 'unknown', 'label' => __( 'Throttling capability unknown', 'quard' ), 'reason' => $reason, 'time' => $time, 'effective' => '' );
	}

	/** The operator confirms a loaded generation; a reload/restart invalidates that evidence. */
	public static function generation( $pid ) {
		if ( ! is_int( $pid ) || $pid < 2 ) { return false; }
		$stat = @file_get_contents( '/proc/' . $pid . '/stat' );
		$cmd = @file_get_contents( '/proc/' . $pid . '/cmdline' );
		$children = @file_get_contents( '/proc/' . $pid . '/task/' . $pid . '/children' );
		if ( ! $stat || ! $cmd || false === strpos( $cmd, 'nginx: master process' ) || false === $children || ! preg_match( '/^\d+ \(.*\) (.*)$/s', $stat, $m ) ) { return false; }
		$fields = preg_split( '/\s+/', trim( $m[1] ) );
		$workers = array();
		foreach ( preg_split( '/\s+/', trim( $children ) ) as $child ) {
			if ( ! ctype_digit( $child ) ) { continue; }
			$c = @file_get_contents( '/proc/' . $child . '/cmdline' );
			if ( ! $c || false === strpos( $c, 'nginx: worker process' ) || false !== strpos( $c, 'shutting down' ) ) { continue; }
			$s = @file_get_contents( '/proc/' . $child . '/stat' );
			if ( ! $s || ! preg_match( '/^\d+ \(.*\) (.*)$/s', $s, $v ) ) { return false; }
			$f = preg_split( '/\s+/', trim( $v[1] ) );
			if ( ! isset( $f[19] ) ) { return false; }
			$workers[] = array( 'pid' => (int) $child, 'start' => $f[19] );
		}
		usort( $workers, function ( $a, $b ) { return $a['pid'] <=> $b['pid']; } );
		return isset( $fields[19] ) && $workers ? array( 'pid' => $pid, 'start' => $fields[19], 'workers' => $workers ) : false;
	}

	public static function inspect( $probe = false ) {
		$missing = __( 'An operator must audit the effective Nginx configuration and install a read-only capability record. Active modes are unavailable until then; cold protection is independent.', 'quard' );
		$stale = __( 'The operator evidence is stale, unreadable or inconsistent. Keep throttling Off and request a fresh audit; WordPress cannot inspect loaded Nginx configuration automatically.', 'quard' );
		$path = self::path();
		clearstatcache( true );
		if ( ! is_file( $path ) ) { return self::unknown( $missing ); }
		if ( is_link( $path ) || is_link( dirname( $path ) ) || realpath( $path ) !== $path || 0 !== @fileowner( $path ) || 0 !== @fileowner( dirname( $path ) ) || 0640 !== ( @fileperms( $path ) & 0777 ) || 0750 !== ( @fileperms( dirname( $path ) ) & 0777 ) || @filesize( $path ) > 65536 || ! is_readable( $path ) ) { return self::unknown( $stale ); }
		$d = json_decode( (string) @file_get_contents( $path ), true );
		$root = realpath( ABSPATH );
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		if ( ! is_array( $d ) || ! isset( $d['schema'], $d['site'], $d['home'], $d['root'], $d['contract'], $d['core'], $d['created'], $d['state'], $d['files'], $d['access'], $d['globs'], $d['generation'], $d['effective'] ) || self::SCHEMA !== $d['schema'] || $host !== $d['site'] || home_url( '/' ) !== $d['home'] || $root !== $d['root'] || ! hash_equals( self::contract(), (string) $d['contract'] ) || ! is_int( $d['created'] ) || $d['created'] < 1 || $d['created'] > time() + 5 ) { return self::unknown( $stale ); }
		$core = new Nginx( Plugin::policy(), $host );
		if ( ! hash_equals( $core->fingerprint(), (string) $d['core'] ) || ! is_array( $d['files'] ) || ! $d['files'] || count( $d['files'] ) > 256 || ! is_array( $d['globs'] ) || count( $d['globs'] ) > 64 || ! is_array( $d['generation'] ) || ! isset( $d['generation']['pid'] ) || self::generation( $d['generation']['pid'] ) !== $d['generation'] ) { return self::unknown( $stale, $d['created'] ); }
		if ( ! is_array( $d['access'] ) || ! $d['access'] || count( $d['access'] ) > 1024 ) { return self::unknown( $stale, $d['created'] ); }
		foreach ( $d['access'] as $name => $metadata ) {
			$st = is_string( $name ) && '/' === substr( $name, 0, 1 ) ? @stat( $name ) : false;
			if ( ! $st || array( 'uid' => $st['uid'], 'gid' => $st['gid'], 'mode' => $st['mode'] & 0777 ) !== $metadata ) { return self::unknown( $stale, $d['created'] ); }
		}
		foreach ( $d['files'] as $name => $digest ) {
			if ( ! is_string( $name ) || '/' !== substr( $name, 0, 1 ) || ! is_string( $digest ) || ! preg_match( '/\A[a-f0-9]{64}\z/D', $digest ) || ! is_readable( $name ) || ! is_file( $name ) || ! hash_equals( $digest, (string) @hash_file( 'sha256', $name ) ) ) { return self::unknown( $stale, $d['created'] ); }
		}
		foreach ( $d['globs'] as $pattern => $expected ) {
			$found = is_string( $pattern ) && '/' === substr( $pattern, 0, 1 ) ? glob( $pattern ) : false;
			if ( false === $found || ! is_array( $expected ) || count( $expected ) > 256 ) { return self::unknown( $stale, $d['created'] ); }
			sort( $found, SORT_STRING );
			if ( $found !== $expected ) { return self::unknown( $stale, $d['created'] ); }
		}
		if ( 'unsupported' === $d['state'] ) {
			$existing = isset( $d['reason'] ) && 'existing_limits' === $d['reason'];
			return array( 'state' => 'unsupported', 'reason_code' => $existing ? 'existing_limits' : 'unqualified', 'label' => $existing ? __( 'Throttling unsupported — existing Nginx rate limits would be affected.', 'quard' ) : __( 'Throttling unsupported on this audited configuration', 'quard' ), 'reason' => $existing ? __( 'Observe can disable existing enforcement. Enforce can change rejection codes and shared-bucket behavior. Leave throttling Off; cold protection remains independent.', 'quard' ) : __( 'The operator audit found an unqualified identity, error-handler or configuration profile. Active budgets are refused.', 'quard' ), 'time' => $d['created'], 'effective' => $d['effective'] );
		}
		if ( 'available' !== $d['state'] || empty( $d['module_verified'] ) || empty( $d['dry_run_verified'] ) || empty( $d['exclusive_limits'] ) || empty( $d['socket_identity_verified'] ) || empty( $d['loaded_confirmed'] ) || empty( $d['reader_verified'] ) ) { return self::unknown( $stale, $d['created'] ); }
		$r = array( 'state' => 'available', 'reason_code' => 'exclusive', 'label' => __( 'Throttling available — exclusive Nginx profile audited', 'quard' ), 'reason' => __( 'Operator evidence matches current files, includes, code and loaded worker generation. Saving settings still requires a separate deployment and runtime checks.', 'quard' ), 'time' => $d['created'], 'effective' => $d['effective'] );
		return $probe ? self::with_reply( $r, Diagnostics::request_url( home_url( '/' ), 'HEAD', '', 1.5 ) ) : $r;
	}

	public static function with_reply( array $cap, $reply ) {
		if ( 'available' !== $cap['state'] ) { return $cap; }
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$nginx = new Nginx( Plugin::policy(), $host );
		if ( is_wp_error( $reply ) || 200 !== wp_remote_retrieve_response_code( $reply ) || 'on' !== wp_remote_retrieve_header( $reply, 'x-quard-enabled' ) || ! hash_equals( $nginx->fingerprint(), (string) wp_remote_retrieve_header( $reply, 'x-quard-policy' ) ) ) { return self::unknown( __( 'The current cold-protection response cannot be matched. Active modes remain unavailable; check server deployment and loopback HTTP.', 'quard' ), $cap['time'] ); }
		return $cap;
	}

	public static function require_available() {
		$cap = self::inspect( true );
		if ( 'available' !== $cap['state'] ) { throw new \RuntimeException( $cap['label'] . ' ' . $cap['reason'] ); }
		return $cap;
	}
}
