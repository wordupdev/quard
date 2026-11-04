<?php
/** Small composition adapter. The original Sharp adapter stays byte-for-byte intact. */
namespace Quard;
defined( 'ABSPATH' ) || exit;
final class KnivesNginx {
	private $base; private $sharp; private $dull; private $snapshot; private $ns;
	public function __construct( Nginx $base, array $sharp, array $dull ) {
		$this->base = $base; $this->sharp = $sharp; $this->dull = Dull::normalize( $dull ); $this->snapshot = $dull['verified_enabled'] ? Crawler::load() : array( 'valid' => false, 'families' => array(), 'from' => 0, 'until' => 0, 'address' => 'remote_addr' ); $this->ns = $base->variable( 'knives' );
	}
	public function variable( $suffix ) { return $this->ns . '_' . $suffix; }
	public function fingerprint() {
		$s = $this->dull; $effective = array( 'dull' => $s['enabled'] ? array_intersect_key( $s, array_flip( array( 'enabled', 'bots', 'strings', 'excluded', 'response' ) ) ) : false, 'verified' => $s['verified_enabled'] ? $s['families'] : false );
		$data = array_intersect_key( $this->snapshot, array_flip( array( 'valid', 'families', 'from', 'until', 'address' ) ) );
		return hash( 'sha256', wp_json_encode( array( 'sharp' => $this->base->fingerprint(), 'code' => hash_file( 'sha256', __FILE__ ) . hash_file( 'sha256', __DIR__ . '/class-dull.php' ) . hash_file( 'sha256', __DIR__ . '/class-crawler.php' ), 'effective' => $effective, 'snapshot' => $data ) ) );
	}
	private function quote( $text ) { return '"' . str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), $text ) . '"'; }
	private function map( $source, $target, array $entries, $default = '0' ) {
		$out = 'map ' . $source . ' ' . $this->variable( $target ) . " {\n    default " . $this->quote( $default ) . ";\n";
		foreach ( $entries as $pattern => $value ) { $out .= '    ' . $this->quote( $pattern ) . ' ' . $this->quote( $value ) . ";\n"; } return $out . "}\n";
	}
	public function files() {
		$files = $this->base->files(); $s = $this->dull; $q = Dull::effective( $s, $this->sharp ); $v = function ( $n ) { return $this->variable( $n ); }; $core = function ( $n ) { return $this->base->variable( $n ); }; $hash = $this->fingerprint();
		foreach ( $files as &$text ) { $text = str_replace( $this->base->fingerprint(), $hash, $text ); } unset( $text );
		$http = "\n# Dull Knife and verified-crawler Sharp exemption. Native only; no UA-only bypass.\n";
		$http .= $this->map( '$request_method', 'read', array( 'GET' => '1', 'HEAD' => '1' ) );
		$entries = array(); foreach ( $q['exact'] as $key ) { $entries[ '~*' . Policy::query_pattern( array( $key ) ) ] = '1'; } foreach ( $q['prefixes'] as $key ) { $entries[ '~*' . Policy::query_pattern( array(), array( $key ) ) ] = '1'; }
		$http .= $this->map( $core( 'args' ), 'query', $entries );
		$paths = array(); foreach ( $q['excluded'] as $path ) { $paths[ '~*' . Policy::path_pattern( array( $path ) ) ] = '1'; }
		$http .= $this->map( $core( 'path' ), 'excluded', $paths );
		$tokens = array_map( function ( $t ) { return preg_quote( $t, '~' ); }, $s['bots'] );
		$http .= $this->map( '$http_user_agent', 'bot', $tokens ? array( '~*(?:' . implode( '|', $tokens ) . ')' => '1' ) : array() );
		$http .= $this->map( '"' . implode( ':', array( $core( 'host' ), $v( 'read' ), $v( 'bot' ), $v( 'query' ), $v( 'excluded' ) ) ) . '"', 'dull', $s['enabled'] ? array( '1:1:1:1:0' => '1' ) : array() );
		$data = $this->snapshot; $fresh = ! empty( $data['valid'] ) ? array( '~' . Crawler::time_pattern( $data['from'], $data['until'] ) => '1' ) : array();
		$http .= $this->map( '$msec', 'fresh', $s['verified_enabled'] ? $fresh : array() );
		$ua_bits = array(); $entries = array(); $families = array_keys( Crawler::sources() );
		foreach ( $families as $index => $family ) {
			$http .= $this->map( '$http_user_agent', 'ua_' . $index, array( '~*' . Crawler::ua_pattern( $family ) => '1' ) ); $ua_bits[] = $v( 'ua_' . $index );
			$http .= 'geo $' . $data['address'] . ' ' . $v( 'ip_' . $index ) . " {\n    default 0;\n";
			if ( $s['verified_enabled'] && in_array( $family, $s['families'], true ) && ! empty( $data['valid'] ) && isset( $data['families'][ $family ] ) ) { foreach ( $data['families'][ $family ]['cidrs'] as $cidr ) { $http .= '    ' . $cidr . " 1;\n"; } }
			$http .= "}\n";
			$bits = array_fill( 0, count( $families ), '0' ); $bits[ $index ] = '1'; $entries[ implode( ':', $bits ) ] = (string) ( $index + 1 );
		}
		$http .= $this->map( '"' . implode( ':', $ua_bits ) . '"', 'family', $entries );
		$ips = array(); foreach ( $families as $index => $family ) { $ips[ (string) ( $index + 1 ) ] = $v( 'ip_' . $index ); }
		$http .= $this->map( $v( 'family' ), 'family_ip', $ips );
		$http .= $this->map( '"' . $core( 'host' ) . ':' . $v( 'read' ) . ':' . $v( 'fresh' ) . ':' . $v( 'family_ip' ) . '"', 'verified', $s['verified_enabled'] ? array( '1:1:1:1' => '1' ) : array() );
		$http .= $this->map( '"' . $core( 'block' ) . ':' . $v( 'verified' ) . '"', 'sharp', array( '1:0' => '1' ) );
		$files['http.conf'] .= $http;
		$needle = 'if (' . $core( 'block' ) . ') { return ' . $this->sharp['response'] . '; }';
		$replacement = 'if (' . $v( 'dull' ) . ') { return ' . $s['response'] . "; }\n" . 'if (' . $v( 'sharp' ) . ') { return ' . $this->sharp['response'] . '; }';
		if ( 1 !== substr_count( $files['server.conf'], $needle ) ) { throw new \RuntimeException( 'Sharp export shape changed; refusing unsafe composition.' ); }
		$files['server.conf'] = str_replace( $needle, $replacement, $files['server.conf'] );
		return $files;
	}
}
