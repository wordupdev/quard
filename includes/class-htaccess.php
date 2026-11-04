<?php
/** Document-root Apache rules and a separately labelled LiteSpeed candidate. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Htaccess {
	private $policy;
	private $host;
	private $engine;

	public function __construct( array $policy, $host, $engine = 'apache' ) {
		if ( ! in_array( $engine, array( 'apache', 'litespeed-enterprise' ), true ) ) {
			throw new \InvalidArgumentException( 'OpenLiteSpeed has no qualified adapter in this release.' );
		}
		if ( strlen( $host ) > 253 || ! preg_match( '/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z/D', $host ) ) {
			throw new \InvalidArgumentException( 'A valid ASCII hostname is required.' );
		}
		// The effective policy may include preset/site entries beyond the 100 user rules.
		$clean = Policy::normalize( array_merge( $policy, array( 'exact' => array(), 'prefixes' => array(), 'excluded' => array(), 'exceptions' => array() ) ) );
		foreach ( array( 'exact', 'prefixes', 'excluded', 'exceptions' ) as $key ) {
			if ( ! isset( $policy[ $key ] ) || ! is_array( $policy[ $key ] ) || count( $policy[ $key ] ) > 128 ) {
				throw new \InvalidArgumentException( 'Invalid effective rule list.' );
			}
			foreach ( $policy[ $key ] as $rule ) {
				if ( ! is_string( $rule ) || strpbrk( $rule, "\r\n\0" ) !== false ) {
					throw new \InvalidArgumentException( 'Rule contains a forbidden control character.' );
				}
				$one = Policy::normalize( array( $key => array( $rule ) ) );
				if ( $one[ $key ] !== array( $rule ) ) {
					throw new \InvalidArgumentException( 'Rules must be normalized before generation.' );
				}
				$clean[ $key ][] = $rule;
			}
		}
		$clean['no_clearance_keys'] = Policy::NO_CLEARANCE_KEYS;
		$this->policy = $clean;
		$this->host = $host;
		$this->engine = $engine;
		if ( 'litespeed-enterprise' === $engine && 403 !== $clean['response'] ) {
			throw new \InvalidArgumentException( 'LiteSpeed Enterprise candidate supports 403 only; 410/429 are not live qualified.' );
		}
	}

	public function fingerprint() {
		return hash( 'sha256', wp_json_encode( array( 'adapter' => hash_file( 'sha256', __FILE__ ), 'policy' => $this->policy, 'host' => $this->host, 'engine' => $this->engine ) ) );
	}

	public function capabilities() {
		return array( 'engine' => $this->engine, 'readiness' => 'apache' === $this->engine ? 'Uncached Apache profile; native module inventory and site tests required' : 'NOT TESTED LIVE — blocking-only candidate; issuer not qualified', 'managed' => 'apache' === $this->engine, 'issuer' => 'apache' === $this->engine, 'apache_cache_hit_verified' => false, 'responses' => 'apache' === $this->engine ? array( 403, 410, 429 ) : array( 403 ) );
	}

	private function quote( $s ) {
		return '"' . str_replace( '"', '\\"', $s ) . '"';
	}

	private function mark( $variable, $pattern, $flag, $nocase = true ) {
		return 'RewriteCond ' . $variable . ' ' . $this->quote( $pattern ) . ( $nocase ? ' [NC]' : '' ) . "\nRewriteRule ^ - [E=QUARD_" . $flag . ":1]\n";
	}

	public function block() {
		$p = $this->policy;
		$hash = $this->fingerprint();
		$end = 'apache' === $this->engine ? 'END' : 'L';
		$out = "# BEGIN Quard\n# Engine: " . $this->engine . "\n# Policy: " . $hash . "\n";
		if ( 'apache' !== $this->engine ) {
			$out .= "# NOT TESTED LIVE. No clearance issuer. Manual candidate only; not ready for a storefront rollout.\n";
		}
		$out .= "# CACHED BACKENDS NOT QUALIFIED: QuickHandler HITs can bypass denial and issuance.\n# QuickHandler Off alone is insufficient. Operator cache-key/header qualification required.\nRewriteEngine On\n# Recompute from immutable raw request line on every per-directory pass.\n";
		$out .= "RewriteRule ^ - [E=QUARD_VALID:0,E=QUARD_PROTECTED:0,E=QUARD_EXCLUDED:0,E=QUARD_EXCEPTION:0,E=QUARD_OPERATION:0,E=QUARD_CLEAR:0]\n";
		$out .= 'RewriteCond %{THE_REQUEST} ' . $this->quote( '^[^\t ]+[\t ]+(?:https?://[^/\t ]+)?([^?\t ]+)(?:[?]([^\t ]*))?[\t ]+HTTP/' ) . " [NC]\n";
		$out .= "RewriteRule ^ - [E=QUARD_VALID:1,E=QUARD_PATH:%1,E=QUARD_QUERY:%2]\n";
		$out .= "RewriteCond %{ENV:QUARD_VALID} !=1\nRewriteRule ^ - [R=400," . $end . "]\n";
		foreach ( $p['exact'] as $name ) {
			$out .= $this->mark( '%{ENV:QUARD_QUERY}', Policy::query_pattern( array( $name ) ), 'PROTECTED' );
		}
		foreach ( $p['prefixes'] as $name ) {
			$out .= $this->mark( '%{ENV:QUARD_QUERY}', Policy::query_pattern( array(), array( $name ) ), 'PROTECTED' );
		}
		foreach ( array( 'excluded' => 'EXCLUDED', 'exceptions' => 'EXCEPTION' ) as $key => $flag ) {
			foreach ( $p[ $key ] as $path ) {
				$out .= $this->mark( '%{ENV:QUARD_PATH}', Policy::path_pattern( array( $path ) ), $flag );
			}
		}
		foreach ( $p['no_clearance_keys'] as $name ) {
			$out .= $this->mark( '%{ENV:QUARD_QUERY}', Policy::query_pattern( array( $name ) ), 'OPERATION' );
		}
		$out .= 'RewriteCond %{HTTP_COOKIE} ' . $this->quote( '(?:^|;\s*)quard_nav=1(?:;|$)' ) . ( 'apache' === $this->engine ? ' [NV]' : '' ) . "\n";
		$out .= 'RewriteCond %{HTTP_COOKIE} ' . $this->quote( '!(?:^|;\s*)quard_nav=[^;]*(?:;[^;]*)*;\s*quard_nav=' ) . ( 'apache' === $this->engine ? ' [NV]' : '' ) . "\nRewriteRule ^ - [E=QUARD_CLEAR:1]\n";
		if ( $p['enabled'] ) {
			$out .= "# Operational query names NEVER exempt a protected request.\nRewriteCond %{ENV:QUARD_PROTECTED} =1\nRewriteCond %{ENV:QUARD_EXCLUDED} !=1\nRewriteCond %{ENV:QUARD_EXCEPTION} !=1\nRewriteCond %{ENV:QUARD_CLEAR} !=1\n";
			$deny = 403 === $p['response'] ? 'F' : ( 410 === $p['response'] ? 'G' : 'R=429' );
			$out .= 'RewriteRule ^ - [' . $deny . ',' . $end . "]\n";
		}
		if ( 'apache' === $this->engine ) {
			$out .= 'Header always set X-Quard-Policy "' . $hash . "\"\nHeader always set X-Quard-Engine \"apache\"\nHeader always set X-Quard-Enabled \"" . ( $p['enabled'] ? 'on' : 'off' ) . "\"\n";
			if ( $p['enabled'] ) {
				// Late mod_headers expression: final status/type, no CO domain or rewrite-phase cookie.
				$expr = "%{REQUEST_METHOD} == 'GET' && %{REQUEST_STATUS} == 200 && %{CONTENT_TYPE} =~ m#^text/html(?:;|$)# && reqenv('QUARD_VALID') == '1' && reqenv('QUARD_PROTECTED') == '0' && reqenv('QUARD_EXCLUDED') == '0' && reqenv('QUARD_OPERATION') == '0' && reqenv('QUARD_CLEAR') == '0' && req('Accept') =~ m#(?i:text/html)# && req('X-Requested-With') == '' && req('Sec-Fetch-Dest') =~ m#^(?:document)?$# && resp('Set-Cookie') !~ m#(?:^|[;, ]+)quard_nav=#";
				$cookie = 'quard_nav=1; Path=/; Max-Age=' . ( $p['lifetime'] * 60 ) . '; HttpOnly; SameSite=Lax';
				$out .= 'Header always set Cache-Control "private, no-store" ' . $this->quote( 'expr=' . $expr ) . "\n";
				$out .= 'Header always add Set-Cookie ' . $this->quote( $cookie . '; Secure' ) . ' ' . $this->quote( "expr=" . $expr . " && %{HTTPS} == 'on'" ) . "\n";
				$out .= 'Header always add Set-Cookie ' . $this->quote( $cookie ) . ' ' . $this->quote( "expr=" . $expr . " && %{HTTPS} != 'on'" ) . "\n";
			}
		}
		return $out . "# END Quard\n";
	}

	public function files() {
		return array( 'quard-' . $this->engine . '.htaccess' => $this->block() );
	}
}
