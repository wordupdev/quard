<?php
/** Nginx configuration export. This class never writes server-owned files. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Nginx {
	const NAVIGATION_PATH = '/__quard/navigation';
	private $policy;
	private $host;
	private $ns;

	public function __construct( array $policy, $host ) {
		if ( ! preg_match( '/\A[a-z0-9][a-z0-9.-]*\z/D', $host ) || strlen( $host ) > 253 ) {
			throw new \InvalidArgumentException( 'A valid ASCII site hostname is required.' );
		}
		$this->policy = $policy;
		$this->host   = $host;
		$this->ns     = 'quard_' . substr( hash( 'sha256', $host ), 0, 10 );
	}

	public function fingerprint() {
		return hash( 'sha256', wp_json_encode( array( 'adapter' => hash_file( 'sha256', __FILE__ ), 'policy_code' => hash_file( 'sha256', __DIR__ . '/class-policy.php' ), 'host' => $this->host, 'policy' => $this->policy ) ) );
	}

	public function variable( $suffix ) {
		return '$' . $this->ns . '_' . $suffix;
	}

	private function quote( $text ) {
		return '"' . str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), $text ) . '"';
	}

	private function map( $source, $name, array $entries, $default = '0' ) {
		$out = 'map ' . $source . ' ' . $this->variable( $name ) . " {\n    default " . $this->quote( $default ) . ";\n";
		foreach ( $entries as $key => $value ) {
			$out .= '    ' . $this->quote( $key ) . ' ' . $this->quote( $value ) . ";\n";
		}
		return $out . "}\n\n";
	}

	private function query_entries( array $exact, array $prefixes = array() ) {
		$entries = array();
		foreach ( $exact as $name ) {
			$entries[ '~*' . Policy::query_pattern( array( $name ) ) ] = '1';
		}
		foreach ( $prefixes as $name ) {
			$entries[ '~*' . Policy::query_pattern( array(), array( $name ) ) ] = '1';
		}
		return $entries;
	}

	private function path_entries( array $paths ) {
		$entries = array();
		foreach ( $paths as $path ) {
			$entries[ '~*' . Policy::path_pattern( array( $path ) ) ] = '1';
		}
		return $entries;
	}

	public function files() {
		$p = $this->policy;
		$v = function ( $name ) { return $this->variable( $name ); };
		$hash = $this->fingerprint();
		$intro = '# Quard ' . QUARD_VERSION . ' | ' . $this->host . "\n# Policy SHA-256: " . $hash . "\n# Generated from validated policy. Deploy as an administrator, then test and reload.\n";
		$http = $intro . "# HTTP context only. Variables are inert in virtual hosts that do not opt in.\n\n";
		$http .= $this->map( '$server_name', 'host', array( $this->host => '1' ) );
		$http .= $this->map( '$server_name', 'navigation_permitted', array() );
		$http .= $this->map( '$request_uri', 'args', array( '~^[^?]*[?](?<' . $this->ns . '_raw_args>.*)$' => '$' . $this->ns . '_raw_args' ), '' );
		$http .= $this->map( '$request_uri', 'path', array( '~^(?<' . $this->ns . '_raw_path>[^?]*)' => '$' . $this->ns . '_raw_path' ), '' );
		$http .= $this->map( $v( 'args' ), 'protected', $this->query_entries( $p['exact'], $p['prefixes'] ) );
		$http .= $this->map( $v( 'path' ), 'excluded_path', $this->path_entries( $p['excluded'] ) );
		$http .= $this->map( $v( 'args' ), 'operational_query', $this->query_entries( $p['no_clearance_keys'] ) );
		$http .= $this->map( $v( 'path' ), 'exception', $this->path_entries( $p['exceptions'] ) );
		$http .= $this->map( '$http_cookie', 'cookie_value', array( '~' . Policy::COOKIE_VALUE => '1' ) );
		$http .= $this->map( '$http_cookie', 'cookie_duplicate', array( '~' . Policy::COOKIE_DUPLICATE => '1' ) );
		$http .= $this->map( '"' . $v( 'cookie_value' ) . ':' . $v( 'cookie_duplicate' ) . '"', 'clear', array( '1:0' => '1' ) );
		$http .= $this->map( '"' . $v( 'host' ) . ':' . $v( 'protected' ) . ':' . $v( 'excluded_path' ) . ':' . $v( 'exception' ) . ':' . $v( 'clear' ) . '"', 'block', $p['enabled'] ? array( '1:1:0:0:0' => '1' ) : array() );
		$http .= $this->map( '$http_accept', 'html_accept', array( '~*text/html' => '1' ) );
		$http .= $this->map( '$http_x_requested_with', 'xhr', array( '~.+' => '1' ) );
		$http .= $this->map( '$http_sec_fetch_dest', 'navigation', array( '' => '1', 'document' => '1' ) );
		$http .= $this->map( '$sent_http_content_type', 'html_response', array( '~*^text/html(?:;|$)' => '1' ) );
		$http .= $this->map( '$scheme', 'secure', array( 'https' => '; Secure' ), '' );
		// Evaluation in the header filter sees the FINAL content type/status, including static cache hits.
		$source = '"' . implode( ':', array( $v( 'host' ), '$request_method', '$status', $v( 'protected' ), $v( 'excluded_path' ), $v( 'operational_query' ), $v( 'clear' ), $v( 'html_accept' ), $v( 'xhr' ), $v( 'navigation' ), $v( 'html_response' ) ) ) . '"';
		$http .= $this->map( $source, 'set_cookie', $p['enabled'] ? array( '1:GET:200:0:0:0:0:1:0:1:1' => 'quard_nav=1; Path=/; Max-Age=' . ( $p['lifetime'] * 60 ) . '; HttpOnly; SameSite=Lax' . $v( 'secure' ) ) : array(), '' );
		// Only the exact native location sets permission, after method/origin/header/query checks.
		$http .= $this->map( '"' . $v( 'host' ) . ':' . $v( 'navigation_permitted' ) . ':$status:' . $v( 'clear' ) . '"', 'renew_cookie', $p['enabled'] ? array( '1:1:204:0' => 'quard_nav=1; Path=/; Max-Age=' . ( $p['lifetime'] * 60 ) . '; HttpOnly; SameSite=Lax' . $v( 'secure' ) ) : array(), '' );
		$http .= $this->map( '$uri', 'navigation_cache', array( self::NAVIGATION_PATH => 'private, no-store, max-age=0' ), '' );
		$http .= $this->map( $v( 'host' ), 'navigation_capability', $p['enabled'] ? array( '1' => 'nginx' ) : array(), '' );
		$http .= $this->map( $v( 'host' ), 'policy', array( '1' => $hash ), '' );
		$http .= $this->map( $v( 'host' ), 'enabled', array( '1' => $p['enabled'] ? 'on' : 'off' ), '' );
		$server = $intro . "# SERVER context, before existing locations. Keep Virtualmin's FastCGI and rewrites.\n";
		$server .= 'set ' . $v( 'navigation_permitted' ) . " 0;\n";
		$server .= 'if (' . $v( 'block' ) . ') { return ' . $p['response'] . "; }\n";
		$server .= "# Repeat this capability param in PHP locations that define their own fastcgi_param array.\nfastcgi_param QUARD_NAVIGATION_RECOVERY 1;\n";
		$server .= 'location = ' . self::NAVIGATION_PATH . " {\n";
		$server .= "    if (\$request_method != POST) { return 405; }\n    if (\$args != \"\") { return 400; }\n    if (\$http_origin != \"\$scheme://\$http_host\") { return 403; }\n    if (\$http_x_quard_navigation != \"1\") { return 403; }\n";
		$server .= '    set ' . $v( 'navigation_permitted' ) . " 1;\n    return 204;\n}\n";
		$server .= "# Include the generated headers file here AND in HTML locations with their own add_header.\n";
		$headers = $intro . "# SERVER or LOCATION context. Use once per applicable context.\n";
		// GET/200 and permitted POST/204 issuers are mutually exclusive: one header, no duplicates.
		$headers .= 'add_header Set-Cookie "' . $v( 'set_cookie' ) . $v( 'renew_cookie' ) . "\" always;\n";
		$headers .= 'add_header X-Quard-Policy ' . $v( 'policy' ) . " always;\n";
		$headers .= 'add_header X-Quard-Enabled ' . $v( 'enabled' ) . " always;\n";
		$headers .= 'add_header X-Quard-Navigation ' . $v( 'navigation_capability' ) . " always;\n";
		$headers .= 'add_header Cache-Control ' . $v( 'navigation_cache' ) . " always;\n";
		return array( 'http.conf' => $http, 'server.conf' => $server, 'headers.conf' => $headers );
	}
}
