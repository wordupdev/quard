<?php
/** Optional Nginx budgets. Separate settings/revision; no PHP request accounting or privileged writes. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Throttle {
	const OPTION = 'quard_throttle_settings';
	private $settings;
	private $policy;
	private $nginx;
	private $namespace;

	public static function defaults() {
		return array( 'mode' => 'off', 'client_rate' => 60, 'client_burst' => 10, 'site_enabled' => false, 'site_rate' => 600, 'site_burst' => 50 );
	}

	public static function normalize( $input ) {
		if ( ! is_array( $input ) || array_diff_key( $input, self::defaults() ) ) { throw new \InvalidArgumentException( __( 'Unsupported dynamic throttling settings.', 'quard' ) ); }
		$s = array_merge( self::defaults(), $input );
		if ( ! in_array( $s['mode'], array( 'off', 'observe', 'enforce' ), true ) || ! in_array( $s['site_enabled'], array( true, false, 1, 0, '1', '0' ), true ) ) { throw new \InvalidArgumentException( __( 'Choose Off, Observe or Enforce and a valid aggregate switch.', 'quard' ) ); }
		foreach ( array( 'client_rate' => array( 1, 6000 ), 'client_burst' => array( 0, 200 ), 'site_rate' => array( 1, 60000 ), 'site_burst' => array( 0, 1000 ) ) as $key => $bounds ) {
			if ( ! ( is_int( $s[ $key ] ) || is_string( $s[ $key ] ) ) || ! preg_match( '/\A(?:0|[1-9][0-9]{0,5})\z/D', (string) $s[ $key ] ) || $s[ $key ] < $bounds[0] || $s[ $key ] > $bounds[1] ) { throw new \InvalidArgumentException( __( 'Use whole-number request rates and bursts within the displayed bounds.', 'quard' ) ); }
			$s[ $key ] = (int) $s[ $key ];
		}
		$s['site_enabled'] = (bool) $s['site_enabled'];
		return $s;
	}

	public static function requested() {
		try { return self::normalize( get_option( self::OPTION, self::defaults() ) ); }
		catch ( \InvalidArgumentException $e ) { return self::defaults(); }
	}


	/** Unsupported imported/raw desires cannot become effective settings or active exports. */
	public static function settings() {
		$s = self::requested();
		if ( 'off' !== $s['mode'] && 'available' !== Capability::inspect()['state'] ) { $s['mode'] = 'off'; }
		return $s;
	}

	public static function guard_option( $input ) {
		try {
			$s = self::normalize( $input );
			if ( 'off' !== $s['mode'] ) { Capability::require_available(); }
			return $s;
		} catch ( \InvalidArgumentException | \RuntimeException $e ) {
			if ( defined( 'WP_CLI' ) && WP_CLI && 'cli' === PHP_SAPI ) { \WP_CLI::error( $e->getMessage() ); }
			if ( function_exists( 'add_settings_error' ) ) { add_settings_error( 'quard_throttle', 'quard_throttle_blocked', $e->getMessage(), 'error' ); }
			return self::settings();
		}
	}

	public static function sanitize( $input ) {
		if ( ! current_user_can( 'manage_options' ) && ! ( defined( 'WP_CLI' ) && WP_CLI && 'cli' === PHP_SAPI ) ) { return self::settings(); }
		try {
			$s = self::guard_option( $input );
			if ( function_exists( 'wp_set_option_autoload' ) ) { wp_set_option_autoload( self::OPTION, false ); }
			if ( $s !== self::normalize( $input ) ) { return $s; }
			add_settings_error( 'quard_throttle', 'quard_throttle_saved', __( 'Desired budgets saved. Nothing changes on the server until an operator validates, deploys and tests the separate throttle configuration.', 'quard' ), 'success' );
			return $s;
		} catch ( \InvalidArgumentException $e ) {
			add_settings_error( 'quard_throttle', 'quard_throttle_invalid', $e->getMessage(), 'error' );
			return self::settings();
		}
	}

	public function __construct( array $settings, array $policy, $host ) {
		$this->settings = self::normalize( $settings );
		$this->policy = $policy;
		$this->nginx = new Nginx( $policy, $host );
		$this->namespace = 'quard_t_' . substr( hash( 'sha256', $host ), 0, 10 );
	}

	public static function adapter() {
		return new self( self::requested(), Plugin::policy(), strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) );
	}

	public function fingerprint() {
		return hash( 'sha256', wp_json_encode( array( 'code' => hash_file( 'sha256', __FILE__ ), 'protection' => $this->nginx->fingerprint(), 'budgets' => $this->settings ) ) );
	}

	public function variable( $name ) { return '$' . $this->namespace . '_' . $name; }
	public function zone( $name ) { return $this->namespace . '_' . $name; }

	/** Facts must come from the operator's current effective-config audit, never HTTP/admin input. */
	public static function require_context( array $facts, $mode ) {
		$cap = Capability::require_available();
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		if ( empty( $facts['created'] ) || ! is_int( $facts['created'] ) || $facts['created'] > time() || time() - $facts['created'] > 120 || empty( $facts['site'] ) || $host !== $facts['site'] || empty( $facts['contract'] ) || ! hash_equals( Capability::contract(), (string) $facts['contract'] ) || empty( $facts['nginx_effective_sha256'] ) || ! hash_equals( $cap['effective'], (string) $facts['nginx_effective_sha256'] ) ) { throw new \RuntimeException( 'Fresh matching operator preflight is required for active export.' ); }
		if ( empty( $facts['module_verified'] ) || empty( $facts['exclusive_limits'] ) || empty( $facts['socket_identity_verified'] ) || empty( $facts['dry_run_verified'] ) ) {
			throw new \RuntimeException( 'Active throttle export requires operator preflight: native module, socket client identity and an exclusive limit_req configuration. Observe must never put unrelated limits into dry run. Use the private operator exporter; shared-limit configurations are refused.' );
		}
	}

	public function files( array $facts = array() ) {
		$s = $this->settings;
		$active = 'off' !== $s['mode'];
		if ( $active ) {
			if ( ! $this->policy['enabled'] ) { throw new \RuntimeException( 'Enable and deploy cold-request protection before enabling dynamic throttling.' ); }
			self::require_context( $facts, $s['mode'] );
		}
		$v = function ( $name ) { return $this->variable( $name ); };
		$core = function ( $name ) { return $this->nginx->variable( $name ); };
		$intro = '# Quard dynamic throttling ' . QUARD_VERSION . "\n# Throttle SHA-256: " . $this->fingerprint() . "\n# Separate from the protection policy. Manual privileged deployment only.\n";
		$http = $intro . "# HTTP context, AFTER this site's core Quard maps. No other limit_req contexts allowed.\n";
		$http .= 'map "' . implode( ':', array( $core( 'host' ), $core( 'protected' ), $core( 'excluded_path' ), $core( 'exception' ), $core( 'clear' ) ) ) . '" ' . $v( 'eligible' ) . " {\n    default 0;\n";
		if ( $active ) { $http .= "    \"1:1:0:0:1\" 1;\n"; }
		$http .= "}\nmap " . $v( 'eligible' ) . ' ' . $v( 'client_key' ) . " {\n    default \"\";\n" . ( $active ? "    1 \$binary_remote_addr;\n" : '' ) . "}\n";
		$http .= 'map ' . $v( 'eligible' ) . ' ' . $v( 'site_key' ) . " {\n    default \"\";\n" . ( $active && $s['site_enabled'] ? '    1 "' . $this->namespace . "\";\n" : '' ) . "}\n";
		foreach ( array( 'revision' => $this->fingerprint(), 'mode' => $s['mode'] ) as $key => $value ) { $http .= 'map ' . $core( 'host' ) . ' ' . $v( $key ) . " { default \"\"; 1 \"" . $value . "\"; }\n"; }
		$http .= 'map "' . $v( 'eligible' ) . ( $active ? ':$limit_req_status' : ':' ) . '" ' . $v( 'result' ) . " {\n    default \"\";\n";
		foreach ( array( 'PASSED', 'REJECTED', 'REJECTED_DRY_RUN' ) as $result ) { $http .= '    "1:' . $result . '" "' . $result . "\";\n"; }
		$http .= "}\n";
		$server = $intro . "# SERVER context, alongside the existing core guard. Never inside if.\n# Refuse parent/child/unrelated limit_req directives; re-audit after config edits.\n";
		if ( $active ) {
			foreach ( array( 'client' => true, 'site' => $s['site_enabled'] ) as $kind => $enabled ) {
				if ( ! $enabled ) { continue; }
				$http .= 'limit_req_zone ' . $v( $kind . '_key' ) . ' zone=' . $this->zone( $kind ) . ( 'client' === $kind ? ':2m' : ':64k' ) . ' rate=' . $s[ $kind . '_rate' ] . "r/m;\n";
				$burst = $s[ $kind . '_burst' ];
				$server .= 'limit_req zone=' . $this->zone( $kind ) . ( $burst ? ' burst=' . $burst . ' nodelay' : '' ) . ";\n";
			}
			$server .= 'limit_req_dry_run ' . ( 'observe' === $s['mode'] ? 'on' : 'off' ) . ";\nlimit_req_status 429;\nlimit_req_log_level notice;\n";
		} else { $server .= "# Off: no zones, limit_req, dry-run or rejection-status directives.\n"; }
		$headers = $intro . "# Repeat once in every effective header context, preserving core/security headers.\n";
		foreach ( array( 'Policy' => 'revision', 'Mode' => 'mode', 'Result' => 'result' ) as $header => $var ) { $headers .= 'add_header X-Quard-Throttle-' . $header . ' ' . $v( $var ) . " always;\n"; }
		return array( 'throttle-http.conf' => $http, 'throttle-server.conf' => $server, 'throttle-headers.conf' => $headers );
	}

	/** Current capability and separate configuration observation; never a per-zone outcome claim. */
	public static function status() {
		$desired = self::adapter();
		$r = array( 'label' => __( 'Unsupported', 'quard' ), 'desired' => $desired->fingerprint(), 'observed' => '', 'mode' => '', 'time' => 0, 'capability' => 'unsupported', 'reason_code' => 'server', 'detail' => __( 'Dynamic throttling is supported only on an audited exclusive Nginx profile.', 'quard' ) );
		if ( 'nginx' !== Deployment::detect()['engine'] ) { return $r; }
		$cap = Capability::inspect();
		$reply = Diagnostics::request_url( home_url( '/' ), 'HEAD', '', 1.5 );
		$cap = Capability::with_reply( $cap, $reply );
		$r['capability'] = $cap['state'];
		$r['audit_time'] = $cap['time'];
		$r['reason_code'] = isset( $cap['reason_code'] ) ? $cap['reason_code'] : 'unknown';
		$r['requested_mode'] = self::requested()['mode'];
		$r['effective_desired_mode'] = self::settings()['mode'];
		$r['observed'] = is_wp_error( $reply ) ? '' : (string) wp_remote_retrieve_header( $reply, 'x-quard-throttle-policy' );
		$r['mode'] = is_wp_error( $reply ) ? '' : (string) wp_remote_retrieve_header( $reply, 'x-quard-throttle-mode' );
		$r['time'] = time();
		if ( 'available' !== $cap['state'] ) {
			$r['label'] = $cap['label']; $r['detail'] = $cap['reason'];
			if ( 'off' !== self::requested()['mode'] ) { $r['detail'] .= ' ' . __( 'A saved active request is unavailable under this capability gate. Save Off and have an operator review the server state.', 'quard' ); }
			if ( in_array( $r['mode'], array( 'observe', 'enforce' ), true ) ) { $r['detail'] .= ' ' . __( 'A server throttle integration is still observed. An operator must review or retire it; selecting Off does not remove server rules.', 'quard' ); }
			return $r;
		}
		$r['label'] = __( 'Not deployed', 'quard' );
		$r['detail'] = __( 'Exclusive profile available. Desired settings do not activate or remove server limits.', 'quard' );
		if ( $r['observed'] || $r['mode'] ) {
			$r['label'] = __( 'Drift detected', 'quard' );
			$r['detail'] = __( 'Observed throttle revision or mode differs from desired settings. Operator deployment and runtime tests are required.', 'quard' );
			if ( hash_equals( $r['desired'], $r['observed'] ) && self::requested()['mode'] === $r['mode'] ) {
				if ( in_array( $r['mode'], array( 'observe', 'enforce' ), true ) ) {
					$r['capability'] = 'active';
					$r['label'] = 'observe' === $r['mode'] ? __( 'Observing', 'quard' ) : __( 'Enforcing', 'quard' );
				} else { $r['label'] = __( 'Not deployed', 'quard' ); }
				$r['detail'] = __( 'Matching audited configuration observed. Rejection, upstream avoidance and capacity still require independent operator tests; no counters or shared result-header attribution are used here.', 'quard' );
			}
		}
		return $r;
	}
}
