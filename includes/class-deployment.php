<?php
/** Engine evidence, scoped preflight and explicit managed Apache actions. No privileged writes. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Deployment {
	const OPTION = 'quard_deployment';
	const WARNING = 'quard_cleanup_warning';

	/** Loaded modules are evidence of risk, never proof of effective cache configuration. */
	public static function cache_modules() {
		$found = array();
		foreach ( function_exists( 'apache_get_modules' ) ? apache_get_modules() : array() as $module ) {
			if ( false !== stripos( $module, 'cache' ) || false !== stripos( $module, 'pagespeed' ) ) { $found[] = $module; }
		}
		return $found;
	}

	public static function detect() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : '';
		$engine = 'unknown';
		$source = 'PHP server environment unavailable; manual export only';
		if ( function_exists( 'apache_get_version' ) && false === stripos( apache_get_version(), 'litespeed' ) ) {
			$engine = 'apache'; $source = 'apache_get_version()';
		} elseif ( false !== stripos( $software, 'OpenLiteSpeed' ) ) {
			$engine = 'openlitespeed'; $source = 'PHP SERVER_SOFTWARE; runtime not qualified';
		} elseif ( false !== stripos( $software, 'LiteSpeed' ) ) {
			$engine = 'litespeed-unknown'; $source = 'PHP SERVER_SOFTWARE does not prove Enterprise edition';
		} elseif ( preg_match( '~Apache/2\.4(?:\.|\s|$)~i', $software ) ) {
			$engine = 'apache'; $source = 'PHP SERVER_SOFTWARE; rewrite/header challenge still required';
		} elseif ( false !== stripos( $software, 'nginx' ) ) {
			$engine = 'nginx'; $source = 'PHP SERVER_SOFTWARE and existing exported-policy observation';
		}
		return array( 'engine' => $engine, 'source' => $source, 'confidence' => 'apache' === $engine && function_exists( 'apache_get_version' ) ? 'Native server API; override preflight required' : 'Backend hint; HTTP evidence required' );
	}

	public static function adapter( $engine = '' ) {
		if ( ! $engine ) { $engine = self::detect()['engine']; }
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		if ( in_array( $engine, array( 'apache', 'litespeed-enterprise' ), true ) ) {
			$base = new Htaccess( Plugin::policy(), $host, $engine );
			if ( class_exists( 'Quard\\Dull' ) && Dull::active() ) {
				throw new \RuntimeException( __( 'Dull Knife and verified crawler exemptions require Nginx. Use manual Sharp Knife-only export for this engine; managed deployment of these features is not supported.', 'quard' ) );
			}
			return $base;
		}
		if ( in_array( $engine, array( 'openlitespeed', 'litespeed-unknown' ), true ) ) { throw new \RuntimeException( 'This LiteSpeed edition has no qualified active adapter. Manual review is required.' ); }
		// CLI/unknown hosting retains the existing Nginx export contract; never auto-installs it.
		$base = new Nginx( Plugin::policy(), $host ); return class_exists( 'Quard\\Dull' ) ? Dull::adapt( $base, 'nginx' ) : $base;
	}

	/** Pure manual generation. Selecting a target grants no runtime or deployment capability. */
	public static function manual_adapter( $engine ) {
		if ( ! is_string( $engine ) || ! in_array( $engine, array( 'nginx', 'apache', 'litespeed-enterprise', 'openlitespeed' ), true ) ) {
			throw new \InvalidArgumentException( esc_html__( 'Choose a manual export target above. Server detection does not select an unconfirmed LiteSpeed edition.', 'quard' ) );
		}
		if ( 'openlitespeed' === $engine ) {
			throw new \RuntimeException( esc_html__( 'OpenLiteSpeed is NOT READY: this release has no rule generator for it. Do not install Apache or Enterprise rules as an assumed substitute.', 'quard' ) );
		}
		if ( in_array( $engine, array( 'apache', 'litespeed-enterprise' ), true ) ) {
			$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
			return new Htaccess( Plugin::policy(), $host, $engine );
		}
		return self::adapter( $engine );
	}

	public static function file() {
		$root = rtrim( ABSPATH, '/' );
		if ( isset( $_SERVER['DOCUMENT_ROOT'] ) && realpath( $_SERVER['DOCUMENT_ROOT'] ) !== realpath( $root ) ) { throw new \RuntimeException( 'WordPress root differs from the actual document root. Manual deployment required.' ); }
		if ( is_multisite() || ! in_array( (string) wp_parse_url( home_url(), PHP_URL_PATH ), array( '', '/' ), true ) ) { throw new \RuntimeException( 'Managed subdirectory/multisite deployment is not qualified.' ); }
		return new ManagedFile( $root, dirname( $root ) . '/.quard-backups-' . substr( hash( 'sha256', $root ), 0, 12 ) );
	}

	private static function request( $url, $method = 'GET' ) {
		return wp_remote_request( $url, array( 'method' => $method, 'timeout' => 2, 'redirection' => 0, 'limit_response_size' => 2048, 'headers' => array( 'Accept' => 'text/html', 'Cookie' => '' ) ) );
	}

	/** Probe files are created only after explicit preflight on an Apache backend. */
	public static function preflight( $remove = false ) {
		$detected = self::detect();
		if ( 'apache' !== $detected['engine'] ) { throw new \RuntimeException( 'Automatic .htaccess writes require a positively identified Apache backend; use manual export on this server.' ); }
		if ( ! function_exists( 'apache_get_modules' ) ) { throw new \RuntimeException( 'Native Apache module/cache inventory is unavailable. Use manual export; automatic installation is not qualified for this backend.' ); }
		$modules = apache_get_modules();
		if ( ! in_array( 'mod_rewrite', $modules, true ) || ! in_array( 'mod_headers', $modules, true ) ) { throw new \RuntimeException( 'Required native rewrite/header modules are not confirmed.' ); }
		if ( self::cache_modules() ) { throw new \RuntimeException( 'A cache module is loaded. Cache HITs can bypass cold denial and clearance issuance. No cached Apache profile is qualified; automatic installation is refused. Manual export is for operator review, not approval to deploy.' ); }
		$file = self::file();
		$snapshot = $file->snapshot();
		$root = rtrim( ABSPATH, '/' );
		$name = 'quard-probe-' . bin2hex( random_bytes( 12 ) );
		$dir = $root . '/' . $name;
		$token = bin2hex( random_bytes( 16 ) );
		if ( ! mkdir( $dir, 0755 ) ) { throw new \RuntimeException( 'Cannot create a scoped capability probe.' ); }
		try {
			file_put_contents( $dir . '/ok.txt', $token );
			// An existing file survives WordPress's parent !-f rewrite, reaching this directory.
			file_put_contents( $dir . '/guard.txt', $token );
			file_put_contents( $dir . '/.htaccess', "RewriteEngine On\nRewriteRule ^guard[.]txt$ - [G,END]\nHeader always set X-Quard-Probe \"" . $token . "\" \"expr=%{REQUEST_STATUS} == 200\"\n" );
			$ok = self::request( home_url( '/' . $name . '/ok.txt' ) );
			$guard = self::request( home_url( '/' . $name . '/guard.txt' ) );
			if ( is_wp_error( $ok ) || is_wp_error( $guard ) || 200 !== wp_remote_retrieve_response_code( $ok ) || trim( wp_remote_retrieve_body( $ok ) ) !== $token || wp_remote_retrieve_header( $ok, 'x-quard-probe' ) !== $token || 410 !== wp_remote_retrieve_response_code( $guard ) ) { throw new \RuntimeException( 'Actual .htaccess rewrite/header activation was not demonstrated. Nothing was installed.' ); }
		} finally {
			foreach ( array( 'ok.txt', 'guard.txt', '.htaccess' ) as $n ) { if ( is_file( $dir . '/' . $n ) ) { unlink( $dir . '/' . $n ); } }
			rmdir( $dir );
		}
		$state = get_option( self::OPTION, array() );
		$adapter = self::adapter( 'apache' );
		$restoring = 'restore' === $remove;
		$plan = $restoring ? $file->restore_plan( isset( $state['backup'] ) ? $state['backup'] : '' ) : $file->plan( $adapter->block(), isset( $state['block_hash'] ) ? $state['block_hash'] : '', $remove );
		if ( $plan['snapshot']['hash'] !== $snapshot['hash'] || $plan['snapshot']['exists'] !== $snapshot['exists'] ) { throw new \RuntimeException( 'File changed during capability preflight.' ); }
		return array( 'hash' => $snapshot['hash'], 'exists' => $snapshot['exists'], 'policy' => $adapter->fingerprint(), 'remove' => true === $remove, 'restore' => $restoring, 'previous_policy' => isset( $state['previous_policy'] ) ? $state['previous_policy'] : '', 'plan' => $plan, 'time' => time(), 'path' => $file->path(), 'source' => $detected['source'] . '; actual FileInfo rewrite/header challenge passed', 'syntax' => 'Full server syntax validation unavailable to WordPress; real HTTP smoke verification required', 'cache' => 'NOT QUALIFIED: real cache HIT and QuickHandler behavior require operator testing' );
	}

	public static function apply( array $preflight ) {
		if ( 'apache' !== self::detect()['engine'] || time() - $preflight['time'] > 300 || ! hash_equals( self::adapter( 'apache' )->fingerprint(), $preflight['policy'] ) ) { throw new \RuntimeException( 'Preflight expired, engine changed or desired policy changed. Preview again.' ); }
		$file = self::file();
		$state = get_option( self::OPTION, array() );
		$plan = ! empty( $preflight['restore'] ) ? $file->restore_plan( isset( $state['backup'] ) ? $state['backup'] : '' ) : $file->plan( self::adapter( 'apache' )->block(), isset( $state['block_hash'] ) ? $state['block_hash'] : '', $preflight['remove'] );
		if ( $plan['snapshot']['hash'] !== $preflight['hash'] || $plan['snapshot']['exists'] !== $preflight['exists'] || $plan['after'] !== $preflight['plan']['after'] ) { throw new \RuntimeException( 'Concurrent file or plan change. Preview again.' ); }
		try {
			$result = $file->commit( $plan, function () use ( $preflight ) {
				if ( $preflight['remove'] || ! empty( $preflight['restore'] ) ) {
					$r = self::request( home_url( '/' ), 'HEAD' );
					return ! is_wp_error( $r ) && 200 === wp_remote_retrieve_response_code( $r ) && ( ! empty( $preflight['restore'] ) ? $preflight['previous_policy'] : '' ) === (string) wp_remote_retrieve_header( $r, 'x-quard-policy' );
				}
				return Diagnostics::run()['passed'];
			} );
			$new = array( 'engine' => 'apache', 'block_hash' => $plan['block_hash'], 'backup' => $result['backup'] ? $result['backup'] : ( isset( $state['backup'] ) ? $state['backup'] : '' ), 'previous_policy' => isset( $state['policy'] ) ? $state['policy'] : '', 'policy' => $preflight['remove'] ? '' : $preflight['policy'], 'status' => $preflight['remove'] ? 'Not deployed' : 'Verified', 'verified_at' => time() );
			if ( ! empty( $preflight['restore'] ) ) { $new['policy'] = $preflight['previous_policy']; $new['status'] = $new['policy'] ? 'Restored / unverified — run tests' : 'Not deployed'; $new['verified_at'] = 0; }
			self::save( $new ); delete_option( self::WARNING );
			return $new;
		} catch ( \Throwable $e ) {
			$state['status'] = 'Failed / unverified'; $state['error'] = $e->getMessage(); self::save( $state );
			throw $e;
		}
	}


	private static function save( array $value ) { update_option( self::OPTION, $value, false ); }

	public static function cleanup() {
		$state = get_option( self::OPTION, array() );
		if ( empty( $state['block_hash'] ) ) { return; }
		try { self::apply( self::preflight( true ) ); }
		catch ( \Throwable $e ) { update_option( self::WARNING, 'Managed Quard cleanup failed: ' . $e->getMessage() . ' Server protection may remain. Use the private recovery record or remove only the owned block after review.', false ); }
	}
}
