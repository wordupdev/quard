<?php
/**
 * Lightweight navigation-cookie issuer for uncached LiteSpeed Enterprise storefronts.
 * Enforcement stays in the web server; this component never denies a request.
 */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class LitespeedClearance {

    public static function boot() {
        $software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : '';
        if ( false === stripos( $software, 'LiteSpeed' ) || false !== stripos( $software, 'OpenLiteSpeed' ) ) {
            return;
        }
        add_action( 'template_redirect', array( __CLASS__, 'issue' ), 1 );
    }

    /** Only ordinary, original front-end HTML navigation can mint clearance. */
    public static function eligible_request( array $policy, array $server ) {
        if ( 'GET' !== ( isset( $server['REQUEST_METHOD'] ) ? $server['REQUEST_METHOD'] : '' ) ) { return false; }
        $uri = isset( $server['REQUEST_URI'] ) ? (string) $server['REQUEST_URI'] : '';
        if ( '' === $uri || '/' !== $uri[0] || preg_match( '~[\x00-\x20\x7f]|%(?![a-f0-9]{2})~i', $uri ) || false !== strpos( $uri, '#' ) ) { return false; }
        $classification = Policy::classify( $policy, $uri );
        if ( $classification['protected'] || $classification['excluded'] || $classification['exception'] || $classification['operational'] ) { return false; }
        // Never mint clearance from search/sort/filter URLs, even when unprotected.
        $parts = explode( '?', $uri, 2 );
        if ( isset( $parts[1] ) ) {
            $pattern = Policy::query_pattern( array_merge( Policy::EXACT, array( 's', 'orderby', 'feed', 'preview' ) ), Policy::PREFIXES );
            if ( preg_match( '~' . $pattern . '~i', $parts[1] ) ) { return false; }
        }
        if ( empty( $server['HTTP_ACCEPT'] ) || ! preg_match( '~(?:^|[,\s])text/html(?:[;,\s]|$)~i', $server['HTTP_ACCEPT'] ) || ! empty( $server['HTTP_X_REQUESTED_WITH'] ) ) { return false; }
        if ( isset( $server['HTTP_SEC_FETCH_DEST'] ) && ! in_array( $server['HTTP_SEC_FETCH_DEST'], array( '', 'document' ), true ) ) { return false; }
        if ( isset( $server['HTTP_SEC_FETCH_SITE'] ) && ! in_array( $server['HTTP_SEC_FETCH_SITE'], array( 'none', 'same-origin' ), true ) ) { return false; }
        // Malformed or duplicated Quard cookies do not silently repair themselves.
        if ( preg_match( '~(?:^|;\s*)quard_nav\s*(?:=|;|$)~', isset( $server['HTTP_COOKIE'] ) ? $server['HTTP_COOKIE'] : '' ) ) { return false; }
        return true;
    }

    public static function issue() {
        $software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : '';
        if ( false === stripos( $software, 'LiteSpeed' ) || false !== stripos( $software, 'OpenLiteSpeed' ) ) { return; }
        $policy = Plugin::policy();
        if ( ! $policy['enabled'] || 403 !== $policy['response'] ) { return; }
        // When the original experimental MU issuer is present, let it remain the sole writer.
        if ( defined( 'WPMU_PLUGIN_DIR' ) && is_file( WPMU_PLUGIN_DIR . '/quard-litespeed-issuer.php' ) ) { return; }
        if ( headers_sent() || 200 !== http_response_code() || ! self::eligible_request( $policy, $_SERVER ) ) { return; }
        $home_host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
        $request_host = strtolower( (string) ( isset( $_SERVER['HTTP_HOST'] ) ? $_SERVER['HTTP_HOST'] : '' ) );
        if ( '' === $home_host || $home_host !== $request_host ) { return; }
        if ( is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) { return; }
        foreach ( array( 'is_404', 'is_search', 'is_feed', 'is_preview', 'is_trackback', 'is_cart', 'is_checkout', 'is_account_page', 'is_wc_endpoint_url' ) as $fn ) {
            if ( function_exists( $fn ) && $fn() ) { return; }
        }
        // No output buffering or shutdown-hook changes. Cookies are short-lived and forgeable.
        setcookie( 'quard_nav', '1', array(
            'expires' => time() + $policy['lifetime'] * 60,
            'path' => '/',
            'secure' => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ) );
    }
}
