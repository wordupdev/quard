<?php
/** Small browser usability bridge; native Nginx still owns issuance and cold denial. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Navigation {
	public static function enqueue() {
		if ( is_admin() || is_404() || http_response_code() >= 300 || empty( $_SERVER['QUARD_NAVIGATION_RECOVERY'] ) || '1' !== (string) $_SERVER['QUARD_NAVIGATION_RECOVERY'] ) { return; }
		$p = Plugin::policy();
		if ( ! $p['enabled'] ) { return; }
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$c = Policy::classify( $p, $uri );
		if ( $c['excluded'] || $c['operational'] || ( $c['protected'] && ! Policy::has_clearance( isset( $_SERVER['HTTP_COOKIE'] ) ? (string) $_SERVER['HTTP_COOKIE'] : '' ) ) ) { return; }
		wp_enqueue_script( 'quard-navigation', plugins_url( 'assets/navigation.js', QUARD_FILE ), array(), QUARD_VERSION, false );
		$config = array( 'endpoint' => Nginx::NAVIGATION_PATH, 'query' => Policy::query_pattern( $p['exact'], $p['prefixes'] ), 'excluded' => Policy::path_pattern( array_merge( $p['excluded'], $p['exceptions'] ) ), 'error' => __( 'Navigation clearance could not be renewed. Please retry or reload this page.', 'quard' ) );
		wp_add_inline_script( 'quard-navigation', 'window.quardNavigation=' . wp_json_encode( $config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT ) . ';', 'before' );
	}
}
