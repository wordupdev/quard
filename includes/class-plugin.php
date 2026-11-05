<?php
/** WordPress lifecycle and settings. No PHP request blocking; qualified LiteSpeed profiles may issue clearance. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Plugin {
	const OPTION = 'quard_settings';

	public static function boot() {
		LitespeedClearance::boot();
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		if ( false === stripos( isset( $_SERVER['SERVER_SOFTWARE'] ) ? $_SERVER['SERVER_SOFTWARE'] : '', 'LiteSpeed' ) ) {
			add_action( 'wp_enqueue_scripts', array( 'Quard\\Navigation', 'enqueue' ) );
		}
		// Cover add/update/import/WP-CLI even when admin_init never runs.
		add_filter( 'sanitize_option_' . Throttle::OPTION, array( 'Quard\\Throttle', 'guard_option' ), PHP_INT_MAX );
		add_filter( 'pre_update_option_' . Throttle::OPTION, array( 'Quard\\Throttle', 'guard_option' ), PHP_INT_MAX );
		add_filter( 'sanitize_option_' . Throttle::OPTION, array( 'Quard\\Dull', 'budget_guard' ), PHP_INT_MAX );
		add_filter( 'sanitize_option_' . Dull::OPTION, array( 'Quard\\Dull', 'guard' ), PHP_INT_MAX );
		Admin::boot();
	}

	public static function activate() {
		add_option( self::OPTION, Policy::defaults(), '', false );
		add_option( Throttle::OPTION, Throttle::defaults(), '', false );
		add_option( Dull::OPTION, Dull::defaults(), '', false );
	}

	public static function settings() {
		try {
			return Policy::normalize( get_option( self::OPTION, Policy::defaults() ) );
		} catch ( \InvalidArgumentException $e ) {
			return Policy::defaults();
		}
	}

	public static function policy() {
		$paths = array();
		// Honor localized WooCommerce pages without making WooCommerce a dependency.
		foreach ( array( 'woocommerce_cart_page_id', 'woocommerce_checkout_page_id', 'woocommerce_myaccount_page_id' ) as $option ) {
			$id = (int) get_option( $option, 0 );
			if ( $id > 0 ) {
				$uri = get_page_uri( $id );
				if ( is_string( $uri ) && preg_match( '/\A[a-zA-Z0-9_\/.~-]+\z/D', $uri ) && false === strpos( $uri, '..' ) ) {
					$paths[] = '/' . trim( $uri, '/' ) . '/*';
				}
			}
		}
		return Policy::effective( self::settings(), $paths );
	}

	public static function adapter() {
		return Deployment::adapter();
	}

	public static function deactivate() {
		Deployment::cleanup();
		$warning = get_option( Deployment::WARNING, '' );
		if ( $warning ) {
			wp_die( esc_html( $warning ), esc_html__( 'Quard cleanup needs review', 'quard' ), array( 'response' => 409, 'back_link' => true ) );
		}
	}

	public static function register() {
		register_setting( 'quard', self::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( __CLASS__, 'sanitize' ), 'default' => Policy::defaults(), 'show_in_rest' => false ) );
		add_option( Throttle::OPTION, Throttle::defaults(), '', false );
		add_option( Dull::OPTION, Dull::defaults(), '', false );
		register_setting( 'quard_throttle', Throttle::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( 'Quard\\Throttle', 'sanitize' ), 'default' => Throttle::defaults(), 'show_in_rest' => false ) );
		register_setting( 'quard_dull', Dull::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( 'Quard\\Dull', 'sanitize' ), 'default' => Dull::defaults(), 'show_in_rest' => false ) );
	}

	public static function sanitize( $input ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return self::settings();
		}
		try {
			$p = Policy::normalize( $input );
			// Never autoload policy on ordinary frontend requests.
			if ( function_exists( 'wp_set_option_autoload' ) ) {
				wp_set_option_autoload( self::OPTION, false );
			}
			add_settings_error( 'quard', 'quard_saved', __( 'Desired policy saved. Export, deploy and test the configuration to apply it on the server.', 'quard' ), 'success' );
			return $p;
		} catch ( \InvalidArgumentException $e ) {
			add_settings_error( 'quard', 'quard_invalid', $e->getMessage(), 'error' );
			return self::settings();
		}
	}
}
