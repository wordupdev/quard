<?php
/** Usage: wp eval-file wp-content/plugins/quard/tools/export.php /private/export/directory */
if ( 'cli' !== PHP_SAPI || ! defined( 'WP_CLI' ) || ! WP_CLI || ! class_exists( 'Quard\\Plugin' ) ) {
	if ( 'cli' !== PHP_SAPI ) {
		http_response_code( 404 );
		header( 'Content-Type: text/plain; charset=utf-8' );
	}
	exit( 'Quard exporter is available through WP-CLI only.' );
}
$directory = isset( $args[0] ) ? $args[0] : '';
if ( ! is_dir( $directory ) || ! is_writable( $directory ) ) {
	WP_CLI::error( 'Create a writable export directory first.' );
}
foreach ( Quard\Plugin::adapter()->files() as $name => $content ) {
	if ( false === file_put_contents( rtrim( $directory, '/' ) . '/' . $name, $content ) ) {
		WP_CLI::error( 'Could not export ' . $name );
	}
}
WP_CLI::success( 'Exported policy ' . Quard\Plugin::adapter()->fingerprint() );
