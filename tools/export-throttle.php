<?php
/** Operator boundary: wp eval-file this-file /private/preflight.json /private/empty-export-directory */
if ( 'cli' !== PHP_SAPI || ! defined( 'WP_CLI' ) || ! WP_CLI || ! class_exists( 'Quard\\Throttle' ) ) {
	if ( 'cli' !== PHP_SAPI ) { http_response_code( 404 ); header( 'Content-Type: text/plain; charset=utf-8' ); }
	exit( 'Throttle export is available through the operator WP-CLI preflight only.' );
}
$proof = isset( $args[0] ) ? $args[0] : '';
$directory = isset( $args[1] ) ? $args[1] : '';
if ( ! is_file( $proof ) || ! is_dir( $directory ) || ! is_writable( $directory ) ) { WP_CLI::error( 'Supply the private operator preflight and an empty writable export directory.' ); }
$facts = json_decode( file_get_contents( $proof ), true );
if ( ! is_array( $facts ) || empty( $facts['created'] ) || time() - $facts['created'] > 120 || $facts['created'] > time() || empty( $facts['site'] ) || $facts['site'] !== strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) ) { WP_CLI::error( 'Preflight is expired, invalid or belongs to another site.' ); }
try { $files = Quard\Throttle::adapter()->files( $facts ); }
catch ( Throwable $e ) { WP_CLI::error( $e->getMessage() ); }
foreach ( $files as $name => $content ) {
	$target = rtrim( $directory, '/' ) . '/' . $name;
	$handle = fopen( $target, 'x' );
	if ( false === $handle ) { WP_CLI::error( 'Export target exists or cannot be created.' ); }
	chmod( $target, 0600 );
	if ( strlen( $content ) !== fwrite( $handle, $content ) ) { fclose( $handle ); WP_CLI::error( 'Incomplete export; discard this export directory.' ); }
	fclose( $handle );
}
WP_CLI::success( 'Exported separate throttle revision ' . Quard\Throttle::adapter()->fingerprint() . '. Validate, deploy and independently test; this did not edit Nginx.' );
