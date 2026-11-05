<?php
/**
 * Plugin Name: Quard
 * Description: Reduce cold dynamic URL spraying with a navigation cookie and generated web-server rules.
 * Version: 1.0.1-rc1
 * Requires at least: 6.4
 * Requires PHP: 7.4
 * Author: mohsengham
 * Text Domain: quard
 * License: GPL-2.0-or-later
 */

defined( 'ABSPATH' ) || exit;

define( 'QUARD_VERSION', '1.0.1-rc1' );
define( 'QUARD_FILE', __FILE__ );

require_once __DIR__ . '/includes/class-policy.php';
require_once __DIR__ . '/includes/class-nginx.php';
require_once __DIR__ . '/includes/class-crawler.php';
require_once __DIR__ . '/includes/class-dull.php';
require_once __DIR__ . '/includes/class-knives-nginx.php';
require_once __DIR__ . '/includes/class-navigation.php';
require_once __DIR__ . '/includes/class-throttle.php';
require_once __DIR__ . '/includes/class-capability.php';
require_once __DIR__ . '/includes/class-diagnostics.php';
require_once __DIR__ . '/includes/class-htaccess.php';
require_once __DIR__ . '/includes/class-managed-file.php';
require_once __DIR__ . '/includes/class-deployment.php';
require_once __DIR__ . '/includes/class-litespeed-clearance.php';
require_once __DIR__ . '/includes/class-plugin.php';
require_once __DIR__ . '/includes/class-admin.php';
require_once __DIR__ . '/includes/class-dull-admin.php';

register_activation_hook( __FILE__, array( 'Quard\\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Quard\\Plugin', 'deactivate' ) );
Quard\Plugin::boot();
