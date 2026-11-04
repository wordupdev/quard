<?php
/** Preserve server recovery state. Failed managed cleanup aborts deletion. */
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;
require_once __DIR__ . '/quard.php';
Quard\Plugin::deactivate();
// Retain non-autoloaded policy/deployment/backup references for explicit operator retirement.
