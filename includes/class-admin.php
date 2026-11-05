<?php
/** Scoped settings screen and capability/nonce-protected administrative actions. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

final class Admin {
	public static function boot() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_post_quard_export', array( __CLASS__, 'export' ) );
		add_action( 'admin_post_quard_throttle_export', array( __CLASS__, 'throttle_export' ) );
		add_action( 'admin_post_quard_test', array( __CLASS__, 'test' ) );
		add_action( 'admin_post_quard_deploy', array( __CLASS__, 'deploy' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( QUARD_FILE ), array( __CLASS__, 'links' ) );
		add_action( 'admin_notices', array( __CLASS__, 'inactive_warning' ) );
	}

	public static function menu() {
		add_options_page( __( 'Quard', 'quard' ), __( 'Quard', 'quard' ), 'manage_options', 'quard', array( __CLASS__, 'render' ) );
	}

	public static function links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=quard' ) ) . '">' . esc_html__( 'Settings', 'quard' ) . '</a>' );
		return $links;
	}

	public static function assets( $hook ) {
		if ( 'settings_page_quard' === $hook ) {
			wp_enqueue_style( 'quard-admin', plugins_url( 'assets/admin.css', QUARD_FILE ), array(), QUARD_VERSION );
		}
	}

	public static function inactive_warning() {
		$warning = get_option( Deployment::WARNING, '' );
		if ( $warning && current_user_can( 'manage_options' ) ) { echo '<div class="notice notice-error"><p>' . esc_html( $warning ) . '</p></div>'; }
		$screen = get_current_screen();
		if ( current_user_can( 'manage_options' ) && $screen && 'plugins' === $screen->id ) {
			echo '<div class="notice notice-info"><p>' . esc_html__( 'Quard server rules have a separate deployment lifecycle. Before deactivating or deleting Quard, separately retire its Sharp/Dull/crawler rules and any dynamic throttle integration. Deactivation cannot remove server-owned Nginx rules.', 'quard' ) . '</p></div>';
		}
	}

	private static function authorize( $nonce ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'quard' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce );
	}

	public static function export() {
		self::authorize( 'quard_export' );
		$name = isset( $_GET['file'] ) ? sanitize_text_field( wp_unslash( $_GET['file'] ) ) : '';
		try { $files = Deployment::adapter( self::manual_engine() )->files(); } catch ( \Throwable $e ) { wp_die( esc_html( $e->getMessage() ), '', array( 'response' => 409 ) ); }
		if ( ! isset( $files[ $name ] ) ) {
			wp_die( esc_html__( 'Unknown configuration file.', 'quard' ) );
		}
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . ( 0 === strpos( $name, 'quard-' ) ? $name : 'quard-' . $name ) . '"' );
		echo $files[ $name ]; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- validated plain-text configuration download.
		exit;
	}

	public static function test() {
		self::authorize( 'quard_test' );
		Diagnostics::run();
		wp_safe_redirect( admin_url( 'options-general.php?page=quard&tested=1' ) );
		exit;
	}

	public static function throttle_export() {
		self::authorize( 'quard_throttle_export' );
		$name = isset( $_GET['file'] ) ? sanitize_text_field( wp_unslash( $_GET['file'] ) ) : '';
		try { $files = Throttle::adapter()->files(); }
		catch ( \Throwable $e ) { wp_die( esc_html( $e->getMessage() ), '', array( 'response' => 409 ) ); }
		if ( ! isset( $files[ $name ] ) ) { wp_die( esc_html__( 'Unknown configuration file.', 'quard' ), '', array( 'response' => 400 ) ); }
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="quard-' . $name . '"' );
		echo $files[ $name ]; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- validated plain-text download.
		exit;
	}

	private static function select( $key, array $options, array $s ) {
		echo '<select id="quard-' . esc_attr( $key ) . '" name="quard_settings[' . esc_attr( $key ) . ']">';
		foreach ( $options as $value => $label ) {
			echo '<option value="' . esc_attr( $value ) . '" ' . selected( (string) $s[ $key ], (string) $value, false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select>';
	}

	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s = Plugin::settings();
		$p = Plugin::policy();
		$status = Diagnostics::status();
		$throttle_status = Throttle::status();
		$last = get_option( Diagnostics::OPTION, array() );
		$tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'protection';
		$tabs = array( 'protection' => __( 'Protection', 'quard' ), 'rules' => __( 'Rules', 'quard' ), 'dull' => __( 'Dull Knife', 'quard' ), 'traffic' => __( 'Traffic', 'quard' ), 'advanced' => __( 'Advanced', 'quard' ) );
		if ( ! isset( $tabs[ $tab ] ) ) {
			$tab = 'protection';
		}
		?>
		<div class="wrap"><hr class="wp-header-end"></div>
		<div class="wrap quard-app">
			<header class="quard-header">
				<div class="quard-brand"><svg viewBox="0 0 48 48" width="48" height="48" aria-hidden="true"><rect width="48" height="48" rx="14" fill="#195be8"/><path d="M29 9c2 13-1 20-13 24l-2-3L29 9Z" fill="#fff"/><path d="m27 28 9 10m-12-9 6-6" stroke="#b9d0ff" stroke-width="4" stroke-linecap="round"/></svg><div><h1>Quard <span><?php echo esc_html( QUARD_VERSION ); ?></span></h1><p><?php esc_html_e( 'A sharper boundary for expensive requests.', 'quard' ); ?></p></div></div>
				<span class="quard-badge"><?php esc_html_e( 'WordPress Query Guard', 'quard' ); ?></span>
			</header>
			<?php settings_errors( 'quard' ); ?>
			<nav class="quard-nav" aria-label="<?php esc_attr_e( 'Quard settings', 'quard' ); ?>">
				<?php foreach ( $tabs as $key => $label ) : ?>
					<a <?php echo $tab === $key ? 'aria-current="page"' : ''; ?> href="<?php echo esc_url( add_query_arg( array( 'page' => 'quard', 'tab' => $key ), admin_url( 'options-general.php' ) ) ); ?>"><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</nav>
			<div class="quard-status <?php echo $status['verified'] ? 'quard-verified' : ''; ?>"><span class="quard-dot"></span><div><strong><?php echo esc_html( $status['label'] ); ?></strong><p><?php echo esc_html( sprintf( __( 'Desired protection: %1$s. Observed server state: %2$s. Saving settings requires a separate server deployment.', 'quard' ), $s['enabled'] ? __( 'On', 'quard' ) : __( 'Off', 'quard' ), $status['enabled'] ? $status['enabled'] : __( 'unknown', 'quard' ) ) ); ?></p></div></div>
			<p class="quard-note" data-quard-throttle-capability="<?php echo esc_attr( $throttle_status['capability'] ); ?>"><strong><?php
			if ( in_array( $throttle_status['mode'], array( 'observe', 'enforce' ), true ) && 'active' !== $throttle_status['capability'] ) { esc_html_e( 'Throttling server integration needs operator review', 'quard' ); }
			elseif ( 'existing_limits' === $throttle_status['reason_code'] ) { esc_html_e( 'Throttling Off — unsupported with current existing limits', 'quard' ); }
			elseif ( 'unknown' === $throttle_status['capability'] ) { esc_html_e( 'Throttling Off — capability unknown', 'quard' ); }
			elseif ( 'active' === $throttle_status['capability'] ) { echo esc_html( $throttle_status['label'] ); }
			else { esc_html_e( 'Throttling Off', 'quard' ); }
			?></strong> · <?php echo esc_html( $throttle_status['detail'] ); ?></p>
			<?php if ( $status['error'] ) : ?><p class="quard-note"><?php echo esc_html( $status['error'] ); ?></p><?php endif; ?>
			<form method="post" action="options.php" <?php echo in_array( $tab, array( 'protection', 'rules' ), true ) ? '' : 'hidden'; ?>>
				<?php settings_fields( 'quard' ); ?>
				<section class="quard-card" <?php echo 'protection' === $tab ? '' : 'hidden'; ?>>
					<h2><?php esc_html_e( 'Protection', 'quard' ); ?></h2><p class="quard-intro"><?php esc_html_e( 'Sharp Knife: the existing cold-navigation gate. Dull Knife independently denies selected bots on selected query keys. Both enforce before PHP through separately deployed server rules.', 'quard' ); ?></p>
					<div class="quard-field"><label for="quard-enabled"><?php esc_html_e( 'Enable protection', 'quard' ); ?></label><div><input type="hidden" name="quard_settings[enabled]" value="0"><label class="quard-switch"><input id="quard-enabled" type="checkbox" name="quard_settings[enabled]" value="1" <?php checked( $s['enabled'] ); ?>><span></span><b><?php esc_html_e( 'Desired server protection', 'quard' ); ?></b></label><p><?php esc_html_e( 'Defaults to off. Deploy the generated configuration to enable or disable enforcement.', 'quard' ); ?></p></div></div>
					<div class="quard-field"><label for="quard-mode"><?php esc_html_e( 'Protection mode', 'quard' ); ?></label><div><?php self::select( 'mode', array( 'balanced' => __( 'Balanced', 'quard' ), 'strict' => __( 'Strict', 'quard' ), 'custom' => __( 'Custom', 'quard' ) ), $s ); ?><p><?php esc_html_e( 'Balanced allows standalone orderby. Strict protects it. Custom uses only your parameter rules.', 'quard' ); ?></p></div></div>
					<div class="quard-field"><label for="quard-lifetime"><?php esc_html_e( 'Browser clearance lifetime', 'quard' ); ?></label><div><?php self::select( 'lifetime', array( 5 => __( '5 minutes', 'quard' ), 15 => __( '15 minutes', 'quard' ), 30 => __( '30 minutes', 'quard' ), 60 => __( '60 minutes', 'quard' ) ), $s ); ?><p><?php esc_html_e( 'Browser retention for quard_nav=1. This static cookie can be acquired or forged and has no cryptographic expiry.', 'quard' ); ?></p></div></div>
					<div class="quard-field"><label for="quard-response"><?php esc_html_e( 'Cold-request response', 'quard' ); ?></label><div><?php self::select( 'response', array( 403 => '403 — Forbidden', 410 => '410 — Gone', 429 => '429 — Too Many Requests' ), $s ); ?><p><?php esc_html_e( '403 is recommended. 410 can discourage indexing; 429 is a denial response, not a rate limiter.', 'quard' ); ?></p></div></div>
				</section>
				<section class="quard-card" <?php echo 'rules' === $tab ? '' : 'hidden'; ?>>
					<h2><?php esc_html_e( 'Rules', 'quard' ); ?></h2><p class="quard-intro"><?php esc_html_e( 'One rule per line. Balanced and Strict always include their preset rules plus your additions. Custom uses these parameter fields alone.', 'quard' ); ?></p>
					<?php foreach ( array( 'exact' => array( __( 'Exact query parameters', 'quard' ), __( 'Lowercase letters, digits, underscores and hyphens. Example: min_price', 'quard' ) ), 'prefixes' => array( __( 'Parameter prefixes', 'quard' ), __( 'One trailing wildcard only. Example: filter_*', 'quard' ) ), 'excluded' => array( __( 'Additional excluded paths', 'quard' ), __( 'Exact /path or subtree /path/*. Excluded paths cannot issue clearance.', 'quard' ) ), 'exceptions' => array( __( 'Direct-access exceptions', 'quard' ), __( 'Allow protected requests on these paths. Protected requests still cannot issue clearance.', 'quard' ) ) ) as $key => $field ) : ?>
						<div class="quard-field"><label for="quard-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $field[0] ); ?></label><div><textarea id="quard-<?php echo esc_attr( $key ); ?>" name="quard_settings[<?php echo esc_attr( $key ); ?>]" rows="5" spellcheck="false" dir="ltr"><?php echo esc_textarea( implode( "\n", $s[ $key ] ) ); ?></textarea><p><?php echo esc_html( $field[1] ); ?></p></div></div>
					<?php endforeach; ?>
					<details><summary><?php esc_html_e( 'Built-in operational exclusions', 'quard' ); ?></summary><p><code><?php echo esc_html( implode( ', ', $p['excluded'] ) ); ?></code></p><p><?php esc_html_e( 'Operational query keys never bypass protection. Requests with only operational keys continue normally and cannot issue clearance. Path exclusions shown above still apply. Parameter names include case, percent-encoding and PHP dot/space aliases.', 'quard' ); ?></p></details>
				</section>
				<div class="quard-save"><?php submit_button( __( 'Save desired policy', 'quard' ), 'primary', 'submit', false ); ?><span><?php esc_html_e( 'A server deployment is required to apply changes.', 'quard' ); ?></span></div>
			</form>
			<?php if ( 'protection' === $tab ) : ?>
				<section class="quard-card"><div class="quard-card-heading"><div><h2><?php esc_html_e( 'Test Protection', 'quard' ); ?></h2><p><?php esc_html_e( 'Run a small set of real HTTP probes against this site. No orders or products are modified.', 'quard' ); ?></p></div><form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="quard_test"><?php wp_nonce_field( 'quard_test' ); ?><button class="button" type="submit"><?php esc_html_e( 'Run tests', 'quard' ); ?></button></form></div>
				<?php if ( ! empty( $last['rows'] ) ) : ?><p><?php echo esc_html( sprintf( __( 'Last run: %s UTC. These probes do not independently attest FastCGI avoidance or every payment workflow; see the release test report.', 'quard' ), gmdate( 'Y-m-d H:i:s', $last['time'] ) ) ); ?></p><table class="quard-table"><thead><tr><th><?php esc_html_e( 'Probe', 'quard' ); ?></th><th><?php esc_html_e( 'Result', 'quard' ); ?></th><th><?php esc_html_e( 'Observation', 'quard' ); ?></th></tr></thead><tbody><?php foreach ( $last['rows'] as $row ) : ?><tr><td><?php echo esc_html( $row['label'] ); ?></td><td><strong><?php echo esc_html( $row['result'] ); ?></strong></td><td><?php echo esc_html( $row['detail'] ); ?></td></tr><?php endforeach; ?></tbody></table><?php endif; ?>
				</section>
				<p class="quard-note"><?php esc_html_e( 'Real homepage → menu browsing is not attested by synthetic HTTP queries. Run the operator browser acceptance test; browser journey coverage here is NOT TESTED. Native Nginx recovery renews clearance for existing storefront documents without PHP. A direct cold protected URL remains denied. The navigation cookie is not proof of human activity.', 'quard' ); ?></p>
			<?php elseif ( 'dull' === $tab ) : ?>
				<?php DullAdmin::render(); ?>
			<?php elseif ( 'traffic' === $tab ) : ?>
				<?php self::throttle_panel( $throttle_status ); ?>
			<?php elseif ( 'advanced' === $tab ) : ?>
				<?php self::deployment_panel( $status ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	private static function throttle_panel( $status ) {
		$s = Throttle::settings();
		$can_activate = in_array( $status['capability'], array( 'available', 'active' ), true );
		?>
		<section class="quard-card"><h2><?php esc_html_e( 'Dynamic Throttling', 'quard' ); ?></h2>
		<p class="quard-intro"><?php esc_html_e( 'Only admitted expensive dynamic requests are counted. Ordinary site traffic is unaffected by Quard budgets. This optional Nginx layer does not authenticate visitors.', 'quard' ); ?></p>
		<p><strong><?php echo esc_html( $status['label'] ); ?></strong> · <?php echo esc_html( $status['detail'] ); ?></p>
		<p><?php esc_html_e( 'Capability:', 'quard' ); ?> <strong><?php echo esc_html( $status['capability'] ); ?></strong><?php if ( ! empty( $status['audit_time'] ) ) { echo ' · ' . esc_html( gmdate( 'Y-m-d H:i:s', $status['audit_time'] ) ) . ' UTC'; } ?></p>
		<p><?php esc_html_e( 'Desired revision:', 'quard' ); ?> <code class="quard-hash"><?php echo esc_html( $status['desired'] ); ?></code><br><?php esc_html_e( 'Observed revision:', 'quard' ); ?> <code class="quard-hash"><?php echo esc_html( $status['observed'] ? $status['observed'] : __( 'None / unverified', 'quard' ) ); ?></code></p>
		<?php if ( $status['time'] ) : ?><p><?php echo esc_html( sprintf( __( 'Configuration observation: %s UTC. No privileged logs or traffic counters are read by WordPress.', 'quard' ), gmdate( 'Y-m-d H:i:s', $status['time'] ) ) ); ?></p><?php endif; ?>
		<?php settings_errors( 'quard_throttle' ); ?>
		<form method="post" action="options.php">
		<?php settings_fields( 'quard_throttle' ); ?>
		<div class="quard-field"><label for="quard-throttle-mode"><?php esc_html_e( 'Dynamic Throttling', 'quard' ); ?></label><div><select id="quard-throttle-mode" name="quard_throttle_settings[mode]">
		<?php foreach ( array( 'off' => __( 'Off (default)', 'quard' ), 'observe' => __( 'Observe / dry run', 'quard' ), 'enforce' => __( 'Enforce', 'quard' ) ) as $value => $label ) : ?><option value="<?php echo esc_attr( $value ); ?>" <?php selected( $s['mode'], $value ); ?> <?php disabled( 'off' !== $value && ! $can_activate ); ?>><?php echo esc_html( $label ); ?></option><?php endforeach; ?>
		</select><p><?php esc_html_e( 'Off is always available. Observe/Enforce require current operator evidence for an exclusive Nginx profile. The same gate protects form, API, import, CLI and export paths; saving never deploys a limit.', 'quard' ); ?></p></div></div>
		<?php foreach ( array( 'client' => __( 'Per-client budget', 'quard' ), 'site' => __( 'Per-site aggregate budget', 'quard' ) ) as $kind => $label ) : ?>
		<div class="quard-field"><label for="quard-throttle-<?php echo esc_attr( $kind ); ?>-rate"><?php echo esc_html( $label ); ?></label><div>
		<?php if ( 'site' === $kind ) : ?><input type="hidden" name="quard_throttle_settings[site_enabled]" value="0"><label><input type="checkbox" name="quard_throttle_settings[site_enabled]" value="1" <?php checked( $s['site_enabled'] ); ?>> <?php esc_html_e( 'Enable shared aggregate cap (off by default)', 'quard' ); ?></label><p><?php esc_html_e( 'A shared cap can reject legitimate shoppers during busy periods. Qualify capacity before enabling it.', 'quard' ); ?></p><?php else : ?><p><?php esc_html_e( 'Client identity is the socket IP. Shared IPs can group legitimate visitors; forwarded-IP setups require separate operator qualification.', 'quard' ); ?></p><?php endif; ?>
		<label><?php esc_html_e( 'Requests per minute', 'quard' ); ?> <input id="quard-throttle-<?php echo esc_attr( $kind ); ?>-rate" type="number" min="1" max="<?php echo 'client' === $kind ? '6000' : '60000'; ?>" step="1" name="quard_throttle_settings[<?php echo esc_attr( $kind ); ?>_rate]" value="<?php echo esc_attr( $s[ $kind . '_rate' ] ); ?>"></label>
		<label><?php esc_html_e( 'Burst', 'quard' ); ?> <input type="number" min="0" max="<?php echo 'client' === $kind ? '200' : '1000'; ?>" step="1" name="quard_throttle_settings[<?php echo esc_attr( $kind ); ?>_burst]" value="<?php echo esc_attr( $s[ $kind . '_burst' ] ); ?>"></label>
		<p><?php esc_html_e( 'Nginx uses an average rate and burst allowance, not a fixed wall-clock quota. Excess requests are rejected with 429 without queueing.', 'quard' ); ?></p></div></div>
		<?php endforeach; ?>
		<?php submit_button( __( 'Save desired budgets', 'quard' ) ); ?>
		</form></section>
		<section class="quard-card"><h2><?php esc_html_e( 'Throttle export and verification', 'quard' ); ?></h2><p><?php esc_html_e( 'The protection policy and throttle revision are separate. Removing throttle rules must preserve the existing cold-request guard. A matching configuration header does not independently prove rate rejection or PHP avoidance.', 'quard' ); ?></p>
		<?php try { foreach ( Throttle::adapter()->files() as $name => $content ) { ?>
		<details class="quard-rule-preview"><summary><?php echo esc_html( $name ); ?></summary><p><a class="button" href="<?php echo esc_url( wp_nonce_url( add_query_arg( array( 'action' => 'quard_throttle_export', 'file' => $name ), admin_url( 'admin-post.php' ) ), 'quard_throttle_export' ) ); ?>"><?php esc_html_e( 'Download rules', 'quard' ); ?></a></p><pre dir="ltr"><?php echo esc_html( $content ); ?></pre></details>
		<?php } } catch ( \RuntimeException $e ) { ?><p class="quard-note"><?php echo esc_html( $e->getMessage() ); ?></p><?php } ?>
		<p><?php esc_html_e( 'Use the private operator exporter for Observe/Enforce. It audits the effective Nginx configuration before the guarded CLI export. WordPress never edits Nginx or receives administrative shell privileges. Apache/LiteSpeed throttling is unsupported.', 'quard' ); ?></p></section>
		<?php
	}

	private static function manual_engine() {
		$default = 'apache' === Deployment::detect()['engine'] ? 'apache' : 'nginx';
		$engine = isset( $_GET['engine'] ) ? sanitize_key( $_GET['engine'] ) : $default;
		return in_array( $engine, array( 'nginx', 'apache', 'litespeed-enterprise', 'openlitespeed' ), true ) ? $engine : 'nginx';
	}

	public static function deploy() {
		self::authorize( 'quard_deploy' );
		$operation = isset( $_POST['operation'] ) ? sanitize_key( $_POST['operation'] ) : '';
		$key = 'quard_preflight_' . get_current_user_id();
		try {
			if ( in_array( $operation, array( 'preview', 'preview-remove', 'preview-restore' ), true ) ) {
				$mode = 'preview-restore' === $operation ? 'restore' : ( 'preview-remove' === $operation );
				set_transient( $key, Deployment::preflight( $mode ), 300 );
				$message = __( 'Preflight passed. Review the exact file diff before applying.', 'quard' );
			} elseif ( 'apply' === $operation ) {
				$preflight = get_transient( $key );
				if ( ! is_array( $preflight ) ) { throw new \RuntimeException( 'A fresh preflight preview is required.' ); }
				Deployment::apply( $preflight ); delete_transient( $key );
				$message = __( 'Managed operation completed and HTTP checked. Cache and upstream qualification remain separate.', 'quard' );
			} else { throw new \RuntimeException( 'Unknown deployment action.' ); }
		} catch ( \Throwable $e ) {
			delete_transient( $key );
			$message = $e->getMessage();
		}
		set_transient( 'quard_deploy_notice_' . get_current_user_id(), $message, 300 );
		wp_safe_redirect( admin_url( 'options-general.php?page=quard&tab=advanced' ) );
		exit;
	}

	private static function deployment_button( $operation, $label, $disabled = false ) {
		?><form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="quard_deploy"><input type="hidden" name="operation" value="<?php echo esc_attr( $operation ); ?>"><?php wp_nonce_field( 'quard_deploy' ); ?><button class="button" type="submit" <?php disabled( $disabled ); ?>><?php echo esc_html( $label ); ?></button></form><?php
	}

	private static function deployment_panel( array $status ) {
		$detected = Deployment::detect();
		$engine = self::manual_engine();
		$state = get_option( Deployment::OPTION, array() );
		$managed_label = isset( $state['status'] ) ? $state['status'] : __( 'Not deployed', 'quard' );
		if ( ! empty( $state['policy'] ) ) {
			try {
				if ( ! hash_equals( $state['policy'], Plugin::adapter()->fingerprint() ) ) { $managed_label = false !== stripos( $managed_label, 'Failed' ) ? __( 'Failed / update required', 'quard' ) : __( 'Update required', 'quard' ); }
				elseif ( 'Verified' === $managed_label && ! $status['verified'] ) { $managed_label = __( 'Installed / unverified', 'quard' ); }
			} catch ( \Throwable $e ) { $managed_label = __( 'Not tested / unverified', 'quard' ); }
		}
		$preview = get_transient( 'quard_preflight_' . get_current_user_id() );
		$notice = get_transient( 'quard_deploy_notice_' . get_current_user_id() );
		delete_transient( 'quard_deploy_notice_' . get_current_user_id() );
		$labels = array( 'nginx' => 'Nginx', 'apache' => 'Apache 2.4', 'litespeed-enterprise' => 'LiteSpeed Enterprise', 'openlitespeed' => 'OpenLiteSpeed', 'litespeed-unknown' => 'LiteSpeed — edition unconfirmed', 'unknown' => __( 'Unknown', 'quard' ) );
		if ( $notice ) { echo '<p class="quard-note">' . esc_html( $notice ) . '</p>'; }
		?>
		<section class="quard-card"><h2><?php esc_html_e( 'Server integration', 'quard' ); ?></h2>
		<p><strong><?php echo esc_html( $labels[ $detected['engine'] ] ); ?></strong> — <?php echo esc_html( $detected['confidence'] ); ?></p><p><?php echo esc_html( $detected['source'] ); ?></p>
		<p><?php esc_html_e( 'Effective observed state:', 'quard' ); ?> <strong><?php echo esc_html( $status['label'] ); ?></strong></p>
		<p><?php esc_html_e( 'Managed .htaccess state:', 'quard' ); ?> <?php echo esc_html( $managed_label ); ?><?php if ( ! empty( $state['verified_at'] ) ) { echo ' · ' . esc_html( gmdate( 'Y-m-d H:i:s', $state['verified_at'] ) ) . ' UTC'; } ?></p>
		<p><?php esc_html_e( 'Cache HIT behavior and real payment workflows are not qualified by ordinary HTTP probes. Confirm them separately on the target server.', 'quard' ); ?></p>
		<table class="quard-table"><thead><tr><th><?php esc_html_e( 'Adapter', 'quard' ); ?></th><th><?php esc_html_e( 'Readiness', 'quard' ); ?></th></tr></thead><tbody>
		<tr><td>Nginx</td><td><?php esc_html_e( 'Existing manual HTTP/server/header export. WordPress never edits Nginx or Virtualmin files.', 'quard' ); ?></td></tr>
		<tr><td>Apache 2.4</td><td><?php esc_html_e( 'Uncached profile only. Cached deployment NOT READY: HITs can bypass denial and issuance; rewrite cache-key isolation also requires qualification. Managed apply requires native module inventory, actual override/header preflight and HTTP verification.', 'quard' ); ?></td></tr>
		<tr><td>LiteSpeed Enterprise</td><td><?php esc_html_e( 'EXPERIMENTAL. PHP clearance candidate requires an exact qualified uncached Enterprise 6.3.7 profile. Full policy, browser and pre-PHP evidence required; not deployed by export.', 'quard' ); ?></td></tr>
		<tr><td>OpenLiteSpeed</td><td><?php esc_html_e( 'NOT READY. Separate rewrite loading/restart and header qualification required. No deployable adapter.', 'quard' ); ?></td></tr>
		</tbody></table></section>
		<section class="quard-card"><h2><?php esc_html_e( 'Preview and download rules', 'quard' ); ?></h2>
		<form method="get" action="<?php echo esc_url( admin_url( 'options-general.php' ) ); ?>"><input type="hidden" name="page" value="quard"><input type="hidden" name="tab" value="advanced"><label for="quard-export-engine"><?php esc_html_e( 'Export adapter', 'quard' ); ?></label> <select id="quard-export-engine" name="engine"><?php foreach ( array( 'nginx', 'apache', 'litespeed-enterprise', 'openlitespeed' ) as $id ) : ?><option value="<?php echo esc_attr( $id ); ?>" <?php selected( $engine, $id ); ?>><?php echo esc_html( $labels[ $id ] ); ?></option><?php endforeach; ?></select> <button class="button" type="submit"><?php esc_html_e( 'Preview rules', 'quard' ); ?></button></form>
		<?php try { $adapter = Deployment::adapter( $engine ); ?>
		<p><?php esc_html_e( 'Desired export revision:', 'quard' ); ?> <code class="quard-hash"><?php echo esc_html( $adapter->fingerprint() ); ?></code></p>
		<?php foreach ( $adapter->files() as $name => $content ) : ?><details class="quard-rule-preview"><summary><?php echo esc_html( $name ); ?></summary><p><a class="button" href="<?php echo esc_url( wp_nonce_url( add_query_arg( array( 'action' => 'quard_export', 'file' => $name, 'engine' => $engine ), admin_url( 'admin-post.php' ) ), 'quard_export' ) ); ?>"><?php esc_html_e( 'Download rules', 'quard' ); ?></a></p><pre dir="ltr"><?php echo esc_html( $content ); ?></pre></details><?php endforeach; ?>
		<?php } catch ( \Throwable $e ) { ?><p><?php echo esc_html( $e->getMessage() ); ?></p><?php } ?>
		<p><?php esc_html_e( 'Manual export is always available for supported generators. Choose only the adapter matching the real server. A downloaded or installed file does not prove active protection.', 'quard' ); ?></p></section>
		<section class="quard-card"><h2><?php esc_html_e( 'Managed document-root .htaccess', 'quard' ); ?></h2><p><?php esc_html_e( 'Preview first. Apply uses the server-held snapshot, private backup, concurrency checks and atomic replacement. Failed HTTP verification restores the previous bytes. No generic server configuration or arbitrary file path can be submitted.', 'quard' ); ?></p>
		<div class="quard-downloads"><?php self::deployment_button( 'preview', __( 'Preflight and preview', 'quard' ), 'apache' !== $detected['engine'] ); self::deployment_button( 'preview-remove', __( 'Preview remove Quard block', 'quard' ), 'apache' !== $detected['engine'] || empty( $state['block_hash'] ) ); self::deployment_button( 'preview-restore', __( 'Preview previous configuration', 'quard' ), 'apache' !== $detected['engine'] || empty( $state['backup'] ) ); ?></div>
		<?php if ( is_array( $preview ) ) : ?>
		<p><strong><?php echo esc_html( $preview['plan']['kind'] ); ?></strong> · <code><?php echo esc_html( $preview['path'] ); ?></code></p><p><?php echo esc_html( $preview['source'] ); ?></p><p><?php echo esc_html( $preview['syntax'] ); ?></p><p><?php echo esc_html( $preview['cache'] ); ?></p>
		<?php if ( ! function_exists( 'wp_text_diff' ) ) { require_once ABSPATH . WPINC . '/wp-diff.php'; } echo wp_text_diff( $preview['plan']['snapshot']['bytes'], $preview['plan']['after'], array( 'show_split_view' => false ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- WordPress escapes diff output.
		self::deployment_button( 'apply', __( 'Apply reviewed .htaccess change', 'quard' ) ); ?>
		<?php endif; ?>
		<p><?php esc_html_e( 'Nginx and unconfirmed/cached backends use manual export. Managed cleanup is attempted on deactivation; unsafe cleanup stops and leaves a durable warning. Nginx rules always require manual retirement.', 'quard' ); ?></p></section>
		<?php
	}

}
