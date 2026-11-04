<?php
/** Focused settings card. No network refresh or deployment from WordPress. */
namespace Quard;
defined( 'ABSPATH' ) || exit;
final class DullAdmin {
	public static function render() {
		try { $s = Dull::settings(); } catch ( \RuntimeException $e ) { echo '<div class="notice notice-error"><p>' . esc_html( $e->getMessage() ) . '</p></div>'; $s = Dull::defaults(); }
		$data = Crawler::load(); $reply = Diagnostics::request_url( home_url( '/' ), 'HEAD', '', 1.5 ); $observed = is_wp_error( $reply ) ? '' : (string) wp_remote_retrieve_header( $reply, 'x-quard-policy' );
		try { $desired = Deployment::adapter( 'nginx' )->fingerprint(); } catch ( \RuntimeException $e ) { $desired = ''; }
		$match = $desired && $observed && hash_equals( $desired, $observed );
		$label = ! $observed ? __( 'Server integration unverified', 'quard' ) : ( $match ? __( 'Matching configuration observed', 'quard' ) : __( 'Configuration update required', 'quard' ) );
		?>
		<section class="quard-card"><h2><?php esc_html_e( 'Dull Knife', 'quard' ); ?></h2>
		<p class="quard-intro"><?php esc_html_e( 'Deny selected bot User-Agents on selected dynamic query keys before PHP, even with a navigation cookie. Sharp Knife remains the separate cold-navigation gate. Dull defaults Off.', 'quard' ); ?></p>
		<p><strong><?php echo esc_html( $label ); ?></strong></p><p><?php esc_html_e( 'Desired combined policy:', 'quard' ); ?> <code class="quard-hash"><?php echo esc_html( $desired ? $desired : __( 'Invalid / unavailable', 'quard' ) ); ?></code><br><?php esc_html_e( 'Observed policy:', 'quard' ); ?> <code class="quard-hash"><?php echo esc_html( $observed ? $observed : __( 'None', 'quard' ) ); ?></code></p>
		<p><?php esc_html_e( 'Saving only prepares policy. An operator must export all three core files, review, validate, deploy and test. Matching headers do not attest crawler visits or indexing outcomes. Test Protection probes Sharp; Dull denial and crawler identity require separate operator UA/IP/upstream tests. Disabling a setting does not remove old server rules.', 'quard' ); ?></p>
		<div class="notice notice-warning inline"><p><strong><?php esc_html_e( 'Indexing risk: this is an opt-in denial policy, not Google-recommended SEO.', 'quard' ); ?></strong> <?php esc_html_e( 'Any bot-only denial can affect indexing. Google strongly advises against returning 410 to Googlebot and 200 to humans for the same URL. 410 signals permanent removal; 404 also signals missing content. Use purpose-built SEO landing paths as exclusions. Robots.txt is the usual published faceted-crawl control; Quard does not edit it.', 'quard' ); ?></p></div>
		<?php settings_errors( 'quard_dull' ); ?>
		<form method="post" action="options.php">
		<?php settings_fields( 'quard_dull' ); ?>
		<div class="quard-field"><label for="quard-dull-enabled"><?php esc_html_e( 'Dull Knife On / Off', 'quard' ); ?></label><div><input type="hidden" name="quard_dull_settings[enabled]" value="0"><input id="quard-dull-enabled" type="checkbox" name="quard_dull_settings[enabled]" value="1" <?php checked( $s['enabled'] ); ?>> <?php esc_html_e( 'Prepare bot + dynamic-key denial (off by default)', 'quard' ); ?></div></div>
		<?php foreach ( array( 'bots' => array( __( 'Bots', 'quard' ), __( 'One plain UA token per line, case-insensitive substring matching; maximum 50. Suggestions: Googlebot, bingbot, OAI-SearchBot, GPTBot, ClaudeBot, facebookexternalhit. A token is never identity verification. ChatGPT-User is user-triggered fetching, not an automatic training crawler.', 'quard' ) ), 'strings' => array( __( 'Dynamic strings', 'quard' ), __( 'One exact parameter key or trailing prefix* per line, maximum 100. Examples: min_price, max_price, filter_*, query_type_*, orderby. Matches names, not text inside query values. No raw regex.', 'quard' ) ), 'excluded' => array( __( 'Important SEO / excluded paths', 'quard' ), __( 'Exact /landing/ or subtree /landing/* only. Operational paths and existing Sharp exceptions also stay excluded from Dull. A path exception covers every query there; use a dedicated indexable landing path rather than exempting the entire shop.', 'quard' ) ) ) as $key => $field ) : ?>
		<div class="quard-field"><label for="quard-dull-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $field[0] ); ?></label><div><textarea id="quard-dull-<?php echo esc_attr( $key ); ?>" name="quard_dull_settings[<?php echo esc_attr( $key ); ?>]" rows="5" dir="ltr" spellcheck="false"><?php echo esc_textarea( implode( "\n", $s[ $key ] ) ); ?></textarea><p><?php echo esc_html( $field[1] ); ?></p></div></div>
		<?php endforeach; ?>
		<div class="quard-field"><label for="quard-dull-response"><?php esc_html_e( 'Response', 'quard' ); ?></label><div><select id="quard-dull-response" name="quard_dull_settings[response]">
		<?php foreach ( array( 403 => __( '403 — Forbidden (default)', 'quard' ), 404 => __( '404 — Missing; indexing risk', 'quard' ), 410 => __( '410 — Permanent removal; status-cloaking risk', 'quard' ) ) as $code => $text ) : ?><option value="<?php echo esc_attr( $code ); ?>" <?php selected( $s['response'], $code ); ?>><?php echo esc_html( $text ); ?></option><?php endforeach; ?></select>
		<input type="hidden" name="quard_dull_settings[permanent_ack]" value="0"><p><label><input type="checkbox" name="quard_dull_settings[permanent_ack]" value="1" <?php checked( $s['permanent_ack'] ); ?>> <?php esc_html_e( 'I explicitly accept 410 permanent-removal and bot-only status-cloaking/indexing risk. Required to save 410.', 'quard' ); ?></label></p></div></div>
		<h3><?php esc_html_e( 'Verified crawler exemption from Sharp only', 'quard' ); ?></h3>
		<p><?php esc_html_e( 'Independent and off by default. Only a selected known UA family PLUS its own official IP ranges AND a fresh deployed native time guard can bypass Sharp. Dull and existing server security still apply. No UA-only bypass, request-time DNS or PHP verification.', 'quard' ); ?></p>
		<input type="hidden" name="quard_dull_settings[verified_enabled]" value="0"><label><input type="checkbox" name="quard_dull_settings[verified_enabled]" value="1" <?php checked( $s['verified_enabled'] ); ?>> <?php esc_html_e( 'Prepare verified crawler Sharp exemptions', 'quard' ); ?></label>
		<input type="hidden" name="quard_dull_settings[families][]" value="">
		<?php foreach ( Crawler::sources() as $family => $url ) : ?><p><label><input type="checkbox" name="quard_dull_settings[families][]" value="<?php echo esc_attr( $family ); ?>" <?php checked( in_array( $family, $s['families'], true ) ); ?>> <code><?php echo esc_html( $family ); ?></code></label> — <?php echo esc_html( ! empty( $data['fresh'] ) && isset( $data['families'][ $family ] ) ? sprintf( __( '%d official ranges available for export; not proof of a real crawler visit', 'quard' ), count( $data['families'][ $family ]['cidrs'] ) ) : __( 'Unavailable for export: no fresh snapshot. Loaded exemption state needs operator review.', 'quard' ) ); ?></p><?php endforeach; ?>
		<p><strong><?php echo esc_html( $data['reason'] ); ?></strong></p>
		<?php if ( ! empty( $data['valid'] ) ) : ?><p><?php echo esc_html( sprintf( __( 'Snapshot fetched: %1$s UTC. Exemption expires natively: %2$s UTC, even without reload. Refreshing JSON alone does not extend deployed rules.', 'quard' ), gmdate( 'Y-m-d H:i:s', $data['from'] ), gmdate( 'Y-m-d H:i:s', $data['until'] ) ) ); ?></p><?php endif; ?>
		<p><?php esc_html_e( 'Googlebot uses only common-crawler ranges. OpenAI search, training, user-triggered fetching and ads have separate mappings. ClaudeBot/facebookexternalhit can be Dull tokens but receive no verified exemption here. Only direct original-socket identity is qualified; proxied crawler verification requires separate review. Expired/invalid data grants no exemption.', 'quard' ); ?></p>
		<p><?php esc_html_e( 'Nginx only. Apache Dull/exemptions are not implemented; LiteSpeed Enterprise is not tested live; OpenLiteSpeed deferred. Optional dynamic budgets remain Off on mixed-limit hosts and are not qualified together with these new layers.', 'quard' ); ?></p>
		<?php submit_button( __( 'Save desired Dull / crawler policy', 'quard' ) ); ?>
		</form></section>
		<?php
	}
}
