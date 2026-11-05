=== Quard ===
Contributors: mohsengham
Tags: security, performance, nginx, query, woocommerce
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.1-rc1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Reduce cold dynamic URL spraying before PHP using a navigation cookie and generated web-server rules.

== Description ==

Quard manages a portable query-protection policy in WordPress and exports Nginx configuration for privileged installation. New installations default to off. It never claims that a forgeable navigation cookie authenticates a human.

Protection and Rules are functional. Traffic does not collect analytics. Advanced exports configuration and shows observed revisions. See README.md for generic installation and retirement guidance. Tests and site-specific operator records are provided separately in the private source/review release.

== Installation ==

1. Install and activate Quard.
2. Open Settings > Quard and review the desired policy.
3. Have an administrator install all three generated files in the correct Nginx contexts.
4. Validate Nginx, gracefully reload, then run Test Protection.

== Frequently Asked Questions ==

= Does deactivation remove Nginx protection? =

No. Deploy a disabled policy or remove the server integration first. Follow the generic retirement guidance in README.md and your private operator rollback record.

= Is the cookie cryptographic authentication? =

No. Clients can acquire or forge it. This release reduces cold direct request spraying.

= Are Apache and LiteSpeed supported? =

Apache has a disposable WordPress-tested uncached profile. Cached Apache deployment remains NOT READY: cache HITs can bypass denial and issuance. LiteSpeed Enterprise has an experimental uncached PHP-clearance candidate; manual generation does not verify the edition or qualify cache HIT behavior. OpenLiteSpeed is deferred. See README.md for exact limits.

== Changelog ==

= Private Prompt 22 correction (1.1.1-rc1) =
* Export Sharp Knife-only Apache/LiteSpeed candidates independently of saved Nginx add-ons, with explicit scope warnings.
* Preserve Nginx bytes, fingerprints and conservative managed deployment gates.

= 0.3.0-dev =
* Gate active dynamic budgets on fresh, read-only operator evidence for an exclusive Nginx limit profile.
* Refuse mixed/unknown profiles through settings, supported imports, WP-CLI and generated configuration; Off remains supported.
* Show capability and separate deployed state without attributing shared limiter outcomes or claiming automatic detection.
* Preserve cold protection and navigation recovery; no live limiter configuration changes.


= 0.2.3.1-dev =
* Add native Nginx navigation renewal for eligible existing WordPress documents after cookie expiry, cache revalidation or history restoration.
* Keep direct cold protected URLs denied; add literal-homepage diagnostics and separate actual-menu browser acceptance coverage.
* Preserve protection rules and optional throttling settings; re-export and deploy the complete updated Nginx revision.

= 0.2.3-dev =
* Add optional Nginx dynamic-query budgets with Off, Observe and Enforce modes.
* Add separate per-client and optional shared-site budgets, private operator preflight and configuration status.
* Keep all budgets off by default and preserve the existing cold-query policy and backend safety gates.

= 0.2.2-dev =
* Qualify scoped Nginx WordPress cache profiles with genuine HIT and early-denial evidence.
* Validate Quard cookie attributes independently of unrelated cookies and reject conflicting clearance headers.
* Preserve the existing Nginx policy and unqualified-backend deployment refusals.

= 0.2.1-dev =
* Keep cached Apache deployment disabled after real WordPress cache safety investigation.
* Prevent cache-module diagnostics from granting a verified badge.
* Strengthen the native rewrite/header preflight.

= 0.2.0-dev =
* Add Apache document-root rules and safe managed-block preview/apply/remove/recovery.
* Add a separately labelled LiteSpeed Enterprise candidate; defer OpenLiteSpeed.
* Preserve the existing Nginx adapter and security policy.
* Refuse automatic writes on cached or unconfirmed backends.

== 0.3.0-dev ==
Optional Nginx Dull Knife bot/query denial and separate official IP + UA crawler exemption from Sharp. Both default Off; operator deployment required. Bot-only denial can affect indexing; 410 requires explicit acknowledgement. See DULL-KNIFE.md. No UA-only exemption.

== Changelog ==

= 1.1.1-rc1 =
* Separate read-only manual adapter generation from runtime detection and deployment qualification.
* Preserve a browser-local manual target and URL selection across Quard tabs; unknown editions never silently select Nginx.
* Keep server installation conservative and label unverified candidate rules explicitly.
