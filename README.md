# Quard — WordPress Query Guard

**1.1.1-rc1 — engineering candidate** · PHP 7.4+ · WordPress 6.4+ · GPL-2.0-or-later

Quard reduces cold requests to expensive dynamic URLs before PHP. WordPress manages the policy; generated Nginx rules enforce it. New installations default to **off**.

## Manual rule preview on shared hosting

Settings → Quard has an explicit **Manual export target** selector. Choose Nginx, Apache 2.4, or the experimental LiteSpeed Enterprise candidate. An unknown LiteSpeed edition asks for a choice rather than substituting Nginx. OpenLiteSpeed has no generator and remains NOT READY.

Preview/download uses the same canonical policy and fingerprint as that target's generator. Nginx exports three separate context files; Apache/LiteSpeed export their own managed block. Apache/LiteSpeed manual exports contain Sharp Knife only, even when saved Nginx-only Dull/crawler features are enabled. A prominent scope warning accompanies the preview and download, and response headers repeat the selected engine, exported policy fingerprint and omitted-feature warning. These exports do not disable or save any settings. Managed deployment still refuses active unsupported add-ons. Unsupported response codes produce an explanation. Downloaded bytes match the preview.

The choice follows Quard tab links and the page URL. This browser also remembers it per site/admin when local storage is available. JavaScript-disabled or storage-blocked browsers can still use the ordinary GET selector and download links; the URL carries their selection. No WordPress policy option or server file is changed by preview.

**Manual candidate — runtime NOT VERIFIED** is distinct from effective protection. A selected Enterprise target does not prove the detected edition or qualify its cache, PHP issuer, or automatic installation. Incompatible rules can break shoppers. The existing managed-install gates, backups, root/symlink/hash checks and rollback remain mandatory; unconfirmed/cached backends stay refused. This candidate is not a public release or WordPress.org approval.

## Dull Knife and verified crawler exemptions

Two independent new switches default Off. Dull denies selected bot UA tokens on selected dynamic query keys, even with clearance. The optional Sharp exemption requires a selected crawler family plus its own official IP ranges and a fresh native expiry guard; a UA alone never bypasses Sharp. These features are Nginx-only and need operator deployment. See [DULL-KNIFE.md](DULL-KNIFE.md) for manual setup, data refresh, platform limits and the prominent bot-only denial/indexing warning. Installing with both switches Off leaves the existing Sharp adapter and fingerprint unchanged.

## Navigation recovery hotfix

Menu links must use the storefront's canonical host or relative URLs. A host-only clearance cookie cannot follow a menu link to a different domain. Correct stale menu URLs explicitly; Quard does not rewrite external links or broaden cookie domains.

The Nginx export now includes an exact native `/__quard/navigation` location. A same-origin POST with an Origin header and the fixed navigation marker can restore a missing cookie without PHP. Other methods, origins, markers and query strings are refused. This is a usability endpoint for an already displayed storefront document, not authentication. A direct cold protected URL still receives the configured denial and no script or renewal redirect.

Eligible WordPress documents load a small local script only when Nginx supplies the trusted `QUARD_NAVIGATION_RECOVERY` FastCGI parameter. It renews on page restoration/focus and before a trusted same-origin protected link click, then replays the site's normal link handlers. Existing valid cookies are not refreshed. This covers expiry in open tabs, cached documents, 304 revalidation and back/forward restoration. Modern JavaScript is needed for expired-document recovery; normal fresh navigation and immediate filters still work without JavaScript. Documents cached before installing this script need one full reload. Static HTML documents without the bridge retain normal GET issuance but cannot recover an expired cookie in place.

Deploy all three updated Nginx files together. If a PHP location defines its own `fastcgi_param` directives, repeat `fastcgi_param QUARD_NAVIGATION_RECOVERY 1;` in that location; Nginx does not merge the parent parameter array. Preserve the existing handler. Confirm the script is present after any script optimizer or page-cache update. The native endpoint is exact, uncacheable and separate from the unchanged cold-filter gate. It does not enable throttling, grant human identity or make a forgeable cookie secure against a determined bot.

## Optional Dynamic Throttling (Nginx)

Throttling has a separate capability gate. Unknown, unsupported, available and active are distinct states; the cold-protection card remains independent. Existing mixed Nginx limits make Observe/Enforce unavailable because they can alter unrelated enforcement, response codes and shared-bucket accounting. Off remains supported. This plugin does not rearrange other limits or attempt a workaround.

Before active settings or exports are accepted, an administrative operator must use the private source-bundle audit tool to install read-only evidence outside the document root. WordPress never runs Nginx commands or writes the evidence. The audit is deliberately conservative across the entire Nginx master: unrelated limits, unqualified proxy identity, error handlers or ambiguous configuration prevent qualification. False refusals are preferable to weakening another site's protection.

Evidence is bound to this site's canonical URL/root, cold policy, capability code, configuration/include membership, file permissions, Nginx binary and explicitly confirmed worker generation. The operator must identify the actual PHP reader and attest that the audited configuration is loaded. Unreadable dependencies, code/policy edits, reloads, restarts and detected drift require a fresh audit. WordPress cannot independently discover effective Nginx configuration; this record is operator evidence, not automatic server certification. A matching active configuration header is configuration observation only, not independently verified rejection or upstream avoidance.

Settings API, ordinary option writes/imports, WP-CLI and configuration generation all enforce the gate. Direct database/code edits are outside that supported boundary; legacy unavailable active desires are treated as ineffective and cannot generate an active configuration. Saving Off or encountering stale evidence does not remove already deployed server rules: an operator must retire those separately. Manual Off export is always available. There is no PHP request limiter or privileged deployment endpoint.


Traffic contains separate Off (default), Observe and Enforce settings. Budgets apply only to cleared requests already protected by the canonical query policy, across methods and query ordering. Excluded paths and direct-access exceptions have empty keys. Bogus operational query keys cannot exempt expensive archive requests. Normal pages, ordinary assets, tracking, search and Balanced standalone orderby remain outside these budgets.

The per-client budget uses the socket IP, not arbitrary forwarded headers or cookie identities. Its default is 60 requests/minute with burst 10; it is inactive until explicitly deployed. An optional shared per-site budget defaults off, with an editable 600/minute and burst 50. Shared/NAT IPs and site-wide peaks can affect legitimate shoppers; choose capacity cautiously. Nginx applies an average leaky-bucket rate, not a fixed wall-clock quota. Excess Enforce requests return 429 without queueing; Observe records native excess without Quard rejection. Both happen before upstream/PHP. Cold requests are still denied earlier by the existing gate and are not counted by these budgets.

Protection settings and throttle settings/revisions are independent. Saving does not deploy or remove either integration. Off exports contain no limit directives, zones or dry-run/status changes. Nginx remains an operator-owned manual deployment: WordPress receives no elevated privileges. Active throttle export requires the private operator preflight; browser requests cannot supply that attestation. The initial qualified profile conservatively refuses other active limit_req contexts, unqualified real-IP/proxy-protocol configuration and custom error_page handlers. Shared-limit operation remains unsupported; never enable dry run where it can weaken another guard. Ordinary core exports remain available.

Status reports matching observed configuration, missing deployment, unsupported engines or revision/mode drift. It never claims independent rate rejection, upstream avoidance or capacity from a saved toggle/header alone. No privileged logs or traffic counters are read by WordPress. Runtime tests and private operator logs remain the verification boundary. Zones use bounded native shared memory; restarting Nginx resets their in-memory state. Disable/remove only the optional throttle integration to retain cold-query protection.

Dynamic throttling is Nginx-specific. Apache/LiteSpeed/OpenLiteSpeed budget support is not implemented. A forgeable navigation cookie still is not human authentication, and IP/site budgets do not stop every distributed attack. Cached Apache refusal, unqualified vendor runtimes and payment/cache limitations below remain in force.

## Setup

1. Install and activate the plugin. Open **Settings → Quard**.
2. Review Protection and Rules. Saving changes only the desired policy.
3. Download all three configuration files from Advanced. Have a server administrator inspect the target virtual host, back up every affected file and install the files in the correct contexts.
4. Run `nginx -t`. Reload gracefully only after successful validation.
5. Confirm the observed revision matches, then use Test Protection. An observed revision alone does not mean the probes passed.

`http.conf` belongs in Nginx's HTTP context. `server.conf` belongs in the intended server context, before existing locations. Include `headers.conf` once at server level and repeat it in HTML-serving locations that define their own `add_header` directives. Preserve the existing PHP handler and WordPress rewrites. The primary `server_name` must match the canonical WordPress hostname used by the export.

WordPress never edits privileged server files. The guarded CLI alternative is:

```text
wp eval-file wp-content/plugins/quard/tools/export.php <existing-private-export-directory>
```

Run this as an authorized site operator. Keep exports, backups and operational reports outside the public document root. Deploy all three files from the same revision. Review integration again after hosting-panel or cache changes.

## Protection

Balanced includes `min_price`, `max_price`, `rating_filter`, `min_rating`, `filter_*`, and `query_type_*`, plus your additions. Standalone `orderby` remains allowed unless explicitly added. Strict adds `orderby`. Custom uses your parameter fields alone. Tracking, pagination and normal search do not automatically trigger blocking.

Names accept lowercase letters, digits, hyphens and underscores. Prefixes accept one trailing wildcard. Paths accept exact `/path` or subtree `/path/*`; the subtree includes `/path` itself. Root-wide `/*`, arbitrary regexes, directives and code are rejected. Current path input is ASCII; localized and subdirectory operational routes need explicit review.

Operational query names such as `rest_route`, `wc-ajax`, `wc-api` or `add-to-cart` **never exempt a protected request**. Requests containing only those keys continue through normal application routing because they do not contain a protected query. Such requests cannot issue clearance. To avoid a universal bypass, query-style APIs mixed with protected parameters need existing clearance or a carefully reviewed dedicated API path. Use native REST paths where appropriate.

Administration, native REST, login, cart, checkout, account and callback paths have built-in exclusions. Review your actual application routes, including custom authentication/payment endpoints, before enabling. Additional path exclusions and direct-access exceptions are explicit administrator choices: they permit protected queries on those paths, so use the smallest route possible. Do not exempt a storefront archive merely to accommodate an unrelated query key.

## Clearance and caches

A successful ordinary HTML GET navigation can establish `quard_nav=1` with Path=/, HttpOnly, SameSite=Lax, host-only scope and Secure on HTTPS. Nginx issues it, including when PHP is bypassed. Protected requests, operational queries, excluded paths, HEAD, AJAX/fetch and non-HTML responses cannot issue it. An existing valid cookie is not repeatedly refreshed.

Keep the header include at the final HTML-serving location, including cache locations. Verify both cleared and cookie-less visitors after enabling a page cache or CDN. Avoid storing and replaying the clearance Set-Cookie header from cached upstream responses.

The cookie is forgeable and has no cryptographic expiry or human-verification property. Max-Age only controls normal browser retention. A visitor opening a shared filtered URL directly may be denied and must first visit an ordinary page. The cookie gate is not a full bot-detection system. Optional native budgets are a separate setting.

## Diagnostics and retirement

Test Protection first checks the literal homepage and its cookie, then compares cleared navigation with a fresh shop/archive baseline. The native renewal HTTP probe is checked when advertised. Real menu clicks, expiry and browser history are explicitly separate NOT TESTED coverage in PHP diagnostics; run the operator browser acceptance test. It requires HTTP 200 HTML at the intended route with matching policy headers and matching available WordPress page/archive identity. Only same-origin, same-path canonicalization retaining query pairs is followed; the pagination probe also allows removal of `page=1`. Login/challenge redirects and missing clearance fail verification. A site whose markup cannot provide a comparable identity stays unverified.

The status request has a short timeout and never reuses cached success. Failed or unavailable loopback HTTP leaves integration unverified. HTTP probes do not prove PHP was bypassed; use Nginx upstream logs independently.

Before deactivation or deletion, deploy a disabled policy or remove the Quard includes/maps as one scoped server change. Validate and reload Nginx, then confirm enforcement is off. Plugin deletion cannot remove root-owned rules. Options remain non-autoloaded until explicitly removed by an operator.

Traffic does not collect analytics. Adapter readiness and managed deployment limits are described below; unqualified engines are not presented as supported. Private source/review bundles contain tests and operator documentation; they do not belong in the installed plugin directory.

## Portability and managed deployment (0.2)

Nginx's existing adapter and policy identity are retained. The Apache 2.4 document-root adapter uses original request-line classification, terminal rewrite denials and late response-header cookie issuance. It supports 403/410/429 in the tested uncached profile. Apache requires mod_rewrite, mod_headers and effective FileInfo overrides. The host-only cookie is not created with the domain-requiring CO flag.

Advanced offers separate preview/download labels for Nginx, Apache, LiteSpeed Enterprise and OpenLiteSpeed. Managed Apache preflight requires the real document root, native module inventory, no loaded cache/pagespeed module, correct ownership/writability, and an actual rewrite/header challenge. PHP-FPM environments without native module inventory use manual export. A fresh preview shows the exact path/diff; apply uses a server-held snapshot, lock, private backup and atomic replacement. Concurrent edits, symlinks, unowned/changed/missing/duplicate markers and ambiguous roots are refused. The Quard marker block is outside WordPress and cache-owned regions.

Removal and recovery also require previews. Only an owned block is removed. A failed HTTP smoke check restores the exact previous bytes; later concurrent changes prevent blind restoration and require operator recovery. Backups remain in a private sibling directory outside the document root. Managed deactivation attempts cleanup; failed cleanup preserves a durable warning and stops deactivation/deletion. Forced filesystem removal or silent upgrade hooks cannot guarantee cleanup. Nginx always needs manual retirement.

Apache cached deployment remains **NOT READY**. Genuine cache HIT tests reproduced missing clearance and, with CacheQuickHandler On, bypass of a cold denial on a prewarmed protected URL. QuickHandler Off alone still lost fresh headers. An explicit CACHE filter marker restored issuance in an isolated WordPress fixture, but rewritten routes shared a cache key and returned the wrong page, including checkout/account routes. That experimental profile is not shipped as supported. Automatic installation refuses loaded cache modules; ordinary diagnostic probes cannot qualify a cache. Server/vhost cache directives require an administrator and must never be silently changed by WordPress. Unknown proxies/CDNs also require separate qualification. The uncached native Apache workflow was qualified on a disposable WordPress/WooCommerce fixture; owner-site and real payment qualification remain separate.

LiteSpeed Enterprise has an **experimental uncached PHP-clearance candidate**, limited to 403, inherited from the v1.1.0 GitHub tag. Its stateless rewrite classifier enforces denial in the server; the first-party PHP issuer can grant clearance only when an eligible WordPress navigation executes. It does not qualify LSCache HIT issuance. Manual preview is available even when the edition is unknown, but generation does not establish Enterprise identity or runtime support. No automatic Enterprise apply is shipped. This development task did not test a real LiteSpeed server; a storefront rollout still requires exact-profile policy, browser and pre-PHP qualification. OpenLiteSpeed is **NOT READY / deferred**: no deployable adapter; its rewrite autoload, restart and header behavior need separate runtime verification. Never treat these as a generic LiteSpeed-supported badge.

Private release documents contain server-specific integration, cache limitations, test evidence and the future-site smoke checklist. Only this generic guidance and runtime files belong in the installed plugin.

## Nginx page-cache qualification (0.2.2)

The existing Nginx adapter was qualified on isolated WordPress/WooCommerce FastCGI-cache HTTP/HTTPS and proxy-cache HTTP profiles with real MISS/HIT and independent upstream/PHP evidence. This is profile-specific testing, not automatic certification of a host, CDN or cache plugin. The original GET issuer and cold-query matching semantics are retained; the navigation-recovery hotfix adds the separate native renewal route. No live cache is enabled by activating Quard.

Install the server guard before cache/location handling. Cache keys must preserve the original requested URI and relevant origin identity; do not collapse WordPress routes onto index.php. Keep normal session/private/operational bypass and no-store behavior, and respect upstream Set-Cookie/Cache-Control. The navigation cookie is added by Nginx per response, not stored as a personalized cache token. Use a single Quard issuer.

Nginx 1.28 uses standard add_header inheritance: a child location declaring any add_header drops parent declarations. Repeat the Quard header include in every applicable final location and retain the site's existing security headers there. Newer inheritance directives must not be assumed available. Test real cached normal HTML and a cleared-warmed protected URL requested cold. Header labels alone do not prove no upstream execution.

Eligible successful HTML GET responses issue clearance. HEAD, redirects, 304, errors, assets, operational and protected requests do not; a WordPress document carrying the navigation bridge renews separately after a conditional 304. Older documents and static HTML without the script need a full eligible 200 navigation. Existing valid clearance is not refreshed. Test Protection validates exactly one correctly scoped Quard cookie independently of unrelated cookies; conflicting or malformed Quard cookies fail. Ordinary probes still do not qualify cache HIT/upstream behavior or payments. Apache cached refusal, unqualified LiteSpeed Enterprise and deferred OpenLiteSpeed are unchanged.
