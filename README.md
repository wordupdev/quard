<div align="center">

# Quard 🔪

**WordPress Query Guard**

*Cut wasteful dynamic requests before they cut into your server.*

</div>

Quard is a server-aware WordPress plugin designed to help site operators reduce costly dynamic URL traffic, particularly filter and sorting requests on WooCommerce stores. Quard lets administrators configure a policy in WordPress and export rules for review and installation at the web-server layer.

> [!IMPORTANT]
> **Development status — not a stable release.** This public repository contains engineering-candidate code and documentation. Do not assume it matches the latest private development work, is approved by WordPress.org, or is safe to deploy without a qualified operator review. The current private 2.0 release candidate is still undergoing compliance and platform admission. There is no publicly supported stable 2.0 installer.

## How Quard works

### Sharp Knife

Sharp Knife reduces cold requests to selected expensive dynamic URL patterns. A lightweight navigation cookie lets ordinary visitors first browse a normal page and then use supported filters. Denial rules are enforced at the web server in qualified configurations, so rejected traffic need not reach PHP.

**The navigation cookie is not proof of humanity or cryptographic authorization**. A determined client can acquire or forge it, and a direct link to a protected URL may be denied until a visitor navigates normally.

### Dull Knife

Dull Knife is a separate optional policy for declining selected bot User-Agents when they request selected dynamic URL patterns. It does not grant crawler identity or authenticate User-Agents. Bot-specific denial codes may affect crawling and indexing; configure only after reviewing the implications and actual server support.

### Diagnostics and controlled deployment

Quard distinguishes saved settings, generated rules, and the server configuration actually loaded. WordPress does not automatically own root-level Nginx files. An administrator must review, validate, deploy and verify exported rules.

## Compatibility boundaries

| Environment | Current status |
|---|---|
| Nginx | Primary engineering focus; configuration-specific qualification is required |
| Apache 2.4 | Uncached profiles have been tested; cached configurations remain unqualified |
| LiteSpeed Enterprise | Experimental only; not a supported production deployment target |
| OpenLiteSpeed | Deferred |

**Excluded from the proposed public 2.0 scope:** verified-crawler exemptions, crawler-snapshot publication/scheduling, and active dynamic throttling. Private experiments exist but are not approved for public operation. Older copies of the source may still expose experimental controls; their presence is **not** a support guarantee.

## Before testing Quard

1. Work on an isolated or disposable WordPress installation, never a production site.
2. Confirm your web server, routing and cache behavior.
3. Inspect policy output and identify any checkout, REST, webhook, account, and other operational paths.
4. Keep a verified server-configuration backup and rollback procedure.
5. Check real browser navigation, filter requests, and independent upstream/PHP logs before making deployment decisions.

**Never assume that deactivating the plugin removes server-level rules.** Remove or disable those rules safely and reload the server separately.

## Project status and contribution

Quard is under active hardening and independent review. Source-level test results are scoped to their documented fixtures and do not constitute universal platform certification. Current WordPress.org Plugin Check findings are still under review; **WordPress.org approval has not been granted**.

- For bugs and reproducible non-security issues, open a GitHub issue.
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) and avoid publishing exploit details in issues.
- For contribution guidance, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Maintainer and license

Maintained by [wordupdev](https://github.com/wordupdev). WordPress.org contributor: **mohsengham**.

Licensed under [GPL-2.0-or-later](LICENSE).
