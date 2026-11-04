=== Quard ===
Contributors: mohsengham
Tags: security, performance, nginx, query, woocommerce
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Stop wasteful dynamic URL requests at the web server, before they consume WordPress and WooCommerce resources.

== Description ==

= Expensive requests. A sharper response. =

A single WooCommerce category can generate thousands of filter, price-range and sorting combinations. When those URLs are repeatedly requested, PHP and the database may do expensive work for pages nobody really needs.

**Quard** gives site operators a focused way to control that traffic. WordPress provides the settings and diagnostics; generated web-server rules enforce supported protections before WordPress has to run.

= Sharp Knife: protect dynamic requests =

* Define costly query parameters and wildcard patterns, including WooCommerce-style price and attribute filters.
* Reject protected cold/direct requests at Nginx before PHP.
* Allow normal browsing to establish a lightweight navigation cookie for subsequent filtered navigation.
* Review policy state and test expected behavior from the plugin settings page.

= Dull Knife: keep crawling useful =

* Match configured bot User-Agent patterns against selected dynamic query patterns.
* Return a chosen response status for those requests, without blocking ordinary catalog pages.
* Optionally exempt trusted crawler families from Sharp Knife using official IP ranges **and** User-Agent matching. A claimed User-Agent alone never establishes trust.

Dull Knife and crawler exemptions are optional, Nginx-only features. Bot-specific denial can affect indexing; carefully review patterns and response codes before enabling.

= Designed for cautious deployment =

* Clear separation between saved WordPress policy and deployed server configuration.
* Generated Nginx configuration for manual, administrator-controlled installation.
* Built-in HTTP diagnostics for common navigation and denial scenarios.
* Conservative defaults: new installations do not automatically modify Nginx.

Quard works especially well with WooCommerce but can also be configured for other WordPress sites using costly dynamic query URLs.

= Know the limits =

The navigation cookie is **not** cryptographic authentication or a human-verification challenge. A determined automated client can obtain or forge it. Quard primarily reduces cold dynamic URL spraying, not every form of automated traffic. Installed Nginx rules are not removed when the WordPress plugin is deactivated.

**Platform status:** Nginx is the primary supported deployment path. Uncached Apache has a tested limited profile; cached Apache remains unqualified. LiteSpeed Enterprise has not been qualified live; OpenLiteSpeed is deferred. Dull Knife and trusted crawler exemption currently require Nginx.

== Installation ==

1. Install and activate Quard in WordPress.
2. Open **Settings > Quard** and review the protection rules. Protection is off on new installations until you configure it.
3. Use **Advanced** to export the generated Nginx configuration files.
4. As a server administrator, install the HTTP-level maps in the Nginx `http` context and the site-specific directives and response headers in the appropriate virtual host and HTML locations. Preserve existing caching, security and PHP-FPM settings.
5. Run `nginx -t`; reload Nginx only after validation succeeds.
6. Return to **Settings > Quard > Protection** and run **Test Protection**.
7. Test real shopping, filter links, mobile browsing and any checkout/payment integrations before relying on the installation.

For deployment and rollback details, consult the included `README.md` and `DULL-KNIFE.md` documentation. Back up configuration before changes.

== Frequently Asked Questions ==

= Will Quard speed up every WordPress request? =

No. It aims to prevent selected wasteful dynamic requests from reaching PHP. Gains depend on the site's request patterns, caching and server configuration.

= Does Quard automatically change Nginx? =

No. Exported configuration must be installed, tested and reloaded by an authorized administrator.

= Is a navigation cookie proof of a human visitor? =

No. The cookie is a lightweight browser-navigation signal and can be forged.

= Will deactivating the plugin disable the server rules? =

No. Remove or deploy a disabled server policy before deactivating or deleting Quard. Validate and reload the web server.

= Can Dull Knife block Googlebot from filters without blocking product pages? =

Yes, when configured that way. Its bot and query-pattern matching is selective. Review SEO consequences carefully; returning different indexing signals to crawlers may affect search visibility.

= Is LiteSpeed supported? =

Not as a fully qualified storefront deployment in this release. Nginx is the primary supported platform.

== Changelog ==

= 1.0.0 =
* Initial public versioning baseline.
* Sharp Knife cold-query protection and navigation clearance.
* Optional Dull Knife dynamic-URL crawler rules.
* Optional official-IP-plus-User-Agent trusted crawler exemptions.
* Server-configuration exports and HTTP diagnostics.

== Upgrade Notice ==

= 1.0.0 =
Review the generated web-server policy carefully before enabling. Server changes require manual administration and are not undone by plugin deactivation.
