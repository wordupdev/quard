# Dull Knife (Nginx)

Sharp Knife is Quard's existing cold-navigation cookie gate. Dull Knife is an independent, opt-in bot/query denial. Both new switches default **Off**. Installing the plugin does not deploy server rules.

In Settings → Quard → Dull Knife:

1. Set **Bots** to plain User-Agent tokens, one per line. Matching is a case-insensitive substring, not identity verification. Suggestions are editable: Googlebot, bingbot, OAI-SearchBot, GPTBot, ClaudeBot, facebookexternalhit. ChatGPT-User is user-triggered fetching, not an automatic training crawler.
2. Set **Dynamic strings** to exact lowercase query keys or a trailing wildcard: `min_price`, `max_price`, `filter_*`, `query_type_*`, `orderby`. Values containing these words do not match. Rules use the existing Sharp parameter-name/encoding semantics.
3. Select 403 (default), 404, or explicitly acknowledge 410's permanent-removal/indexing risk. No Dull 429 option exists.
4. Exclude dedicated indexable landing paths if needed. Exact `/landing/` or subtree `/landing/*` only. These are **Dull** exclusions, not a new Sharp bypass. Existing operational paths and Sharp exceptions are also excluded from Dull.
5. Save desired policy; export all three Nginx files from Advanced. A privileged operator reviews and deploys them together, runs `nginx -t`, gracefully reloads, tests requests and retains exact rollback files. WordPress never writes Nginx configuration.

For GET/HEAD, Dull checks bot token AND configured query key AND non-excluded path before Sharp or upstream/cache. A clearance cookie or verified crawler address cannot override Dull. POST and excluded operational routes receive no new Dull denial. Existing server restrictions still apply.

**SEO warning:** Any bot-only denial can affect indexing. Google explicitly strongly advises against returning 410 to Googlebot while returning 200 to people for the same URL. 410 signals permanent removal; 404 signals missing content. This is a deliberate owner policy, not Google-recommended or SEO-safe behavior. Google's usual faceted-crawl recommendation is robots.txt; Quard does not alter it or metadata. Review important landing URLs before enabling.

## Optional verified crawler exemption from Sharp

A separate switch permits a selected known crawler family to bypass **only Sharp**, requiring its specific UA family plus its own freshly published official CIDRs and an original socket source address. Dull, WAF/bot firewalls and all other server restrictions remain effective. A claimed Googlebot or other UA alone never earns an exemption.

Googlebot common crawler, Bingbot, OAI-SearchBot, GPTBot, ChatGPT-User and OAI-AdsBot have separate mappings. ClaudeBot and facebookexternalhit can be Dull tokens but are not given exemptions here. Ambiguous multiple known bot families receive none. Only the direct-client Nginx profile is qualified; trusted proxy chains require separate qualification. Never enable an unreviewed X-Forwarded-For trust rule.

The operator tool `tools/refresh-crawlers.py` is in the separate source/operator bundle, not the public plugin directory. It fetches only fixed official HTTPS URLs, validates public IPv4/IPv6 CIDRs, atomically publishes a root-owned private snapshot outside the document root and retains its previous copy. It neither changes settings nor deploys Nginx rules. No network/DNS request runs in a visitor's request path.

Refresh **daily**, export and redeploy. The native time guard expires exemptions after at most 24 hours, even without PHP or reload. Invalid/missing data generates no exemption; expired deployed rules fail closed to Sharp. Refreshing the snapshot alone does not extend running rules. Check observed policy and expiry independently. Matching policy headers show configuration identity, not proof of a real crawler visit, Dull acceptance, or SEO success.

A bot can change its claimed User-Agent and evade a token-based Dull rule. The navigation cookie remains forgeable. This edition reduces cold query spraying; it does not prove human identity. Disabling plugin controls or removing WordPress files cannot remove already deployed Nginx rules. Retire server rules before uninstalling. Apache's existing uncached Sharp adapter remains; these new features are Nginx-only. Cached Apache is NOT READY, LiteSpeed Enterprise NOT TESTED LIVE, OpenLiteSpeed deferred. Real payment flows remain unqualified. Optional budgets combined with Dull/exemptions are not qualified; keep them Off.
