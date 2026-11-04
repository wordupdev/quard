/* quard-navigation: usability only, not browser identity or bot authentication. */
(function () {
	'use strict';
	var config = window.quardNavigation;
	if (!config || window.top !== window || !window.fetch || !window.AbortController) { return; }
	var query = new RegExp(config.query, 'i');
	var excluded = new RegExp(config.excluded, 'i');
	var endpoint = new URL(config.endpoint, window.location.origin);
	if (endpoint.origin !== window.location.origin) { return; }
	var pending = null;
	var ticket = 0;
	function renew() {
		if (pending) { return pending; }
		var controller = new AbortController();
		var timeout = window.setTimeout(function () { controller.abort(); }, 4000);
		pending = fetch(endpoint.href, { method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { 'X-Quard-Navigation': '1' }, signal: controller.signal }).then(function (response) {
			if (response.status !== 204) { throw new Error('Renewal unavailable'); }
		}).finally(function () { window.clearTimeout(timeout); pending = null; });
		return pending;
	}
	function resume() { if (document.visibilityState === 'visible') { renew().catch(function () {}); } }
	window.addEventListener('pageshow', resume);
	window.addEventListener('focus', resume);
	document.addEventListener('visibilitychange', resume);
	document.addEventListener('click', function (event) {
		if (!event.isTrusted || event.defaultPrevented || event.button !== 0) { return; }
		var anchor = event.target.closest && event.target.closest('a[href]');
		if (!anchor || anchor.hasAttribute('download')) { return; }
		var url = new URL(anchor.href, window.location.href);
		if (url.origin !== window.location.origin || !/^https?:$/.test(url.protocol) || excluded.test(url.pathname) || !query.test(url.search.slice(1))) { return; }
		// A fragment-only jump is not a dynamic navigation.
		if (url.pathname === location.pathname && url.search === location.search && url.hash) { return; }
		event.preventDefault();
		event.stopImmediatePropagation();
		var current = ++ticket;
		var separate = event.ctrlKey || event.metaKey || event.shiftKey || anchor.target === '_blank';
		var popup = separate ? window.open('about:blank', '_blank') : null;
		if (popup) { popup.opener = null; }
		renew().then(function () {
			if (current !== ticket) { if (popup) { popup.close(); } return; }
			if (separate) { if (popup) { popup.location.href = url.href; } return; }
			// Replay through the site's normal click handlers, including WooCommerce AJAX navigation.
			// Programmatic clicks are untrusted and skip this listener; the native gate remains unchanged.
			if (anchor.isConnected && anchor.href === url.href) { anchor.click(); }
		}).catch(function () {
			if (popup) { popup.close(); }
			var notice = document.getElementById('quard-navigation-error');
			if (!notice) { notice = document.createElement('p'); notice.id = 'quard-navigation-error'; notice.setAttribute('role', 'alert'); document.body.prepend(notice); }
			notice.textContent = config.error;
		});
	}, true);
}());
