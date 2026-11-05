/* Browser-only manual target preference. No policy, deployment or server-state writes. */
(function () {
    'use strict';
    var form = document.querySelector('.quard-app .quard-manual-target');
    if (!form) { return; }
    var select = form.querySelector('select[name="engine"]');
    var key = form.dataset.storageKey;
    var allowed = ['nginx', 'apache', 'litespeed-enterprise', 'openlitespeed'];
    var url = new URL(window.location.href);
    var valid = function (value) { return allowed.indexOf(value) !== -1; };
    try {
        if (!url.searchParams.has('engine')) {
            var stored = window.localStorage.getItem(key);
            if (valid(stored) && stored !== select.value) {
                url.searchParams.set('engine', stored);
                window.location.replace(url.toString());
                return;
            }
        }
        if (valid(select.value)) { window.localStorage.setItem(key, select.value); }
    } catch (error) {
        // Blocked storage still leaves ordinary GET preview, links and downloads functional.
    }
    form.addEventListener('submit', function () {
        try {
            if (valid(select.value)) { window.localStorage.setItem(key, select.value); }
            else { window.localStorage.removeItem(key); }
        } catch (error) { /* Preferences are optional. */ }
    });
}());
