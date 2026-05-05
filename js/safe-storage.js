/* Centralized localStorage wrapper.
 *
 * Browsers in private mode, isolated/RBI sessions, and storage-quota-exhausted
 * tabs all throw on localStorage.get/set in different ways. Ad-hoc try/catch
 * scattered across the codebase masks failures inconsistently -- some swallow,
 * some console.warn, some surface to the user. This wrapper normalizes:
 *   - read returns the supplied default on any failure
 *   - write reports the failure via the optional onError callback
 *
 * Loads as a plain script (window.SafeStorage). Use `defer` so consumers can
 * see it on DOMContentLoaded. Do NOT use this for the pre-paint theme script
 * in <head> -- that has to run synchronously before CSS paint and is
 * deliberately inline.
 */
(function () {
    'use strict';
    window.SafeStorage = {
        get: function (key, defaultValue) {
            try {
                var v = localStorage.getItem(key);
                return v == null ? defaultValue : v;
            } catch (_) {
                return defaultValue;
            }
        },
        set: function (key, value, onError) {
            try {
                localStorage.setItem(key, String(value));
                return true;
            } catch (e) {
                if (typeof onError === 'function') {
                    try { onError(e); } catch (_) { /* swallow handler error */ }
                }
                return false;
            }
        },
        remove: function (key) {
            try { localStorage.removeItem(key); return true; }
            catch (_) { return false; }
        },
    };
})();
