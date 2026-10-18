/**
 * HTMX-Lite: Autonomous fallback engine for hx-get, hx-trigger, hx-target, and hx-swap.
 * Enables zero-dependency, 100% offline execution of reactive dashboard updates.
 */
(function() {
    function initHtmxElements(root) {
        if (window.htmx && window.htmx.version) {
            // Full HTMX already loaded from CDN
            return;
        }

        const scope = root || document;
        scope.querySelectorAll('[hx-get]').forEach(el => {
            if (el.__htmx_bound) return;
            el.__htmx_bound = true;

            const url = el.getAttribute('hx-get');
            const targetSel = el.getAttribute('hx-target');
            const trigger = el.getAttribute('hx-trigger') || 'click';
            const swap = el.getAttribute('hx-swap') || 'innerHTML';

            function executeSwap() {
                const targetEl = targetSel ? document.querySelector(targetSel) : el;
                if (!targetEl) return;

                el.classList.add('htmx-request');
                fetch(url, { headers: { 'HX-Request': 'true' } })
                    .then(res => {
                        if (!res.ok) throw new Error('HTTP ' + res.status);
                        return res.text();
                    })
                    .then(html => {
                        if (swap === 'outerHTML') {
                            const parent = targetEl.parentNode;
                            targetEl.outerHTML = html;
                            initHtmxElements(parent || document);
                        } else {
                            targetEl.innerHTML = html;
                            initHtmxElements(targetEl);
                        }
                        el.classList.remove('htmx-request');
                    })
                    .catch(err => {
                        console.warn('HTMX update error:', err);
                        el.classList.remove('htmx-request');
                    });
            }

            if (trigger.startsWith('every ')) {
                const intervalSec = parseInt(trigger.replace('every ', '').replace('s', ''), 10) || 10;
                setInterval(executeSwap, intervalSec * 1000);
            } else if (trigger === 'load') {
                executeSwap();
            } else {
                el.addEventListener(trigger, e => {
                    e.preventDefault();
                    executeSwap();
                });
            }
        });
    }

    document.addEventListener('DOMContentLoaded', () => initHtmxElements(document));
    window.initHtmxElements = initHtmxElements;
})();
