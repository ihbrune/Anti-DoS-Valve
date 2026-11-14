/**
 * Anti-DoS Collector - Table & Scroll Ergonomics Manager
 *
 * Provides:
 * 1. Synchronized Viewport-Docked Floating Horizontal Scrollbar:
 *    Automatically detects wide .table-responsive containers and anchors a sleek
 *    horizontal scrollbar to the bottom of the viewport whenever the table is
 *    in view but its native bottom scrollbar is below the fold.
 * 2. Bi-directional Scroll Synchronization between the active table and floating bar.
 * 3. Left / Right Scroll Affordance Hints (visual gradient shadows when overflow exists).
 * 4. Keyboard Accessibility (tabindex="0", role="region", aria-label="Scrollable table").
 * 5. Clipboard Copy Utility (window.copyText).
 * 6. Full lifecycle support for HTMX dynamic swaps and window resizing.
 */
(function () {
    'use strict';

    let floatingScrollbar = null;
    let floatingContent = null;
    let activeContainer = null;
    let isSyncing = false;
    let ticking = false;

    function getFloatingScrollbar() {
        if (!floatingScrollbar) {
            floatingScrollbar = document.createElement('div');
            floatingScrollbar.className = 'table-floating-scrollbar';
            floatingScrollbar.setAttribute('aria-hidden', 'true');

            floatingContent = document.createElement('div');
            floatingContent.className = 'table-floating-scrollbar-content';
            floatingScrollbar.appendChild(floatingContent);

            floatingScrollbar.addEventListener('scroll', function () {
                if (isSyncing || !activeContainer) return;
                isSyncing = true;
                activeContainer.scrollLeft = floatingScrollbar.scrollLeft;
                isSyncing = false;
            }, { passive: true });

            document.body.appendChild(floatingScrollbar);
        }
        return floatingScrollbar;
    }

    function updateAffordance(container) {
        const maxScroll = container.scrollWidth - container.clientWidth;
        if (maxScroll <= 2) {
            container.classList.remove('can-scroll-left', 'can-scroll-right');
            return;
        }
        const sl = container.scrollLeft;
        container.classList.toggle('can-scroll-left', sl > 4);
        container.classList.toggle('can-scroll-right', sl < maxScroll - 4);
    }

    function evaluateTables() {
        const bar = getFloatingScrollbar();
        const containers = document.querySelectorAll('.table-responsive');
        const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
        const viewportWidth = window.innerWidth || document.documentElement.clientWidth;

        let target = null;
        let targetRect = null;

        for (let i = 0; i < containers.length; i++) {
            const c = containers[i];
            const maxScroll = c.scrollWidth - c.clientWidth;
            const hasOverflow = maxScroll > 2;

            if (hasOverflow) {
                if (!c.hasAttribute('tabindex')) {
                    c.setAttribute('tabindex', '0');
                    c.setAttribute('role', 'region');
                    if (!c.hasAttribute('aria-label')) {
                        c.setAttribute('aria-label', 'Scrollable table');
                    }
                }
            }
            updateAffordance(c);

            if (!target && hasOverflow) {
                const rect = c.getBoundingClientRect();
                // Check if container is partially visible in viewport,
                // top is above viewport bottom, and bottom is below viewport bottom
                if (rect.top < viewportHeight - 40 && rect.bottom > viewportHeight) {
                    target = c;
                    targetRect = rect;
                }
            }
        }

        if (target && targetRect) {
            activeContainer = target;
            bar.style.display = 'block';

            const left = Math.max(0, targetRect.left);
            const right = Math.min(viewportWidth, targetRect.right);
            const width = Math.max(0, right - left);

            bar.style.left = left + 'px';
            bar.style.width = width + 'px';
            floatingContent.style.width = target.scrollWidth + 'px';

            if (!isSyncing) {
                isSyncing = true;
                bar.scrollLeft = target.scrollLeft;
                isSyncing = false;
            }
        } else {
            activeContainer = null;
            bar.style.display = 'none';
        }
    }

    function requestEvaluate() {
        if (!ticking) {
            ticking = true;
            window.requestAnimationFrame(function () {
                evaluateTables();
                ticking = false;
            });
        }
    }

    function bindContainers() {
        const containers = document.querySelectorAll('.table-responsive');
        containers.forEach(function (c) {
            if (c.__tables_bound) return;
            c.__tables_bound = true;

            c.addEventListener('scroll', function () {
                updateAffordance(c);
                if (isSyncing || activeContainer !== c || !floatingScrollbar) return;
                isSyncing = true;
                floatingScrollbar.scrollLeft = c.scrollLeft;
                isSyncing = false;
            }, { passive: true });
        });
        requestEvaluate();
    }

    // Window Listeners
    window.addEventListener('scroll', requestEvaluate, { passive: true });
    window.addEventListener('resize', requestEvaluate, { passive: true });

    // HTMX lifecycle integration
    document.addEventListener('htmx:afterSettle', function () {
        bindContainers();
    });
    document.addEventListener('htmx:afterSwap', function () {
        bindContainers();
    });

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindContainers);
    } else {
        bindContainers();
    }

    // Public API
    window.refreshTableScrollbars = bindContainers;

    window.copyText = function (text, btn) {
        if (!text) return;
        const clean = text.trim();
        function markSuccess() {
            if (!btn) return;
            const orig = btn.innerHTML;
            btn.innerHTML = '<span>&#x2714;</span>';
            btn.classList.add('btn-copy-success');
            setTimeout(function () {
                btn.innerHTML = orig;
                btn.classList.remove('btn-copy-success');
            }, 1800);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(clean).then(markSuccess).catch(function () {
                fallbackCopy(clean, markSuccess);
            });
        } else {
            fallbackCopy(clean, markSuccess);
        }
    };

    function fallbackCopy(text, cb) {
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            if (cb) cb();
        } catch (e) {
            console.warn('Copy fallback failed:', e);
        }
    }
})();
