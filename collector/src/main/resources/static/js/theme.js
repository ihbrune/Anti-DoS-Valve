/**
 * Theme Manager for Anti-DoS Collector
 * Provides seamless Dark / Light mode switching with localStorage & Cookie persistence
 * and prevents Flash of Unstyled Content (FOUC).
 */
(function () {
    function getStoredTheme() {
        try {
            var stored = localStorage.getItem('theme');
            if (stored) return stored;
            var match = document.cookie.match(/(?:^|; )theme=([^;]*)/);
            if (match) return decodeURIComponent(match[1]);
        } catch (e) { }
        return null;
    }

    function applyInitialTheme() {
        var preferred = getStoredTheme();
        if (preferred === 'light' || (!preferred && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches)) {
            document.documentElement.setAttribute('data-theme', 'light');
        } else {
            document.documentElement.setAttribute('data-theme', 'dark');
        }
    }

    // Apply immediately to prevent FOUC
    applyInitialTheme();

    window.toggleTheme = function () {
        try {
            var current = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', current);
            localStorage.setItem('theme', current);
            document.cookie = 'theme=' + current + ';path=/;max-age=31536000;SameSite=Lax';
        } catch (e) {
            console.warn('Theme switch error:', e);
        }
    };

    window.openHelpDrawer = function () {
        var drawer = document.getElementById('help-drawer');
        var backdrop = document.getElementById('help-drawer-backdrop');
        if (drawer) drawer.classList.add('open');
        if (backdrop) backdrop.classList.add('open');
    };

    window.closeHelpDrawer = function () {
        var drawer = document.getElementById('help-drawer');
        var backdrop = document.getElementById('help-drawer-backdrop');
        if (drawer) drawer.classList.remove('open');
        if (backdrop) backdrop.classList.remove('open');
    };

    window.closeNoteModal = function (e) {
        if (e) {
            if (typeof e.stopPropagation === 'function') e.stopPropagation();
            if (typeof e.preventDefault === 'function') e.preventDefault();
        }
        var c = document.getElementById('note-modal-container');
        if (c) c.innerHTML = '';
        document.querySelectorAll('.note-modal-overlay, #note-modal-wrapper').forEach(function (el) {
            el.remove();
        });
    };

    window.updateTargetPlaceholder = function (targetType) {
        var input = document.getElementById('targetKeyInput');
        var help = document.getElementById('targetHelpText');
        if (!input || !help) return;

        if (targetType === 'ASN') {
            input.placeholder = 'e.g. AS24940 or 24940';
            help.innerHTML = 'ASN format: e.g. <code>AS24940</code> (Hetzner), <code>AS16276</code> (OVH)';
        } else {
            input.placeholder = 'e.g. 198.51.100.0/24 or 2001:db8::/64';
            help.innerHTML = 'Subnet CIDR e.g. <code>198.51.100.0/24</code> or IPv6 <code>2001:db8::/64</code>';
        }
    };

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            window.closeHelpDrawer();
            window.closeNoteModal();
            if (typeof window.closeHistoryDrawer === 'function') {
                window.closeHistoryDrawer();
            }
        }
    });
})();
