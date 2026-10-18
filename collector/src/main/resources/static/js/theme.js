/**
 * Theme Manager for Anti-DoS Collector
 * Provides seamless Dark / Light mode switching with localStorage & Cookie persistence
 * and prevents Flash of Unstyled Content (FOUC).
 */
(function() {
    function getStoredTheme() {
        try {
            var stored = localStorage.getItem('theme');
            if (stored) return stored;
            var match = document.cookie.match(/(?:^|; )theme=([^;]*)/);
            if (match) return decodeURIComponent(match[1]);
        } catch (e) {}
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

    window.toggleTheme = function() {
        try {
            var current = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', current);
            localStorage.setItem('theme', current);
            document.cookie = 'theme=' + current + ';path=/;max-age=31536000;SameSite=Lax';
        } catch (e) {
            console.warn('Theme switch error:', e);
        }
    };
})();
