/**
 * Anti-DoS Collector - Desktop & In-App Notification Manager
 *
 * Monitors autonomous mitigation events (AUTO_BLOCK, AUTO_EXTEND, AUTO_CIRCUIT_BREAKER)
 * and triggers HTML5 desktop notifications (even when the tab is in the background)
 * as well as floating in-app toast banners.
 */
(function() {
    'use strict';

    const STORAGE_KEY_LAST_ID = 'antidos_last_alert_id';
    const POLL_INTERVAL_MS = 10000;

    let pollTimer = null;

    function getToastContainer() {
        let container = document.getElementById('collector-toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'collector-toast-container';
            document.body.appendChild(container);
        }
        return container;
    }

    function updateBellIcon() {
        const btns = document.querySelectorAll('.notification-toggle-btn');
        if (!btns || btns.length === 0) return;

        btns.forEach(btn => {
            let dot = btn.querySelector('.notification-status-dot');
            if (!dot) {
                dot = document.createElement('span');
                dot.className = 'notification-status-dot';
                btn.appendChild(dot);
            }

            if (!('Notification' in window)) {
                dot.className = 'notification-status-dot default';
                btn.title = 'Desktop Notifications not supported by this browser (In-app toasts active)';
                return;
            }

            const perm = Notification.permission;
            if (perm === 'granted') {
                dot.className = 'notification-status-dot';
                dot.style.display = 'block';
                btn.title = 'Desktop & in-app alerts are active (Click to test)';
            } else if (perm === 'denied') {
                dot.className = 'notification-status-dot denied';
                dot.style.display = 'block';
                btn.title = 'Desktop notifications are blocked in your browser settings (Click for info)';
            } else {
                dot.className = 'notification-status-dot default';
                dot.style.display = 'block';
                btn.title = 'Click to enable desktop notifications for auto-mitigation events';
            }
        });
    }

    function showCollectorToast(opts) {
        const container = getToastContainer();
        const toast = document.createElement('div');
        const type = opts.type || 'info';
        toast.className = 'collector-toast ' + type;

        const timeStr = opts.timeStr || new Date().toLocaleTimeString();

        toast.innerHTML = `
            <div class="collector-toast-header">
                <div class="collector-toast-title">
                    <span>${opts.icon || '🛡️'}</span>
                    <span>${escapeHtml(opts.title || 'Anti-DoS Alert')}</span>
                </div>
                <button type="button" class="collector-toast-close" title="Dismiss">&times;</button>
            </div>
            <div class="collector-toast-body">${escapeHtml(opts.message || '')}</div>
            <div class="collector-toast-footer">
                <span class="collector-toast-time">${escapeHtml(timeStr)}</span>
                ${opts.actionUrl ? `<a href="${opts.actionUrl}" class="collector-toast-action">${escapeHtml(opts.actionText || 'View in Mitigation &rarr;')}</a>` : ''}
            </div>
        `;

        toast.querySelector('.collector-toast-close').addEventListener('click', function(e) {
            e.stopPropagation();
            dismissToast(toast);
        });

        if (opts.actionUrl) {
            toast.style.cursor = 'pointer';
            toast.addEventListener('click', function(e) {
                if (e.target.tagName !== 'A' && !e.target.classList.contains('collector-toast-close')) {
                    window.location.href = opts.actionUrl;
                }
            });
        }

        container.appendChild(toast);

        // Auto dismiss after 9 seconds
        setTimeout(() => {
            dismissToast(toast);
        }, 9000);
    }

    function dismissToast(toast) {
        if (!toast || !toast.parentNode) return;
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(40px)';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function handleNewAlert(alert) {
        let title = '🛡️ Anti-DoS Mitigation';
        let icon = '🛡️';
        let type = 'danger';
        let actionUrl = '/mitigation';

        if (alert.action === 'AUTO_BLOCK') {
            title = '🛡️ Auto-Mitigation: Subnet Blocked';
            icon = '⚡';
            type = 'danger';
        } else if (alert.action === 'AUTO_EXTEND') {
            title = '⏱️ Auto-Mitigation: TTL Extended';
            icon = '🔥';
            type = 'warning';
        } else if (alert.action === 'AUTO_CIRCUIT_BREAKER') {
            title = '⚠️ Auto-Mitigation: Circuit Breaker';
            icon = '⚠️';
            type = 'warning';
        }

        const body = alert.details || (alert.cidr ? `Subnet: ${alert.cidr}` : 'Autonomous defense action executed');

        // 1. Native Desktop Notification (works in background tabs/windows)
        if ('Notification' in window && Notification.permission === 'granted') {
            try {
                const n = new Notification(title, {
                    body: body,
                    tag: 'antidos-alert-' + alert.id,
                    icon: '/favicon.ico'
                });
                n.onclick = function() {
                    window.focus();
                    window.location.href = actionUrl;
                };
            } catch (err) {
                console.warn('Native notification failed:', err);
            }
        }

        // 2. In-App Floating Toast
        showCollectorToast({
            type: type,
            icon: icon,
            title: title,
            message: body,
            actionUrl: actionUrl,
            timeStr: alert.formattedCreatedAt ? alert.formattedCreatedAt : new Date().toLocaleTimeString()
        });
    }

    async function pollAlerts() {
        const storedLastId = localStorage.getItem(STORAGE_KEY_LAST_ID);
        const sinceId = storedLastId ? parseInt(storedLastId, 10) : -1;

        try {
            const res = await fetch('/api/v1/mitigation/alerts?sinceId=' + sinceId, {
                headers: { 'Accept': 'application/json' }
            });
            if (!res.ok) return;

            const data = await res.json();

            if (sinceId < 0) {
                // Initial baseline: mark current latestId without triggering alerts for past events
                localStorage.setItem(STORAGE_KEY_LAST_ID, data.latestId || 0);
                return;
            }

            if (data.hasNewAlerts && Array.isArray(data.alerts) && data.alerts.length > 0) {
                data.alerts.forEach(handleNewAlert);
                localStorage.setItem(STORAGE_KEY_LAST_ID, data.latestId);
            }
        } catch (err) {
            // Silently ignore network blips during polling
        }
    }

    window.toggleNotificationPermission = function() {
        if (!('Notification' in window)) {
            showCollectorToast({
                type: 'warning',
                icon: '⚠️',
                title: 'Notifications Not Supported',
                message: 'Your web browser does not support the Desktop Notification API. In-app toasts will continue to work.'
            });
            return;
        }

        const perm = Notification.permission;
        if (perm === 'granted') {
            // Trigger test notification
            try {
                const n = new Notification('🛡️ Anti-DoS Notifications Active', {
                    body: 'Desktop & in-app alerts are active. You will be notified whenever autonomous defenses trigger.',
                    tag: 'antidos-test',
                    icon: '/favicon.ico'
                });
                n.onclick = function() {
                    window.focus();
                    window.location.href = '/mitigation';
                };
            } catch (e) {}

            showCollectorToast({
                type: 'success',
                icon: '✅',
                title: 'Notifications Active',
                message: 'Desktop notifications are enabled. You will receive alerts even when the dashboard tab is in the background.'
            });
            updateBellIcon();
        } else if (perm === 'denied') {
            showCollectorToast({
                type: 'danger',
                icon: '🚫',
                title: 'Notifications Blocked',
                message: 'Browser notifications are blocked in your browser site permissions. Please allow notifications for this host to enable desktop alerts.'
            });
            updateBellIcon();
        } else {
            Notification.requestPermission().then(function(newPerm) {
                updateBellIcon();
                if (newPerm === 'granted') {
                    showCollectorToast({
                        type: 'success',
                        icon: '🔔',
                        title: 'Notifications Enabled',
                        message: 'Desktop alerts enabled! You will be notified of autonomous mitigation actions in real time.'
                    });
                    try {
                        new Notification('🔔 Anti-DoS Alerts Enabled', {
                            body: 'You will receive desktop alerts when the autonomous defense engine blocks or extends attacking subnets.',
                            tag: 'antidos-welcome',
                            icon: '/favicon.ico'
                        });
                    } catch (e) {}
                }
            });
        }
    };

    // Initialize on DOM ready
    function init() {
        updateBellIcon();
        // Initial poll after 1s, then every 10s
        setTimeout(pollAlerts, 1000);
        pollTimer = setInterval(pollAlerts, POLL_INTERVAL_MS);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
