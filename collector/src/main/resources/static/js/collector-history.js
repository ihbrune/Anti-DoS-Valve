/**
 * Investigation History & Cross-View Navigator for Anti-DoS Collector
 * 
 * Stores recently investigated IP addresses, CIDR subnets, and ASNs client-side
 * in the browser's localStorage (zero database overhead).
 * Provides a central slide-over navigation drawer to seamlessly pivot into
 * Incidents, Top Offenders, Subnet Profiles, Analytics, and Notes.
 */
(function() {
    'use strict';

    var STORAGE_KEY = 'antidos_investigation_history';
    var MAX_ENTRIES = 50;
    var currentFilter = 'ALL';
    var currentSearch = '';

    var AntiDoSHistory = {
        getHistory: function() {
            try {
                var raw = localStorage.getItem(STORAGE_KEY);
                if (raw) {
                    var parsed = JSON.parse(raw);
                    if (Array.isArray(parsed)) return parsed;
                }
            } catch (e) {
                console.warn('Failed to read investigation history from localStorage:', e);
            }
            return [];
        },

        saveHistory: function(list) {
            try {
                localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
                this.updateBadge(list.length);
            } catch (e) {
                console.warn('Failed to save investigation history to localStorage:', e);
            }
        },

        detectType: function(val, explicitType) {
            if (explicitType && (explicitType === 'IP' || explicitType === 'SUBNET' || explicitType === 'ASN')) {
                return explicitType;
            }
            if (!val) return 'IP';
            var s = String(val).trim();
            if (s.indexOf('/') !== -1) {
                return 'SUBNET';
            }
            if (/^AS\d+$/i.test(s)) {
                return 'ASN';
            }
            if (/^\d+$/.test(s) && parseInt(s, 10) > 0 && parseInt(s, 10) <= 4294967295) {
                // Digits only could be ASN if context implies or pure integer
                return 'ASN';
            }
            return 'IP';
        },

        normalizeValue: function(val, type) {
            var s = String(val).trim();
            if (type === 'ASN') {
                var num = s.replace(/^AS/i, '').trim();
                return 'AS' + num;
            }
            return s;
        },

        addEntry: function(item) {
            if (!item || !item.value) return;
            var rawVal = String(item.value).trim();
            if (!rawVal || rawVal === '—' || rawVal === '-' || rawVal === 'null') return;

            var type = this.detectType(rawVal, item.type);
            var normalizedVal = this.normalizeValue(rawVal, type);
            var id = type + ':' + normalizedVal.toLowerCase();

            var list = this.getHistory();
            var existingIndex = -1;
            for (var i = 0; i < list.length; i++) {
                if (list[i].id === id) {
                    existingIndex = i;
                    break;
                }
            }

            var mergedExtra = item.extra || (existingIndex >= 0 ? list[existingIndex].extra : null);
            var mergedSubnet = item.subnet || (existingIndex >= 0 ? list[existingIndex].subnet : null);
            var mergedAsn = item.asn || (existingIndex >= 0 ? list[existingIndex].asn : null);

            var newEntry = {
                id: id,
                type: type,
                value: normalizedVal,
                label: normalizedVal,
                extra: mergedExtra || null,
                subnet: mergedSubnet || null,
                asn: mergedAsn || null,
                timestamp: Date.now()
            };

            if (existingIndex >= 0) {
                list.splice(existingIndex, 1);
            }

            list.unshift(newEntry);

            if (list.length > MAX_ENTRIES) {
                list = list.slice(0, MAX_ENTRIES);
            }

            this.saveHistory(list);

            var drawer = document.getElementById('history-drawer');
            if (drawer && drawer.classList.contains('open')) {
                this.renderDrawer();
            }
        },

        removeEntry: function(id) {
            var list = this.getHistory();
            list = list.filter(function(entry) { return entry.id !== id; });
            this.saveHistory(list);
            this.renderDrawer();
        },

        clearHistory: function() {
            var list = this.getHistory();
            if (list.length === 0) return;
            if (confirm('Clear all ' + list.length + ' entries from your local investigation history?')) {
                this.saveHistory([]);
                this.renderDrawer();
            }
        },

        setFilter: function(filter) {
            currentFilter = filter || 'ALL';
            this.renderDrawer();
        },

        addFromInput: function() {
            var input = document.getElementById('history-search-input');
            if (!input) return;
            var val = input.value.trim();
            if (!val) return;
            this.addEntry({ value: val });
            input.value = '';
            currentSearch = '';
            this.renderDrawer();
        },

        openNoteModal: function(targetType, targetKey) {
            window.closeHistoryDrawer();
            var modalContainer = document.getElementById('note-modal-container');
            var normalizedKey = targetKey;
            var normType = (targetType === 'ASN') ? 'ASN' : 'SUBNET';

            if (modalContainer && window.htmx) {
                var url = '/notes/modal/view-target?targetType=' + encodeURIComponent(normType) +
                          '&targetKey=' + encodeURIComponent(normalizedKey) +
                          '&context=table';
                window.htmx.ajax('GET', url, { target: '#note-modal-container' });
            } else {
                window.location.href = '/notes?q=' + encodeURIComponent(normalizedKey);
            }
        },

        updateBadge: function(count) {
            if (typeof count !== 'number') {
                count = this.getHistory().length;
            }
            var badges = document.querySelectorAll('.history-badge-count');
            badges.forEach(function(badge) {
                if (count > 0) {
                    badge.textContent = count > 99 ? '99+' : count;
                    badge.style.display = 'inline-block';
                } else {
                    badge.style.display = 'none';
                }
            });
        },

        formatTimeAgo: function(timestamp) {
            if (!timestamp) return '';
            var diff = Math.floor((Date.now() - timestamp) / 1000);
            if (diff < 30) return 'Just now';
            if (diff < 60) return diff + 's ago';
            var mins = Math.floor(diff / 60);
            if (mins < 60) return mins + 'm ago';
            var hours = Math.floor(mins / 60);
            if (hours < 24) return hours + 'h ago';
            var days = Math.floor(hours / 24);
            if (days === 1) return 'Yesterday';
            if (days < 30) return days + 'd ago';
            return new Date(timestamp).toLocaleDateString();
        },

        renderDrawer: function() {
            var listContainer = document.getElementById('history-drawer-list');
            var countBadge = document.getElementById('history-total-count');
            if (!listContainer) return;

            var all = this.getHistory();
            var totalCount = all.length;
            if (countBadge) {
                countBadge.textContent = totalCount + (totalCount === 1 ? ' entry' : ' entries');
            }

            var ipCount = 0;
            var subnetCount = 0;
            var asnCount = 0;
            for (var i = 0; i < all.length; i++) {
                if (all[i].type === 'IP') ipCount++;
                else if (all[i].type === 'SUBNET') subnetCount++;
                else if (all[i].type === 'ASN') asnCount++;
            }

            var chipAll = document.getElementById('hist-chip-all');
            var chipIp = document.getElementById('hist-chip-ip');
            var chipSubnet = document.getElementById('hist-chip-subnet');
            var chipAsn = document.getElementById('hist-chip-asn');

            if (chipAll) chipAll.textContent = 'All (' + totalCount + ')';
            if (chipIp) chipIp.textContent = '🌐 IPs (' + ipCount + ')';
            if (chipSubnet) chipSubnet.textContent = '⚡ Subnets (' + subnetCount + ')';
            if (chipAsn) chipAsn.textContent = '🏢 ASNs (' + asnCount + ')';

            document.querySelectorAll('.history-chip').forEach(function(el) {
                if (el.getAttribute('data-filter') === currentFilter) {
                    el.classList.add('active');
                } else {
                    el.classList.remove('active');
                }
            });

            var searchLower = currentSearch.toLowerCase();
            var filtered = all.filter(function(item) {
                if (currentFilter !== 'ALL' && item.type !== currentFilter) {
                    return false;
                }
                if (searchLower) {
                    var valMatch = item.value && item.value.toLowerCase().indexOf(searchLower) !== -1;
                    var extraMatch = item.extra && item.extra.toLowerCase().indexOf(searchLower) !== -1;
                    return valMatch || extraMatch;
                }
                return true;
            });

            if (filtered.length === 0) {
                if (totalCount === 0) {
                    listContainer.innerHTML =
                        '<div class="history-empty-state">' +
                            '<div style="font-size: 32px; margin-bottom: 8px;">🕒</div>' +
                            '<div style="font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">No investigation history yet</div>' +
                            '<div style="font-size: 12px; color: var(--text-muted); line-height: 1.5; max-width: 320px; margin: 0 auto;">' +
                                'IP addresses, CIDR subnets, and ASNs you search, filter, or click on will be remembered here for instantaneous cross-tool navigation.' +
                            '</div>' +
                        '</div>';
                } else {
                    listContainer.innerHTML =
                        '<div class="history-empty-state">' +
                            '<div style="font-size: 24px; margin-bottom: 6px;">🔍</div>' +
                            '<div style="font-weight: 600; color: var(--text-primary);">No matching items found</div>' +
                            '<div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Try a different search query or clear the filter.</div>' +
                        '</div>';
                }
                return;
            }

            var html = '';
            for (var j = 0; j < filtered.length; j++) {
                var item = filtered[j];
                var typeClass = 'badge-info';
                var typeLabel = 'IP';
                var cleanAsn = item.value.replace(/^AS/i, '');

                if (item.type === 'SUBNET') {
                    typeClass = 'badge-warning';
                    typeLabel = 'SUBNET';
                } else if (item.type === 'ASN') {
                    typeClass = 'badge-purple';
                    typeLabel = 'ASN';
                }

                html += '<div class="history-card" data-id="' + item.id + '">';
                html +=   '<div class="history-card-header">';
                html +=     '<div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; min-width: 0;">';
                html +=       '<span class="badge ' + typeClass + '" style="font-size: 9px; padding: 2px 5px; font-weight: 700;">' + typeLabel + '</span>';
                html +=       '<span class="history-value ip-mono">' + escapeHtml(item.value) + '</span>';
                if (item.extra) {
                    html +=   '<span class="history-extra" title="' + escapeHtml(item.extra) + '">' + escapeHtml(item.extra) + '</span>';
                }
                html +=     '</div>';
                html +=     '<div style="display: flex; align-items: center; gap: 6px; flex-shrink: 0;">';
                html +=       '<span class="history-time">' + AntiDoSHistory.formatTimeAgo(item.timestamp) + '</span>';
                html +=       '<button type="button" class="history-item-del" onclick="AntiDoSHistory.removeEntry(\'' + item.id + '\')" title="Remove this entry">&times;</button>';
                html +=     '</div>';
                html +=   '</div>';

                // Action Navigation Buttons
                html +=   '<div class="history-card-actions">';
                if (item.type === 'IP') {
                    html += '<a href="/events?clientQuery=' + encodeURIComponent(item.value) + '" class="history-action-link" title="Explore raw incident timeline">📋 Incidents</a>';
                    html += '<a href="/offenders?clientQuery=' + encodeURIComponent(item.value) + '" class="history-action-link" title="Analyze offender surge & behavior">⚠️ Offenders</a>';
                    if (item.subnet) {
                        html += '<a href="/profiles?clientQuery=' + encodeURIComponent(item.subnet) + '" class="history-action-link" title="30-day baseline for subnet ' + escapeHtml(item.subnet) + '">⚡ Subnet</a>';
                    }
                    html += '<button type="button" class="history-action-link" onclick="AntiDoSHistory.openNoteModal(\'SUBNET\', \'' + escapeJs(item.value) + '\')" title="View or create investigative note">📝 Note</button>';
                } else if (item.type === 'SUBNET') {
                    html += '<a href="/profiles?clientQuery=' + encodeURIComponent(item.value) + '" class="history-action-link" title="30-day traffic profile & surge radar">⚡ Profiles</a>';
                    html += '<a href="/offenders?groupBy=SUBNET&clientQuery=' + encodeURIComponent(item.value) + '" class="history-action-link" title="Subnet rollup & offender table">⚠️ Rollup</a>';
                    html += '<a href="/events?clientQuery=' + encodeURIComponent(item.value) + '" class="history-action-link" title="Incident explorer for this subnet">📋 Incidents</a>';
                    html += '<button type="button" class="history-action-link" onclick="AntiDoSHistory.openNoteModal(\'SUBNET\', \'' + escapeJs(item.value) + '\')" title="View or create subnet note">📝 Note</button>';
                } else if (item.type === 'ASN') {
                    html += '<a href="/profiles?asn=' + encodeURIComponent(cleanAsn) + '" class="history-action-link" title="Subnet profiles in this ASN">⚡ Profiles</a>';
                    html += '<a href="/offenders?asn=' + encodeURIComponent(cleanAsn) + '" class="history-action-link" title="Top offenders from this ASN">⚠️ Offenders</a>';
                    html += '<a href="/events?asn=' + encodeURIComponent(cleanAsn) + '" class="history-action-link" title="Incidents from this ASN">📋 Incidents</a>';
                    html += '<a href="/analytics" class="history-action-link" title="Bot-mix & Residential proxy cluster">📊 Analytics</a>';
                    html += '<button type="button" class="history-action-link" onclick="AntiDoSHistory.openNoteModal(\'ASN\', \'' + escapeJs(item.value) + '\')" title="View or create ASN note">📝 Note</button>';
                }
                html +=   '</div>';
                html += '</div>';
            }

            listContainer.innerHTML = html;
        }
    };

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function escapeJs(str) {
        if (!str) return '';
        return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    }

    function extractRowMetadata(row) {
        if (!row) return null;
        var parts = [];
        var orgEl = row.querySelector('.as-org, [style*="font-size: 11px"], [style*="color: var(--text-muted)"]');
        if (orgEl && orgEl.textContent) {
            var orgText = orgEl.textContent.trim();
            if (orgText && orgText !== '—' && orgText.length < 50) parts.push(orgText);
        }
        var countryEl = row.querySelector('.badge-secondary');
        if (countryEl && countryEl.textContent) {
            var cText = countryEl.textContent.trim();
            if (cText && cText.length === 2) parts.push(cText);
        }
        var typeEl = row.querySelector('.badge-purple, .badge-warning, .badge-success, .badge-info');
        if (typeEl && typeEl.textContent) {
            var tText = typeEl.textContent.trim();
            if (tText && tText.indexOf('AS') === -1 && tText.indexOf('IP') === -1 && tText.length < 30) {
                parts.push(tText);
            }
        }
        return parts.length > 0 ? parts.join(' · ') : null;
    }

    function inspectCurrentUrl() {
        try {
            var params = new URLSearchParams(window.location.search);
            var clientQuery = (params.get('clientQuery') || '').trim();
            var asn = (params.get('asn') || '').trim();
            var q = (params.get('q') || '').trim();
            var targetKey = (params.get('targetKey') || '').trim();
            var targetType = (params.get('targetType') || '').trim();

            if (clientQuery) {
                AntiDoSHistory.addEntry({ value: clientQuery });
            }
            if (asn) {
                AntiDoSHistory.addEntry({ value: asn, type: 'ASN' });
            }
            if (q) {
                AntiDoSHistory.addEntry({ value: q });
            }
            if (targetKey) {
                AntiDoSHistory.addEntry({ value: targetKey, type: targetType });
            }
        } catch (e) {}
    }

    function ensureHistoryDrawerInDom() {
        if (document.getElementById('history-drawer')) return;

        var backdrop = document.createElement('div');
        backdrop.id = 'history-drawer-backdrop';
        backdrop.className = 'drawer-backdrop';
        backdrop.onclick = window.closeHistoryDrawer;

        var aside = document.createElement('aside');
        aside.id = 'history-drawer';
        aside.className = 'drawer-panel';
        aside.setAttribute('role', 'dialog');
        aside.setAttribute('aria-modal', 'true');
        aside.setAttribute('aria-label', 'Investigation History');

        aside.innerHTML =
            '<div class="drawer-header">' +
                '<div class="drawer-title">' +
                    '<span>🕒</span> Investigation History ' +
                    '<span id="history-total-count" class="badge badge-secondary" style="font-size: 11px; margin-left: 6px;">0 entries</span>' +
                '</div>' +
                '<div style="display: flex; align-items: center; gap: 8px;">' +
                    '<button type="button" class="btn btn-sm" style="font-size: 11px; padding: 4px 8px; color: var(--color-danger); border-color: rgba(239, 68, 68, 0.4);" onclick="AntiDoSHistory.clearHistory()" title="Clear all local investigation history">' +
                        '🗑️ Clear' +
                    '</button>' +
                    '<button type="button" class="drawer-close-btn" onclick="closeHistoryDrawer()" aria-label="Close History Drawer" title="Close History Drawer (Esc)">&times;</button>' +
                '</div>' +
            '</div>' +
            '<div class="drawer-body history-drawer-body">' +
                '<div class="history-search-bar">' +
                    '<input type="text" id="history-search-input" class="history-input" placeholder="Filter history or add IP, CIDR, ASN..." autocomplete="off">' +
                    '<button type="button" class="btn btn-sm" onclick="AntiDoSHistory.addFromInput()" title="Add target to history">+ Add</button>' +
                '</div>' +
                '<div class="history-chips">' +
                    '<button type="button" id="hist-chip-all" class="history-chip active" data-filter="ALL" onclick="AntiDoSHistory.setFilter(\'ALL\')">All</button>' +
                    '<button type="button" id="hist-chip-ip" class="history-chip" data-filter="IP" onclick="AntiDoSHistory.setFilter(\'IP\')">🌐 IPs</button>' +
                    '<button type="button" id="hist-chip-subnet" class="history-chip" data-filter="SUBNET" onclick="AntiDoSHistory.setFilter(\'SUBNET\')">⚡ Subnets</button>' +
                    '<button type="button" id="hist-chip-asn" class="history-chip" data-filter="ASN" onclick="AntiDoSHistory.setFilter(\'ASN\')">🏢 ASNs</button>' +
                '</div>' +
                '<div id="history-drawer-list" class="history-list"></div>' +
            '</div>';

        document.body.appendChild(backdrop);
        document.body.appendChild(aside);

        var searchInput = aside.querySelector('#history-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', function(e) {
                currentSearch = e.target.value.trim();
                AntiDoSHistory.renderDrawer();
            });
            searchInput.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    AntiDoSHistory.addFromInput();
                }
            });
        }
    }

    window.openHistoryDrawer = function() {
        ensureHistoryDrawerInDom();
        var drawer = document.getElementById('history-drawer');
        var backdrop = document.getElementById('history-drawer-backdrop');
        if (drawer) {
            AntiDoSHistory.renderDrawer();
            drawer.classList.add('open');
            var inp = drawer.querySelector('#history-search-input');
            if (inp) setTimeout(function() { inp.focus(); }, 100);
        }
        if (backdrop) backdrop.classList.add('open');
        if (typeof window.closeHelpDrawer === 'function') {
            window.closeHelpDrawer();
        }
    };

    window.closeHistoryDrawer = function() {
        var drawer = document.getElementById('history-drawer');
        var backdrop = document.getElementById('history-drawer-backdrop');
        if (drawer) drawer.classList.remove('open');
        if (backdrop) backdrop.classList.remove('open');
    };

    // Global click listener to automatically capture clicked IPs, Subnets, and ASNs across any table
    document.addEventListener('click', function(e) {
        var target = e.target;
        var el = target.closest('a, button, span.ip-mono, [data-history-key]');
        if (!el) return;

        // 1. Direct explicit data-history-key attribute
        if (el.dataset && el.dataset.historyKey) {
            AntiDoSHistory.addEntry({
                value: el.dataset.historyKey,
                type: el.dataset.historyType,
                extra: el.dataset.historyExtra
            });
            return;
        }

        // 2. Links with clientQuery or asn parameters
        var href = el.getAttribute('href') || el.getAttribute('hx-get') || '';
        if (href && (href.indexOf('clientQuery=') !== -1 || href.indexOf('asn=') !== -1 || href.indexOf('targetKey=') !== -1)) {
            try {
                var url = new URL(href, window.location.origin);
                var cq = url.searchParams.get('clientQuery');
                var asnParam = url.searchParams.get('asn');
                var tk = url.searchParams.get('targetKey');
                var tt = url.searchParams.get('targetType');
                var row = el.closest('tr');
                var extra = extractRowMetadata(row);

                if (cq) AntiDoSHistory.addEntry({ value: cq, extra: extra });
                if (asnParam) AntiDoSHistory.addEntry({ value: asnParam, type: 'ASN', extra: extra });
                if (tk) AntiDoSHistory.addEntry({ value: tk, type: tt, extra: extra });
            } catch (err) {}
        }

        // 3. Monospace IP / Subnet elements
        if (el.classList.contains('ip-mono') && !el.getAttribute('href')) {
            var text = el.textContent.trim();
            if (text && text.indexOf(' ') === -1 && text.length >= 7) {
                var r = el.closest('tr');
                var ext = extractRowMetadata(r);
                AntiDoSHistory.addEntry({ value: text, extra: ext });
            }
        }
    }, true);

    // Global form submit listener to capture submitted searches
    document.addEventListener('submit', function(e) {
        var form = e.target;
        if (!form) return;
        var cqInput = form.querySelector('input[name="clientQuery"]');
        var asnInput = form.querySelector('input[name="asn"]');
        var qInput = form.querySelector('input[name="q"]');

        if (cqInput && cqInput.value.trim()) {
            AntiDoSHistory.addEntry({ value: cqInput.value.trim() });
        }
        if (asnInput && asnInput.value.trim()) {
            AntiDoSHistory.addEntry({ value: asnInput.value.trim(), type: 'ASN' });
        }
        if (qInput && qInput.value.trim()) {
            AntiDoSHistory.addEntry({ value: qInput.value.trim() });
        }
    }, true);

    // Initialize on DOM load
    document.addEventListener('DOMContentLoaded', function() {
        ensureHistoryDrawerInDom();
        inspectCurrentUrl();
        AntiDoSHistory.updateBadge();
    });

    // Expose AntiDoSHistory globally
    window.AntiDoSHistory = AntiDoSHistory;

})();
