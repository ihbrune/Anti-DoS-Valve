/**
 * Anti-DoS Collector - Interactive Telemetry & Forensics Visualizations
 * Powered by Chart.js (Zero-npm, standalone UMD)
 * Supports dark/light theme switching, HTMX life-cycle, and responsive scaling.
 */
(function() {
    window.AntiDoSCharts = window.AntiDoSCharts || {};

    const chartInstances = new Map();

    function getThemeColors() {
        const isLight = document.documentElement.getAttribute('data-theme') === 'light';
        return {
            isLight: isLight,
            textColor: isLight ? '#475569' : '#94a3b8',
            gridColor: isLight ? 'rgba(0, 0, 0, 0.06)' : 'rgba(255, 255, 255, 0.07)',
            tooltipBg: isLight ? 'rgba(255, 255, 255, 0.96)' : 'rgba(15, 23, 42, 0.95)',
            tooltipText: isLight ? '#0f172a' : '#f8fafc',
            tooltipBorder: isLight ? 'rgba(0, 0, 0, 0.12)' : 'rgba(255, 255, 255, 0.15)'
        };
    }

    function destroyChart(canvasId) {
        const canvas = document.getElementById(canvasId);
        if (canvas && typeof Chart !== 'undefined' && typeof Chart.getChart === 'function') {
            try {
                const existing = Chart.getChart(canvas);
                if (existing) {
                    existing.destroy();
                }
            } catch (e) {
                console.warn('Could not destroy existing Chart.js instance on canvas:', canvasId, e);
            }
        }
        if (chartInstances.has(canvasId)) {
            try {
                chartInstances.get(canvasId).destroy();
            } catch (e) {
                console.warn('Could not destroy chart:', canvasId, e);
            }
            chartInstances.delete(canvasId);
        }
    }

    /**
     * 1. Traffic & Attack Timeline (Stacked Bar / Area)
     */
    window.AntiDoSCharts.renderTimeline = function(canvasId, timelineData) {
        if (typeof Chart === 'undefined') return;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        if (!timelineData || !Array.isArray(timelineData) || timelineData.length === 0) return;

        destroyChart(canvasId);
        const theme = getThemeColors();

        const labels = timelineData.map(pt => {
            const d = new Date(pt.bucketStart);
            return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' +
                   d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
        });

        const activeData = timelineData.map(pt => pt.activeRequests);
        const blockedData = timelineData.map(pt => pt.blockedRequests);

        const chart = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Allowed Requests',
                        data: activeData,
                        backgroundColor: 'rgba(56, 189, 248, 0.75)',
                        hoverBackgroundColor: '#38bdf8',
                        borderColor: '#0284c7',
                        borderWidth: 1,
                        borderRadius: 3,
                        stack: 'traffic'
                    },
                    {
                        label: 'Blocked Attacks (429)',
                        data: blockedData,
                        backgroundColor: 'rgba(244, 63, 94, 0.85)',
                        hoverBackgroundColor: '#f43f5e',
                        borderColor: '#e11d48',
                        borderWidth: 1,
                        borderRadius: 3,
                        stack: 'traffic'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                resizeDelay: 50,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: theme.textColor,
                            font: { family: 'inherit', size: 12, weight: '600' },
                            usePointStyle: true,
                            boxWidth: 8
                        }
                    },
                    tooltip: {
                        backgroundColor: theme.tooltipBg,
                        titleColor: theme.tooltipText,
                        bodyColor: theme.tooltipText,
                        borderColor: theme.tooltipBorder,
                        borderWidth: 1,
                        padding: 12,
                        boxPadding: 4,
                        callbacks: {
                            footer: function(tooltipItems) {
                                let total = 0;
                                let blocked = 0;
                                tooltipItems.forEach(item => {
                                    total += item.raw;
                                    if (item.datasetIndex === 1) blocked = item.raw;
                                });
                                const pct = total > 0 ? ((blocked / total) * 100).toFixed(1) : '0.0';
                                return `Total: ${total.toLocaleString()} reqs (${pct}% blocked)`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        stacked: true,
                        grid: { color: theme.gridColor },
                        ticks: {
                            color: theme.textColor,
                            font: { family: 'inherit', size: 11 },
                            maxRotation: 45,
                            autoSkip: true,
                            maxTicksLimit: 14
                        }
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        grid: { color: theme.gridColor },
                        ticks: {
                            color: theme.textColor,
                            font: { family: 'inherit', size: 11 },
                            callback: function(val) {
                                return val >= 1000 ? (val / 1000) + 'k' : val;
                            }
                        }
                    }
                }
            }
        });

        chartInstances.set(canvasId, chart);
    };

    /**
     * 2. Traffic Composition & Bot-Mix Donut
     */
    window.AntiDoSCharts.renderComposition = function(canvasId, compData) {
        if (typeof Chart === 'undefined') return;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        if (!compData || !Array.isArray(compData) || compData.length === 0) return;

        destroyChart(canvasId);
        const theme = getThemeColors();

        const colorMap = {
            'SEARCH_ENGINE': { bg: '#10b981', label: 'Search Engine' },
            'AI_CRAWLER': { bg: '#6366f1', label: 'AI Crawler' },
            'RESIDENTIAL': { bg: '#f59e0b', label: 'Residential ISP' },
            'DATACENTER': { bg: '#ec4899', label: 'Datacenter / Cloud' },
            'MOBILE': { bg: '#0ea5e9', label: 'Mobile Network' },
            'TOR_EXIT_NODE': { bg: '#a855f7', label: 'Tor Anonymizer' },
            'PRIVATE_NETWORK': { bg: '#64748b', label: 'Private Network' },
            'UNKNOWN': { bg: '#94a3b8', label: 'Standard / Unclassified' }
        };

        const labels = compData.map(c => `${c.icon} ${c.label}`);
        const values = compData.map(c => c.totalRequests);
        const backgroundColors = compData.map(c => (colorMap[c.clientType] ? colorMap[c.clientType].bg : '#94a3b8'));

        const chart = new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: backgroundColors,
                    borderWidth: 2,
                    borderColor: theme.isLight ? '#ffffff' : '#0f172a',
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                resizeDelay: 50,
                cutout: '66%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: theme.textColor,
                            font: { family: 'inherit', size: 11 },
                            boxWidth: 10,
                            padding: 10
                        }
                    },
                    tooltip: {
                        backgroundColor: theme.tooltipBg,
                        titleColor: theme.tooltipText,
                        bodyColor: theme.tooltipText,
                        borderColor: theme.tooltipBorder,
                        borderWidth: 1,
                        padding: 12,
                        callbacks: {
                            label: function(context) {
                                const item = compData[context.dataIndex];
                                const reqs = item.totalRequests.toLocaleString();
                                const blk = item.blockedRequests.toLocaleString();
                                return [
                                    `Requests: ${reqs} (${item.percentage}%)`,
                                    `Blocked (429): ${blk}`,
                                    `Subnets: ${item.subnetCount}`
                                ];
                            }
                        }
                    }
                }
            }
        });

        chartInstances.set(canvasId, chart);
    };

    /**
     * 3. Residential Proxy & Subnet Scatterplot (Cluster Intelligence)
     */
    window.AntiDoSCharts.renderScatter = function(canvasId, points) {
        if (typeof Chart === 'undefined') return;
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        if (!points || !Array.isArray(points) || points.length === 0) return;

        destroyChart(canvasId);
        const theme = getThemeColors();

        // Separate points by classification groups for distinct legend items
        const groups = {
            'HIGH_RISK_RESIDENTIAL': {
                label: '🚨 High Risk Residential Cluster',
                bg: 'rgba(244, 63, 94, 0.75)',
                border: '#f43f5e',
                data: []
            },
            'DATACENTER_CLUSTER': {
                label: '🏢 Datacenter / Cloud Scrapers',
                bg: 'rgba(245, 158, 11, 0.75)',
                border: '#f59e0b',
                data: []
            },
            'TOR_ANONYMIZER': {
                label: '🧅 Tor Exit Nodes',
                bg: 'rgba(168, 85, 247, 0.75)',
                border: '#a855f7',
                data: []
            },
            'VERIFIED_BOT': {
                label: '🤖 Search & AI Crawlers',
                bg: 'rgba(16, 185, 129, 0.75)',
                border: '#10b981',
                data: []
            },
            'REGULAR_SUBNET': {
                label: '🌐 Normal Subnets & Clients',
                bg: 'rgba(56, 189, 248, 0.65)',
                border: '#38bdf8',
                data: []
            }
        };

        points.forEach(p => {
            const grp = groups[p.classification] || groups['REGULAR_SUBNET'];
            grp.data.push({
                x: p.distinctClients,
                y: p.averageRequestsPerClient,
                r: Math.max(5, Math.min(24, Math.log10(p.totalRequests + 1) * 5)),
                raw: p
            });
        });

        const datasets = Object.values(groups)
            .filter(g => g.data.length > 0)
            .map(g => ({
                label: g.label,
                data: g.data,
                backgroundColor: g.bg,
                borderColor: g.border,
                borderWidth: 1.5,
                hoverBorderWidth: 2.5
            }));

        const chart = new Chart(canvas, {
            type: 'bubble',
            data: { datasets: datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                resizeDelay: 50,
                onClick: function(e, elements) {
                    if (elements.length > 0) {
                        const el = elements[0];
                        const pt = datasets[el.datasetIndex].data[el.index].raw;
                        if (pt && pt.subnetGroup) {
                            window.location.href = '/offenders?clientQuery=' + encodeURIComponent(pt.subnetGroup) + '&groupBy=SUBNET';
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: theme.textColor,
                            font: { family: 'inherit', size: 11, weight: '600' },
                            usePointStyle: true,
                            boxWidth: 8
                        }
                    },
                    tooltip: {
                        backgroundColor: theme.tooltipBg,
                        titleColor: theme.tooltipText,
                        bodyColor: theme.tooltipText,
                        borderColor: theme.tooltipBorder,
                        borderWidth: 1,
                        padding: 12,
                        callbacks: {
                            title: function(items) {
                                if (items.length > 0) {
                                    const pt = items[0].raw.raw;
                                    return `Subnet: ${pt.subnetGroup}`;
                                }
                                return '';
                            },
                            label: function(context) {
                                const pt = context.raw.raw;
                                const blkPct = pt.totalRequests > 0 ? ((pt.blockedRequests / pt.totalRequests) * 100).toFixed(1) : '0.0';
                                return [
                                    `ISP: ${pt.asOrg} (${pt.asn ? 'AS' + pt.asn : '--'}) [${pt.countryCode}]`,
                                    `Classification: ${pt.clientType}`,
                                    `Distinct IPs in Subnet (X): ${pt.distinctClients}`,
                                    `Ø Requests / IP (Y): ${pt.averageRequestsPerClient}`,
                                    `Total Requests: ${pt.totalRequests.toLocaleString()}`,
                                    `Blocked (429): ${pt.blockedRequests.toLocaleString()} (${blkPct}%)`,
                                    `💡 Click to inspect in Offenders view`
                                ];
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        type: 'logarithmic',
                        title: {
                            display: true,
                            text: 'Unique Client IPs in Subnet (Logarithmic)',
                            color: theme.textColor,
                            font: { weight: '600', size: 11 }
                        },
                        grid: { color: theme.gridColor },
                        ticks: {
                            color: theme.textColor,
                            callback: function(val) {
                                if (val === 1 || val === 5 || val === 10 || val === 50 || val === 100 || val === 250) {
                                    return val;
                                }
                                return null;
                            }
                        }
                    },
                    y: {
                        type: 'logarithmic',
                        title: {
                            display: true,
                            text: 'Average Requests per IP (Logarithmic)',
                            color: theme.textColor,
                            font: { weight: '600', size: 11 }
                        },
                        grid: { color: theme.gridColor },
                        ticks: {
                            color: theme.textColor,
                            callback: function(val) {
                                if (val === 1 || val === 5 || val === 10 || val === 50 || val === 100 || val === 500) {
                                    return val;
                                }
                                return null;
                            }
                        }
                    }
                }
            }
        });

        chartInstances.set(canvasId, chart);
    };

    // Auto-update charts when theme toggles
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'attributes' && mutation.attributeName === 'data-theme') {
                const theme = getThemeColors();
                chartInstances.forEach(function(chart) {
                    if (chart.options.scales) {
                        if (chart.options.scales.x) {
                            chart.options.scales.x.grid.color = theme.gridColor;
                            if (chart.options.scales.x.ticks) chart.options.scales.x.ticks.color = theme.textColor;
                            if (chart.options.scales.x.title) chart.options.scales.x.title.color = theme.textColor;
                        }
                        if (chart.options.scales.y) {
                            chart.options.scales.y.grid.color = theme.gridColor;
                            if (chart.options.scales.y.ticks) chart.options.scales.y.ticks.color = theme.textColor;
                            if (chart.options.scales.y.title) chart.options.scales.y.title.color = theme.textColor;
                        }
                    }
                    if (chart.options.plugins && chart.options.plugins.legend) {
                        chart.options.plugins.legend.labels.color = theme.textColor;
                    }
                    chart.update();
                });
            }
        });
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
})();
