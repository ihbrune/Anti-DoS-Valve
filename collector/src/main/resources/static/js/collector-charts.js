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
        const markedData = timelineData.map(pt => pt.markedRequests || 0);

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
                    },
                    {
                        label: 'Marked / Simulation',
                        data: markedData,
                        backgroundColor: 'rgba(168, 85, 247, 0.85)',
                        hoverBackgroundColor: '#c084fc',
                        borderColor: '#9333ea',
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
                                let marked = 0;
                                tooltipItems.forEach(item => {
                                    total += item.raw;
                                    if (item.datasetIndex === 1) blocked = item.raw;
                                    if (item.datasetIndex === 2) marked = item.raw;
                                });
                                const blkPct = total > 0 ? ((blocked / total) * 100).toFixed(1) : '0.0';
                                const mrkPct = total > 0 ? ((marked / total) * 100).toFixed(1) : '0.0';
                                let text = `Total: ${total.toLocaleString()} reqs (${blkPct}% blocked`;
                                if (marked > 0) {
                                    text += `, ${mrkPct}% marked`;
                                }
                                text += ')';
                                return text;
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
                                const lines = [
                                    `Requests: ${reqs} (${item.percentage}%)`,
                                    `Blocked (429): ${blk}`
                                ];
                                if (item.markedRequests && item.markedRequests > 0) {
                                    lines.push(`Marked: ${item.markedRequests.toLocaleString()}`);
                                }
                                lines.push(`Subnets: ${item.subnetCount}`);
                                return lines;
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
                label: '🚨 Residential Proxy Evasion (High IP Spread, Low Reqs/IP)',
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

        // Compute min and max total requests across all points for dynamic relative scaling
        let minReqs = Infinity;
        let maxReqs = -Infinity;
        points.forEach(p => {
            const reqs = p.totalRequests || 0;
            if (reqs < minReqs) minReqs = reqs;
            if (reqs > maxReqs) maxReqs = reqs;
        });
        if (minReqs === Infinity) minReqs = 0;
        if (maxReqs === -Infinity) maxReqs = 0;

        const MIN_RADIUS = 6;
        const MAX_RADIUS = 26;

        points.forEach(p => {
            const grp = groups[p.classification] || groups['REGULAR_SUBNET'];
            let r = 12;
            if (maxReqs > minReqs) {
                // Square root scaling relative to dynamic min/max of current cluster dataset
                const fraction = (p.totalRequests - minReqs) / (maxReqs - minReqs);
                r = Math.round(MIN_RADIUS + Math.sqrt(Math.max(0, fraction)) * (MAX_RADIUS - MIN_RADIUS));
            }
            r = Math.max(MIN_RADIUS, Math.min(MAX_RADIUS, r));

            const ptItem = {
                x: p.distinctClients,
                y: p.averageRequestsPerClient,
                r: r,
                raw: p
            };
            if (p.hasNote) {
                if (p.noteVerdictColor) {
                    ptItem.borderColor = p.noteVerdictColor;
                    ptItem.borderWidth = 3;
                    ptItem.hoverBorderColor = p.noteVerdictColor;
                    ptItem.hoverBorderWidth = 4;
                } else {
                    ptItem.borderWidth = 3;
                    ptItem.hoverBorderWidth = 4;
                }
            }
            grp.data.push(ptItem);
        });

        const datasets = Object.values(groups)
            .filter(g => g.data.length > 0)
            .map(g => ({
                label: g.label,
                data: g.data,
                backgroundColor: g.bg,
                borderColor: function(context) {
                    const raw = context.raw && (context.raw.raw || context.raw);
                    if (raw && raw.hasNote && raw.noteVerdictColor) {
                        return raw.noteVerdictColor;
                    }
                    return g.border;
                },
                borderWidth: function(context) {
                    const raw = context.raw && (context.raw.raw || context.raw);
                    if (raw && raw.hasNote) {
                        return 3;
                    }
                    return 1.5;
                },
                hoverBorderColor: function(context) {
                    const raw = context.raw && (context.raw.raw || context.raw);
                    if (raw && raw.hasNote && raw.noteVerdictColor) {
                        return raw.noteVerdictColor;
                    }
                    return g.border;
                },
                hoverBorderWidth: function(context) {
                    const raw = context.raw && (context.raw.raw || context.raw);
                    if (raw && raw.hasNote) {
                        return 4;
                    }
                    return 2.5;
                }
            }));

        // Custom plugin drawing a circular arc around each bubble indicating the block-rate %
        const blockRateArcPlugin = {
            id: 'scatterBlockRateArc',
            afterDatasetDraw: function(chart, args) {
                const ctx = chart.ctx;
                const meta = chart.getDatasetMeta(args.index);
                if (!meta || !meta.data) return;

                meta.data.forEach((element, i) => {
                    const rawObj = chart.data.datasets[args.index].data[i];
                    if (!rawObj || !rawObj.raw) return;
                    const pt = rawObj.raw;
                    const total = pt.totalRequests || 0;
                    const blocked = pt.blockedRequests || 0;
                    if (total <= 0 || blocked <= 0) return;

                    const ratio = Math.min(1.0, blocked / total);
                    const x = element.x;
                    const y = element.y;
                    const radius = (element.options.radius || rawObj.r || 6) + 3.5;

                    ctx.save();
                    ctx.beginPath();
                    const startAngle = -Math.PI / 2; // Top center
                    const endAngle = startAngle + (ratio * 2 * Math.PI);
                    ctx.arc(x, y, radius, startAngle, endAngle, false);
                    ctx.strokeStyle = '#f43f5e'; // Danger red
                    ctx.lineWidth = 2.5;
                    ctx.lineCap = 'round';
                    ctx.stroke();
                    ctx.restore();
                });
            }
        };

        const chart = new Chart(canvas, {
            type: 'bubble',
            data: { datasets: datasets },
            plugins: [blockRateArcPlugin],
            options: {
                responsive: true,
                maintainAspectRatio: false,
                resizeDelay: 50,
                onClick: function(e, elements) {
                    if (elements.length > 0) {
                        const el = elements[0];
                        const pt = datasets[el.datasetIndex].data[el.index].raw;
                        if (pt && pt.subnetGroup) {
                            if (window.highlightScatterTableRow && window.highlightScatterTableRow(pt.subnetGroup)) {
                                return;
                            }
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
                                    let title = `Subnet: ${pt.subnetGroup}`;
                                    if (pt.hasNote && pt.noteVerdictIcon) {
                                        title += `  ${pt.noteVerdictIcon} [${pt.noteVerdictDisplayName || 'Note'}]`;
                                    }
                                    return title;
                                }
                                return '';
                            },
                            label: function(context) {
                                const pt = context.raw.raw;
                                const blkPct = pt.totalRequests > 0 ? ((pt.blockedRequests / pt.totalRequests) * 100).toFixed(1) : '0.0';
                                const lines = [
                                    `ISP: ${pt.asOrg} (${pt.asn ? 'AS' + pt.asn : '--'}) [${pt.countryCode}]`,
                                    `Classification: ${pt.clientType}`
                                ];

                                if (pt.hasNote) {
                                    if (pt.subnetNoteVerdict || pt.subnetNoteSnippet) {
                                        const icon = pt.subnetNoteIcon || '📝';
                                        const verdict = pt.subnetNoteVerdict ? `${icon} ${pt.subnetNoteVerdict}` : icon;
                                        const snip = pt.subnetNoteSnippet ? ` - "${pt.subnetNoteSnippet}"` : '';
                                        lines.push(`📝 Subnet Note: ${verdict}${snip}`);
                                    }
                                    if (pt.asnNoteVerdict || pt.asnNoteSnippet) {
                                        const icon = pt.asnNoteIcon || '📝';
                                        const asnLabel = pt.asn ? `AS${pt.asn}` : 'ASN';
                                        const verdict = pt.asnNoteVerdict ? `${icon} ${pt.asnNoteVerdict}` : icon;
                                        const snip = pt.asnNoteSnippet ? ` - "${pt.asnNoteSnippet}"` : '';
                                        lines.push(`📝 ASN Note (${asnLabel}): ${verdict}${snip}`);
                                    }
                                }

                                lines.push(
                                    `Distinct IPs in Subnet (X): ${pt.distinctClients}`,
                                    `Ø Requests / IP (Y): ${pt.averageRequestsPerClient}`,
                                    `Total Requests: ${pt.totalRequests.toLocaleString()}`,
                                    `Blocked (429): ${pt.blockedRequests.toLocaleString()} (${blkPct}%)`
                                );
                                if (pt.markedRequests && pt.markedRequests > 0) {
                                    lines.push(`Marked / Simulated: ${pt.markedRequests.toLocaleString()}`);
                                }
                                if (pt.isReturningTracked) {
                                    lines.push(`Cookie Retention: ${pt.returningRatioPercent.toFixed(1)}%`);
                                }
                                lines.push(`💡 Click to inspect in Offenders view`);
                                return lines;
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

    /**
     * Programmatically highlight a scatter point from external UI (e.g., hover over table row)
     */
    window.AntiDoSCharts.highlightScatterPoint = function(canvasId, subnetGroup) {
        const chart = chartInstances.get(canvasId);
        if (!chart) return;
        for (let d = 0; d < chart.data.datasets.length; d++) {
            const ds = chart.data.datasets[d];
            for (let i = 0; i < ds.data.length; i++) {
                if (ds.data[i].raw && ds.data[i].raw.subnetGroup === subnetGroup) {
                    chart.setActiveElements([{ datasetIndex: d, index: i }]);
                    chart.tooltip.setActiveElements([{ datasetIndex: d, index: i }], { x: 0, y: 0 });
                    chart.update('none');
                    return;
                }
            }
        }
    };

    /**
     * Clear programmatic scatter point highlight
     */
    window.AntiDoSCharts.clearScatterHighlight = function(canvasId) {
        const chart = chartInstances.get(canvasId);
        if (!chart) return;
        chart.setActiveElements([]);
        chart.tooltip.setActiveElements([], { x: 0, y: 0 });
        chart.update('none');
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
