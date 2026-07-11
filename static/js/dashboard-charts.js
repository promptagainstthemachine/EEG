/**
 * Dashboard Chart.js charts — isolated from 3D threat graph so graph errors cannot break charts.
 */
(function () {
    'use strict';

    function readConfig() {
        var el = document.getElementById('dashboard-page-config');
        if (!el) return {};
        try {
            return JSON.parse(el.textContent);
        } catch (e) {
            return {};
        }
    }

    function parseJsonScript(id, fallback) {
        var el = document.getElementById(id);
        if (!el) return fallback;
        try {
            return JSON.parse(el.textContent);
        } catch (e) {
            return fallback;
        }
    }

    function safeRun(label, fn) {
        try {
            fn();
        } catch (err) {
            console.error('[dashboard-charts] ' + label + ' failed:', err);
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.body.style.overflow = '';
        document.documentElement.style.overflow = '';

        if (typeof Chart === 'undefined') {
            console.error('[dashboard-charts] Chart.js not loaded');
            return;
        }

        var config = readConfig();
        var chartColors = {
            critical: '#da3633',
            high: '#f85149',
            medium: '#d29922',
            low: '#3fb950',
            primary: '#58a6ff',
            bg: '#21262d'
        };

        var categoryChart = null;
        var severityChart = null;
        var scanChart = null;
        var timelineChart = null;
        var threatRadarChart = null;
        var charts = [];

        var severityColors = {
            critical: chartColors.critical,
            high: chartColors.high,
            medium: chartColors.medium,
            low: chartColors.low,
            info: chartColors.primary
        };

        var categoryColors = {
            command_injection: chartColors.critical,
            prompt_injection: chartColors.high,
            secrets: chartColors.medium,
            mcp: chartColors.primary,
            supply_chain: chartColors.low,
            agent_control: '#a371f7'
        };

        function findingsHrefForThreat(threatKey) {
            var params = new URLSearchParams();
            if (config.projectId) params.set('project', String(config.projectId));
            if (config.isRuntimeProject) {
                params.set('q', threatKey || '');
                var qs = params.toString();
                return '/findings/runtime/' + (qs ? ('?' + qs) : '');
            }
            if (threatKey) params.set('threat', threatKey);
            var query = params.toString();
            return '/findings/' + (query ? ('?' + query) : '');
        }

        function track(chart) {
            if (chart) charts.push(chart);
            return chart;
        }

        function resizeCharts() {
            charts.forEach(function (c) {
                if (c && typeof c.resize === 'function') c.resize();
            });
        }

        function setChartEmpty(elementId, hasData) {
            var el = document.getElementById(elementId);
            if (el) el.hidden = !!hasData;
        }

        function renderSeverityChart(payload) {
            var ctx = document.getElementById('severityPie');
            if (!ctx) return;

            var hasData = !!(payload && payload.has_data);
            setChartEmpty('severity-empty', hasData);

            if (severityChart) {
                severityChart.destroy();
                charts = charts.filter(function (c) { return c !== severityChart; });
                severityChart = null;
            }
            if (!hasData) return;

            var keys = payload.keys || [];
            var colors = keys.map(function (k) { return severityColors[k] || chartColors.primary; });

            severityChart = track(new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: payload.labels || [],
                    datasets: [{
                        data: payload.values || [],
                        backgroundColor: colors,
                        borderColor: chartColors.bg,
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '58%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#8b949e', boxWidth: 10, padding: 8, font: { size: 10 } }
                        }
                    },
                    onClick: function (e, elements) {
                        if (elements.length > 0 && keys[elements[0].index] && window.filterBySeverity) {
                            window.filterBySeverity(keys[elements[0].index]);
                        }
                    }
                }
            }));
        }

        function renderScanChart(payload) {
            var ctx = document.getElementById('scanBar');
            if (!ctx) return;

            var hasData = !!(payload && payload.has_data);
            setChartEmpty('scan-empty', hasData);

            if (scanChart) {
                scanChart.destroy();
                charts = charts.filter(function (c) { return c !== scanChart; });
                scanChart = null;
            }
            if (!hasData) return;

            scanChart = track(new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: payload.labels || [],
                    datasets: [{
                        data: payload.values || [],
                        backgroundColor: chartColors.primary,
                        borderRadius: 4,
                        borderSkipped: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: '#e6edf3', font: { size: 9 }, maxRotation: 45, minRotation: 0 }
                        },
                        y: {
                            grid: { color: '#30363d' },
                            ticks: { color: '#8b949e', precision: 0 },
                            beginAtZero: true
                        }
                    }
                }
            }));
        }

        function renderCategoryChart(payload) {
            var categoryCtx = document.getElementById('categoryBar');
            if (!categoryCtx) return;

            var hasData = !!(payload && payload.has_data);
            setChartEmpty('category-empty', hasData);

            if (categoryChart) {
                categoryChart.destroy();
                charts = charts.filter(function (c) { return c !== categoryChart; });
                categoryChart = null;
            }
            if (!hasData) return;

            var keys = payload.keys || [];
            var colors = keys.map(function (k) { return categoryColors[k] || chartColors.primary; });

            categoryChart = track(new Chart(categoryCtx, {
                type: 'bar',
                data: {
                    labels: payload.labels || [],
                    datasets: [{
                        data: payload.values || [],
                        backgroundColor: colors,
                        borderRadius: 4,
                        borderSkipped: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: {
                        x: {
                            grid: { color: '#30363d' },
                            ticks: { color: '#8b949e', precision: 0 }
                        },
                        y: {
                            grid: { display: false },
                            ticks: { color: '#e6edf3', font: { size: 10 } }
                        }
                    },
                    onClick: function (e, elements) {
                        if (elements.length > 0 && keys[elements[0].index]) {
                            window.location.href = findingsHrefForThreat(keys[elements[0].index]);
                        }
                    }
                }
            }));
        }

        function setTimelineEmpty(payload) {
            var emptyEl = document.getElementById('timeline-empty');
            if (!emptyEl) return;
            var hasData = !!(payload && payload.has_data);
            emptyEl.hidden = hasData;
            if (!hasData) {
                var hint = 'No findings yet. Gateway detections and Full Scan results appear on this timeline.';
                if (payload && payload.open_total > 0) {
                    hint = 'No change in this window (' + payload.open_total + ' open — try 30D or 90D).';
                }
                emptyEl.textContent = hint;
            }
        }

        function renderTimelineChart(payload) {
            var timelineCtx = document.getElementById('timelineChart');
            if (!timelineCtx) return;

            payload = payload || {};
            var labels = payload.labels || [];
            var critical = payload.critical_high || [];
            var medium = payload.medium_low || [];
            var newCritical = payload.new_critical_high || [];
            var newMedium = payload.new_medium_low || [];

            setTimelineEmpty(payload);

            if (timelineChart) {
                timelineChart.destroy();
                charts = charts.filter(function (c) { return c !== timelineChart; });
                timelineChart = null;
            }

            var maxVal = 0;
            critical.concat(medium).concat(newCritical).concat(newMedium).forEach(function (v) {
                if (v > maxVal) maxVal = v;
            });

            var datasets = [
                {
                    label: 'Open critical/high',
                    data: critical,
                    borderColor: chartColors.critical,
                    backgroundColor: 'rgba(218, 54, 51, 0.15)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.35,
                    pointRadius: labels.length > 14 ? 0 : 4,
                    pointHoverRadius: 6,
                    order: 2
                },
                {
                    label: 'Open medium/low/info',
                    data: medium,
                    borderColor: chartColors.medium,
                    backgroundColor: 'rgba(210, 153, 34, 0.12)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.35,
                    pointRadius: labels.length > 14 ? 0 : 4,
                    pointHoverRadius: 6,
                    order: 3
                }
            ];

            if (newCritical.some(function (v) { return v > 0; }) || newMedium.some(function (v) { return v > 0; })) {
                datasets.push({
                    label: 'New critical/high',
                    data: newCritical,
                    borderColor: chartColors.high,
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    borderDash: [6, 4],
                    fill: false,
                    tension: 0.25,
                    pointRadius: labels.length > 14 ? 0 : 3,
                    order: 0
                });
                datasets.push({
                    label: 'New medium/low/info',
                    data: newMedium,
                    borderColor: chartColors.low,
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    borderDash: [6, 4],
                    fill: false,
                    tension: 0.25,
                    pointRadius: labels.length > 14 ? 0 : 3,
                    order: 1
                });
            }

            timelineChart = track(new Chart(timelineCtx, {
                type: 'line',
                data: { labels: labels, datasets: datasets },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: { mode: 'index', intersect: false },
                    plugins: {
                        legend: {
                            position: 'top',
                            align: 'end',
                            labels: { color: '#8b949e', boxWidth: 12, padding: 8, font: { size: 10 } }
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: '#30363d' },
                            ticks: {
                                color: '#8b949e',
                                font: { size: 10 },
                                maxRotation: 0,
                                autoSkip: true,
                                maxTicksLimit: labels.length > 14 ? 12 : 7
                            }
                        },
                        y: {
                            grid: { color: '#30363d' },
                            ticks: { color: '#8b949e', font: { size: 10 }, precision: 0 },
                            beginAtZero: true,
                            suggestedMax: maxVal > 0 ? Math.max(maxVal + 1, 3) : 5
                        }
                    }
                }
            }));
        }

        function setThreatRadarEmpty(hasData) {
            var el = document.getElementById('threat-radar-empty');
            if (el) el.hidden = !!hasData;
        }

        function renderThreatRadarChart(payload) {
            var radarCtx = document.getElementById('threatRadar');
            if (!radarCtx) return;

            var hasData = !!(payload && payload.has_data);
            setThreatRadarEmpty(hasData);

            if (threatRadarChart) {
                threatRadarChart.destroy();
                charts = charts.filter(function (c) { return c !== threatRadarChart; });
                threatRadarChart = null;
            }
            if (!hasData) return;

            var scaleMax = payload.scale_max || 5;
            var keys = payload.keys || [];
            threatRadarChart = track(new Chart(radarCtx, {
                type: 'radar',
                data: {
                    labels: payload.labels || [],
                    datasets: [{
                        label: 'Open findings',
                        data: payload.values || [],
                        fill: true,
                        backgroundColor: 'rgba(88, 166, 255, 0.22)',
                        borderColor: chartColors.primary,
                        borderWidth: 2,
                        pointBackgroundColor: chartColors.primary,
                        pointBorderColor: '#fff',
                        pointHoverBackgroundColor: '#fff',
                        pointHoverBorderColor: chartColors.primary,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 400 },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: function (ctx) {
                                    return (ctx.label || '') + ': ' + (ctx.parsed.r || 0);
                                }
                            }
                        }
                    },
                    scales: {
                        r: {
                            min: 0,
                            suggestedMax: scaleMax,
                            angleLines: { color: 'rgba(88, 166, 255, 0.2)' },
                            grid: { color: 'rgba(48, 54, 61, 0.9)' },
                            pointLabels: {
                                color: '#e6edf3',
                                font: { size: 11 },
                                padding: 10
                            },
                            ticks: {
                                display: true,
                                color: '#6e7681',
                                backdropColor: 'transparent',
                                stepSize: Math.max(1, Math.ceil(scaleMax / 4))
                            }
                        }
                    },
                    onClick: function (e, elements) {
                        if (elements.length > 0 && keys[elements[0].index]) {
                            window.location.href = findingsHrefForThreat(keys[elements[0].index]);
                        }
                    }
                }
            }));
        }

        safeRun('category', function () {
            renderCategoryChart(parseJsonScript('category-data', { has_data: false }));
        });
        safeRun('severity', function () {
            renderSeverityChart(parseJsonScript('severity-data', { has_data: false }));
        });
        safeRun('scan', function () {
            renderScanChart(parseJsonScript('scan-data', { has_data: false }));
        });
        safeRun('timeline', function () {
            renderTimelineChart(parseJsonScript('timeline-data', {
                labels: [],
                critical_high: [],
                medium_low: [],
                has_data: false
            }));
        });
        safeRun('threat-radar', function () {
            renderThreatRadarChart(parseJsonScript('threat-radar-data', { has_data: false }));
        });

        document.querySelectorAll('.timeline-range-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                window.updateTimeline(btn.getAttribute('data-range') || '7d');
            });
        });

        window.updateTimeline = function (range) {
            var daysMap = { '7d': 7, '30d': 30, '90d': 90 };
            var days = daysMap[range] || 7;
            var titleEl = document.getElementById('timeline-panel-title');
            if (titleEl) titleEl.textContent = 'Findings Timeline (' + days + ' Days)';

            document.querySelectorAll('.timeline-range-btn').forEach(function (btn) {
                btn.classList.toggle('timeline-range-btn--active', btn.getAttribute('data-range') === range);
            });

            var timelineUrl = config.timelineUrl;
            if (!timelineUrl) return;

            var qs = 'days=' + days;
            if (config.projectId) {
                qs += '&project=' + encodeURIComponent(String(config.projectId));
            }
            fetch(timelineUrl + '?' + qs, { headers: { Accept: 'application/json' } })
                .then(function (res) { return res.json(); })
                .then(function (data) { renderTimelineChart(data); })
                .catch(function () { setTimelineEmpty({ has_data: false }); });
        };

        window.addEventListener('resize', resizeCharts);
        window.addEventListener('pageshow', function () {
            document.body.style.overflow = '';
            document.documentElement.style.overflow = '';
            resizeCharts();
        });

        if (typeof ResizeObserver !== 'undefined') {
            document.querySelectorAll('.chart-panel-body, .threat-radar-chart').forEach(function (el) {
                var ro = new ResizeObserver(function () { resizeCharts(); });
                ro.observe(el);
            });
        }

        setTimeout(resizeCharts, 100);
        setTimeout(resizeCharts, 500);
    });
})();
