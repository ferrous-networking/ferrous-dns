    const appCharts = {
        timeline: null,
        queryTypes: null,
        cacheSource: null
    };

    function generateChartColors(count) {
        return Array.from({ length: count }, (_, i) => {
            const hue = Math.round((i / count) * 360 + 200) % 360;
            const lightness = [55, 45, 65][i % 3];
            const saturation = [75, 85, 65][i % 3];
            return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
        });
    }

    function formatSourceKey(key) {
        if (key.includes(':')) {
            const parts = key.split(':');
            const pool = parts[0].charAt(0).toUpperCase() + parts[0].slice(1);
            const server = parts.slice(1).join(':')
                .replace(/^[a-z0-9]+:\/\//, '')
                .replace(/\/.*$/, '')
                .replace(/:\d+$/, '');
            return pool + ': ' + server;
        }
        return key
            .replace(/^blocked_by_/, '')
            .replace(/_hits$/, '')
            .replace(/_/g, ' ')
            .split(' ')
            .map(w => w.charAt(0).toUpperCase() + w.slice(1))
            .join(' ');
    }

    function app() {
        return {
            theme: 'light',
            stats: {},
            queryRate: {queries: 0, rate: '0 q/s'},
            cacheMetrics: {},
            blockFilterStats: {total_blocked_domains: 0},
            sourceStats: {cache: 0, local_dns: 0, blocklist: 0, managed_domain: 0, regex_filter: 0},
            queryTypes: {},
            topBlockedDomains: [],
            topClients: [],
            chartsReady: false,
            pollingIntervals: {fast: null, slow: null},
            _ctrl: {},
            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                await checkAuth();

                await this.loadAllData();
                await this.$nextTick();

                setTimeout(() => {
                    this.initCharts();
                    this.chartsReady = true;
                    scheduleLucide(0);

                    this.loadDashboard(true);

                    startRatePolling(rate => { this.queryRate = rate; });
                    setTimeout(() => this.startPolling(), 100);
                }, 500);

                document.addEventListener('visibilitychange', () => {
                    if (document.hidden) this.stopPolling();
                    else this.startPolling();
                });
            },
            toggleTheme() {
                this.theme = this.theme === 'light' ? 'dark' : 'light';
                localStorage.setItem('theme', this.theme);
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                scheduleLucide()
            },
            async loadAllData() {
                await Promise.all([this.loadDashboard(true), this.loadBlockFilterStats()])
            },
            async loadDashboard(includeTimeline) {
                this._ctrl.dashboard?.abort();
                this._ctrl.dashboard = new AbortController();
                try {
                    const url = `${API_BASE}/dashboard?period=24h&include_timeline=${!!includeTimeline}`;
                    const res = await apiFetch(url, {signal: this._ctrl.dashboard.signal});
                    if (res.ok) {
                        const data = await res.json();
                        this.stats = data.stats;
                        this.cacheMetrics = {
                            total_hits: data.cache_stats.total_hits,
                            total_misses: data.cache_stats.total_misses,
                            total_refreshes: data.cache_stats.total_refreshes,
                            total_entries: data.cache_stats.total_entries,
                            hit_rate: data.cache_stats.hit_rate
                        };
                        if (this.stats.queries_by_type) {
                            this.queryTypes = {...this.stats.queries_by_type};
                        }
                        if (this.stats.source_stats) {
                            const raw = {...this.stats.source_stats};
                            const malware = (raw.dns_tunneling || 0) + (raw.dns_rebinding || 0) + (raw.nxdomain_hijack || 0) + (raw.response_ip_filter || 0);
                            delete raw.dns_tunneling;
                            delete raw.dns_rebinding;
                            delete raw.nxdomain_hijack;
                            delete raw.response_ip_filter;
                            if (malware > 0) raw.malware_detection = malware;
                            this.sourceStats = raw;
                        }
                        this.topBlockedDomains = data.top_blocked_domains || [];
                        this.topClients = data.top_clients || [];
                        if (data.timeline && this.chartsReady) {
                            this.updateTimelineFromData(data.timeline);
                        }
                        if (this.chartsReady) {
                            this.updateQueryTypesChart();
                            this.updateCacheSourceChart();
                        }
                    }
                } catch (e) {
                    if (e.name !== 'AbortError') console.error(e)
                }
            },
            updateTimelineFromData(timeline) {
                if (!this.chartsReady || !appCharts.timeline) return;

                const now = new Date();
                const timeLabels = [];
                const blockedCounts = [];
                const unblockedCounts = [];
                const rateLimitedCounts = [];

                const dataMap = new Map();
                timeline.buckets.forEach(b => {
                    const utcTime = new Date(b.timestamp.replace(' ', 'T') + 'Z');
                    utcTime.setUTCMinutes(Math.floor(utcTime.getUTCMinutes() / 15) * 15, 0, 0);
                    const timeKey = utcTime.getTime();
                    dataMap.set(timeKey, {
                        total: b.total,
                        blocked: b.blocked,
                        unblocked: b.unblocked,
                        rate_limited: b.rate_limited || 0
                    });
                });

                for (let i = 95; i >= 0; i--) {
                    const bucketTime = new Date(now.getTime() - (i * 15 * 60 * 1000));
                    bucketTime.setMinutes(Math.floor(bucketTime.getMinutes() / 15) * 15, 0, 0);
                    const timeKey = bucketTime.getTime();

                    const hour = bucketTime.getHours();
                    const minute = bucketTime.getMinutes();
                    timeLabels.push(minute === 0 ? `${hour}:00` : '');

                    const data = dataMap.get(timeKey) || {total: 0, blocked: 0, unblocked: 0, rate_limited: 0};
                    blockedCounts.push(data.blocked);
                    unblockedCounts.push(data.unblocked);
                    rateLimitedCounts.push(data.rate_limited);
                }

                if (appCharts.timeline && appCharts.timeline.data &&
                    appCharts.timeline.data.datasets[0] && appCharts.timeline.data.datasets[1]) {
                    appCharts.timeline.data.labels = timeLabels;
                    appCharts.timeline.data.datasets[0].data = blockedCounts;
                    appCharts.timeline.data.datasets[1].data = unblockedCounts;
                    if (appCharts.timeline.data.datasets[2]) {
                        appCharts.timeline.data.datasets[2].data = rateLimitedCounts;
                    }
                    appCharts.timeline.update('none');
                }
            },
            updateQueryTypesChart() {
                if (!this.chartsReady) {
                    return;
                }

                try {
                    const validTypes = {};
                    Object.entries(this.queryTypes).forEach(([key, value]) => {
                        if (key !== 'undefined' && key !== 'null' && value > 0) {
                            validTypes[key] = value;
                        }
                    });

                    const pctTooltip = {
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const val = context.parsed;
                                const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                                return ` ${context.label}: ${val.toLocaleString()} (${pct}%)`;
                            }
                        }
                    };
                    if (!appCharts.queryTypes && Object.keys(validTypes).length > 0) {

                        const ctx2 = document.getElementById('queryTypesChart');
                        if (ctx2) {
                            appCharts.queryTypes = new Chart(ctx2.getContext('2d'), {
                                type: 'doughnut',
                                data: {
                                    labels: Object.keys(validTypes),
                                    datasets: [{
                                        data: Object.values(validTypes),
                                        backgroundColor: generateChartColors(Object.keys(validTypes).length)
                                    }]
                                },
                                options: {
                                    responsive: true,
                                    maintainAspectRatio: true,
                                    aspectRatio: 2,
                                    plugins: {legend: {position: 'right'}, tooltip: pctTooltip}
                                }
                            });
                        }
                    } else if (appCharts.queryTypes && appCharts.queryTypes.data && appCharts.queryTypes.canvas && Object.keys(validTypes).length > 0) {

                        const newLabels = Object.keys(validTypes);
                        const newData   = Object.values(validTypes);
                        const curLabels = appCharts.queryTypes.data.labels;
                        const curData   = appCharts.queryTypes.data.datasets[0].data;
                        const labelsChanged = newLabels.length !== curLabels.length ||
                            newLabels.some((l, i) => l !== curLabels[i]);
                        const dataChanged = newData.length !== curData.length ||
                            newData.some((v, i) => v !== curData[i]);
                        if (labelsChanged || dataChanged) {
                            appCharts.queryTypes.data.labels = newLabels;
                            appCharts.queryTypes.data.datasets[0].data = newData;
                            appCharts.queryTypes.data.datasets[0].backgroundColor = generateChartColors(newLabels.length);
                            appCharts.queryTypes.update('none');
                        }
                    }
                } catch (e) {
                    console.error('Error updating query types chart:', e);
                }
            },
            updateCacheSourceChart() {
                if (!this.chartsReady) return;

                const pctTooltip = {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const val = context.parsed;
                            const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                            return ` ${context.label}: ${val.toLocaleString()} (${pct}%)`;
                        }
                    }
                };

                try {
                    const active = Object.entries(this.sourceStats)
                        .filter(([, v]) => v > 0)
                        .map(([key, value]) => ({ label: formatSourceKey(key), value }));

                    if (active.length === 0) return;

                    const labels = active.map(e => e.label);
                    const data   = active.map(e => e.value);
                    const colors = generateChartColors(active.length);

                    if (!appCharts.cacheSource) {
                        const ctx3 = document.getElementById('cacheSourceChart');
                        if (ctx3) {
                            appCharts.cacheSource = new Chart(ctx3.getContext('2d'), {
                                type: 'doughnut',
                                data: {
                                    labels,
                                    datasets: [{data, backgroundColor: colors}]
                                },
                                options: {
                                    responsive: true,
                                    maintainAspectRatio: true,
                                    aspectRatio: 2,
                                    plugins: {legend: {position: 'right'}, tooltip: pctTooltip}
                                }
                            });
                        }
                    } else if (appCharts.cacheSource.data && appCharts.cacheSource.canvas) {
                        const curLabels = appCharts.cacheSource.data.labels;
                        const curData   = appCharts.cacheSource.data.datasets[0].data;
                        const labelsChanged = labels.length !== curLabels.length ||
                            labels.some((l, i) => l !== curLabels[i]);
                        const dataChanged = data.length !== curData.length ||
                            data.some((v, i) => v !== curData[i]);
                        if (labelsChanged || dataChanged) {
                            appCharts.cacheSource.data.labels = labels;
                            appCharts.cacheSource.data.datasets[0].data = data;
                            appCharts.cacheSource.data.datasets[0].backgroundColor = colors;
                            appCharts.cacheSource.update('none');
                        }
                    }
                } catch (e) {
                    console.error('Error updating cache source chart:', e);
                }
            },
            async loadBlockFilterStats() {
                try {
                    const res = await apiFetch(`${API_BASE}/block-filter/stats`);
                    if (res.ok) this.blockFilterStats = await res.json()
                } catch (e) {
                    console.error(e)
                }
            },
            initCharts() {
                try {
                    if (appCharts.timeline) {
                        appCharts.timeline.destroy();
                        appCharts.timeline = null;
                    }
                    if (appCharts.queryTypes) {
                        appCharts.queryTypes.destroy();
                        appCharts.queryTypes = null;
                    }
                    if (appCharts.cacheSource) {
                        appCharts.cacheSource.destroy();
                        appCharts.cacheSource = null;
                    }

                    const ctx1 = document.getElementById('timelineChart');
                    if (ctx1) {
                        appCharts.timeline = new Chart(ctx1.getContext('2d'), {
                            type: 'line',
                            data: {
                                labels: Array.from({length: 96}, (_, i) => {
                                    const mins = (i * 15) % 60;
                                    return mins === 0 ? `${Math.floor(i / 4)}:00` : '';
                                }),
                                datasets: [{
                                    label: 'Blocked',
                                    data: Array(96).fill(0),
                                    borderColor: '#EF4444',
                                    backgroundColor: 'rgba(239,68,68,0.5)',
                                    fill: true,
                                    tension: 0.4,
                                    pointRadius: 1,
                                    pointHoverRadius: 3
                                }, {
                                    label: 'Unblocked',
                                    data: Array(96).fill(0),
                                    borderColor: '#3B82F6',
                                    backgroundColor: 'rgba(59,130,246,0.5)',
                                    fill: true,
                                    tension: 0.4,
                                    pointRadius: 1,
                                    pointHoverRadius: 3
                                }, {
                                    label: 'Rate Limited',
                                    data: Array(96).fill(0),
                                    borderColor: '#F59E0B',
                                    backgroundColor: 'rgba(245,158,11,0.5)',
                                    fill: true,
                                    tension: 0.4,
                                    pointRadius: 1,
                                    pointHoverRadius: 3
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: true,
                                aspectRatio: 3,
                                plugins: {
                                    legend: {position: 'top'},
                                    tooltip: {
                                        callbacks: {
                                            title: function (context) {
                                                const index = context[0].dataIndex;
                                                const minsAgo = (95 - index) * 15;
                                                const date = new Date(Date.now() - minsAgo * 60 * 1000);
                                                const h = String(date.getHours()).padStart(2, '0');
                                                const m = String(Math.floor(date.getMinutes() / 15) * 15).padStart(2, '0');
                                                return `${h}:${m}`;
                                            }
                                        }
                                    }
                                },
                                scales: {
                                    y: {
                                        beginAtZero: true,
                                        stacked: true  
                                    },
                                    x: {
                                        stacked: true,  
                                        ticks: {
                                            maxRotation: 0,
                                            autoSkip: false,  
                                            maxTicksLimit: 48  
                                        },
                                        grid: {
                                            display: true
                                        }
                                    }
                                }
                            }
                        });
                    }

                } catch (e) {
                    console.error('Chart error:', e)
                }
            },
            startPolling() {
                this.stopPolling();
                this.pollingIntervals.fast = setInterval(() => {
                    this.loadDashboard(false);
                }, 10000);
                this.pollingIntervals.slow = setInterval(() => {
                    this.loadDashboard(true);
                }, 60000);
            },
            stopPolling() {
                clearInterval(this.pollingIntervals.fast);
                clearInterval(this.pollingIntervals.slow);
                stopRatePolling();
            },
            formatTime(ms) {
                if (!ms) return '0 ms';
                if (ms < 1) return `${Math.round(ms * 1000)} µs`;
                return `${ms.toFixed(1)} ms`
            },
            formatNumber(n) {
                return (n || 0).toLocaleString();
            }
        }
    }
