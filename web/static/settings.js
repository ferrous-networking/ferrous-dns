    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            currentTab: 'systemstatus',
            loading: true,
            stats: {queries_total: 0},
            config: {
                dns: {
                    pools: [],
                    health_check: {enabled: true, interval_seconds: 30, timeout_ms: 2000, failure_threshold: 3},
                    dnssec_enabled: false,
                    cache_enabled: true,
                    cache_ttl: 3600,
                    cache_min_ttl: 0,
                    cache_max_ttl: 86400,
                    cache_max_entries: 10000,
                    cache_eviction_strategy: 'lfu',
                    cache_min_hit_rate: 0.3,
                    cache_refresh_threshold: 0.8,
                    cache_compaction_interval: 300,
                    cache_optimistic_refresh: true,
                    cache_adaptive_thresholds: true,
                    cache_access_window_secs: 7200
                }
            },
            settings: {
                never_forward_non_fqdn: false,
                never_forward_reverse_lookups: false,
                local_domain: '',
                local_dns_server: ''
            },
            cacheStats: {total_entries: 0, hit_rate: 0, total_hits: 0, total_misses: 0},
            healthStatus: {},
            systemStatus: {
                hostname: '',
            },
            upstreamHealth: [],
            expandedUpstreams: [],
            cacheMetrics: {
                total_entries: 0, hits: 0, misses: 0, evictions: 0,
                insertions: 0, optimistic_refreshes: 0,
                lazy_deletions: 0, compactions: 0, hit_rate: 0,
            },
            systemInfo: {
                kernel: '', load_avg_1m: 0, load_avg_5m: 0, load_avg_15m: 0,
                mem_total_kb: 0, mem_used_kb: 0, mem_available_kb: 0, mem_used_percent: 0,
            },
            restartRequired: false,
            apiRestartRequired: false,
            newApiKey: '',
            showApiKey: false,
            apiKeyJustGenerated: false,
            alert: {show: false, type: 'success', message: ''},
            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadConfig(), this.loadDnsSettings(), this.loadHealthStatus(), this.loadCacheStats(), this.loadStats(), this.loadSystemStatus()]);
                scheduleLucide(100);
                this.startPolling();
                document.addEventListener('visibilitychange', () => {
                    if (document.hidden) this.stopPolling();
                    else this.startPolling();
                });
            },
            toggleTheme() {
                this.theme = this.theme === 'light' ? 'dark' : 'light';
                localStorage.setItem('theme', this.theme);
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                scheduleLucide(50)
            },
            _ctrl: {},
            _pollId: null,
            startPolling() {
                this.stopPolling();
                this._pollId = setInterval(() => {
                    this.loadHealthStatus();
                    this.loadStats();
                    this.loadSystemStatus();
                }, 10000);
            },
            stopPolling() {
                clearInterval(this._pollId);
                this._pollId = null;
                stopRatePolling();
            },
            async loadStats() {
                this._ctrl.stats?.abort();
                this._ctrl.stats = new AbortController();
                try {
                    const r = await fetch(`${API_BASE}/stats`, {signal: this._ctrl.stats.signal});
                    if (r.ok) this.stats = await r.json()
                } catch (e) {
                    if (e.name !== 'AbortError') console.error(e)
                }
            },
            async loadConfig() {
                try {
                    this.loading = true;
                    const res = await fetch(`${API_BASE}/config`);
                    if (res.ok) {
                        const data = await res.json();
                        this.config = {
                            ...this.config, ...data,
                            server: {
                                dns_port: data.server?.dns_port ?? 53,
                                web_port: data.server?.web_port ?? 8080,
                                bind_address: data.server?.bind_address ?? '0.0.0.0',
                                api_key_enabled: data.server?.api_key_enabled ?? false,
                                pihole_compat: data.server?.pihole_compat ?? false,
                            },
                            dns: {
                                ...this.config.dns, ...(data.dns || {}),
                                pools: data.dns?.pools || [],
                                health_check: {
                                    enabled: data.dns?.health_check?.enabled ?? true,
                                    interval_seconds: data.dns?.health_check?.interval_seconds ?? 30,
                                    timeout_ms: data.dns?.health_check?.timeout_ms ?? 2000,
                                    failure_threshold: data.dns?.health_check?.failure_threshold ?? 3
                                },
                                cache_ttl: data.dns?.cache_ttl ?? 3600,
                                cache_min_ttl: data.dns?.cache_min_ttl ?? 0,
                                cache_max_ttl: data.dns?.cache_max_ttl ?? 86400,
                                cache_max_entries: data.dns?.cache_max_entries ?? 10000,
                                cache_eviction_strategy: data.dns?.cache_eviction_strategy ?? 'lfu',
                                cache_min_hit_rate: data.dns?.cache_min_hit_rate ?? 0.3,
                                cache_refresh_threshold: data.dns?.cache_refresh_threshold ?? 0.8,
                                cache_compaction_interval: data.dns?.cache_compaction_interval ?? 300,
                                cache_optimistic_refresh: data.dns?.cache_optimistic_refresh ?? true,
                                cache_adaptive_thresholds: data.dns?.cache_adaptive_thresholds ?? true,
                                cache_access_window_secs: data.dns?.cache_access_window_secs ?? 7200
                            }
                        };
                        if (this.config.dns.pools.length === 0 && data.dns?.upstream_servers?.length > 0) {
                            this.config.dns.pools = [{
                                name: 'default',
                                strategy: 'parallel',
                                priority: 1,
                                servers: [...data.dns.upstream_servers]
                            }]
                        }
                    } else {
                        this.showAlert('error', 'Failed to load configuration')
                    }
                } catch (e) {
                    console.error('Load config error:', e);
                    this.showAlert('error', 'Failed to load: ' + e.message)
                } finally {
                    this.loading = false
                }
            },
            async loadDnsSettings() {
                try {
                    const r = await fetch(`${API_BASE}/settings`);
                    if (r.ok) this.settings = await r.json()
                } catch (e) {
                    console.log('Using default DNS settings', e)
                }
            },
            async loadHealthStatus() {
                this._ctrl.health?.abort();
                this._ctrl.health = new AbortController();
                try {
                    const res = await fetch(`${API_BASE}/health/upstreams`, {signal: this._ctrl.health.signal});
                    if (res.ok) this.healthStatus = await res.json()
                } catch (e) {
                    if (e.name !== 'AbortError') console.error('Load health error:', e)
                }
            },
            async loadCacheStats() {
                try {
                    const res = await fetch(`${API_BASE}/cache/stats`);
                    if (res.ok) this.cacheStats = await res.json()
                } catch (e) {
                    console.error('Load cache stats error:', e)
                }
            },
            getServerHealth(s) {
                return this.healthStatus[s] || 'Unknown'
            },
            addPool() {
                this.config.dns.pools.push({name: '', strategy: 'parallel', priority: 1, servers: ['']});
                setTimeout(() => lucide.createIcons(), 50)
            },
            removePool(idx) {
                this.config.dns.pools.splice(idx, 1)
            },
            getFirstPoolStrategy() {
                return this.config.dns.pools[0]?.strategy || 'parallel'
            },
            setFirstPoolStrategy(s) {
                if (this.config.dns.pools.length > 0) {
                    this.config.dns.pools[0].strategy = s
                } else {
                    this.addPool();
                    this.config.dns.pools[0].strategy = s
                }
            },
            async saveConfig() {
                try {
                    const res = await fetch(`${API_BASE}/config`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({dns: this.config.dns, blocking: this.config.blocking})
                    });
                    const data = await res.json();
                    if (res.ok && data.success !== false) {
                        this.showAlert('success', 'Configuration saved successfully!')
                    } else {
                        this.showAlert('error', 'Failed to save: ' + (data.error || data.message || 'Unknown error'))
                    }
                } catch (e) {
                    this.showAlert('error', 'Failed to save: ' + e.message)
                }
            },
            async saveDnsSettings() {
                try {
                    const r = await fetch(`${API_BASE}/settings`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(this.settings)
                    });
                    const data = await r.json();
                    if (r.ok && data.success !== false) {
                        this.showAlert('success', 'DNS settings saved!');
                        if (data.message && data.message.includes('restart')) {
                            this.restartRequired = true
                        }
                    } else {
                        this.showAlert('error', 'Failed: ' + (data.error || data.message || 'Unknown error'))
                    }
                } catch (e) {
                    console.error(e);
                    this.showAlert('error', 'Error: ' + e.message)
                }
            },
            toggleLocalDomain() {
                if (this.settings.local_domain) {
                    this.settings.local_domain = '';
                    this.settings.local_dns_server = '';
                } else {
                    this.settings.local_domain = 'lan';
                }
            },
            async generateApiKey() {
                try {
                    const r = await fetch(`${API_BASE}/api-key/generate`, {method: 'POST'});
                    if (r.ok) {
                        const data = await r.json();
                        this.newApiKey = data.key;
                        this.showApiKey = true;
                        this.apiKeyJustGenerated = true;
                        scheduleLucide(50);
                    } else {
                        this.showAlert('error', 'Failed to generate key')
                    }
                } catch (e) {
                    this.showAlert('error', 'Error: ' + e.message)
                }
            },
            async saveApiKey() {
                if (!this.newApiKey.trim()) return;
                try {
                    const r = await fetch(`${API_BASE}/config`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({server: {api_key: this.newApiKey.trim()}})
                    });
                    const data = await r.json();
                    if (r.ok && data.success !== false) {
                        this.config.server.api_key_enabled = true;
                        this.apiRestartRequired = true;
                        this.apiKeyJustGenerated = false;
                        this.showAlert('success', 'API key saved. Restart the server to activate.');
                        scheduleLucide(50);
                    } else {
                        this.showAlert('error', 'Failed: ' + (data.error || data.message || 'Unknown error'))
                    }
                } catch (e) {
                    this.showAlert('error', 'Error: ' + e.message)
                }
            },
            async removeApiKey() {
                try {
                    const r = await fetch(`${API_BASE}/config`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({server: {clear_api_key: true}})
                    });
                    const data = await r.json();
                    if (r.ok && data.success !== false) {
                        this.config.server.api_key_enabled = false;
                        this.newApiKey = '';
                        this.apiRestartRequired = true;
                        this.showAlert('success', 'API key removed. Restart the server to apply.');
                        scheduleLucide(50);
                    } else {
                        this.showAlert('error', 'Failed: ' + (data.error || data.message || 'Unknown error'))
                    }
                } catch (e) {
                    this.showAlert('error', 'Error: ' + e.message)
                }
            },
            async savePiholeCompat() {
                try {
                    const r = await fetch(`${API_BASE}/config`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({server: {pihole_compat: this.config.server.pihole_compat}})
                    });
                    const data = await r.json();
                    if (r.ok && data.success !== false) {
                        this.apiRestartRequired = true;
                        this.showAlert('success', 'Pi-hole compatibility setting saved. Restart required.');
                        scheduleLucide(50);
                    } else {
                        this.showAlert('error', 'Failed: ' + (data.error || data.message || 'Unknown error'))
                    }
                } catch (e) {
                    this.showAlert('error', 'Error: ' + e.message)
                }
            },
            async loadSystemStatus() {
                this._ctrl.systemStatus?.abort();
                this._ctrl.systemStatus = new AbortController();
                const sig = this._ctrl.systemStatus.signal;
                try {
                    const [hostnameRes, upstreamRes, cacheRes, sysRes] = await Promise.all([
                        fetch(`${API_BASE}/hostname`,               {signal: sig}),
                        fetch(`${API_BASE}/upstream/health/detail`, {signal: sig}),
                        fetch(`${API_BASE}/cache/metrics`,          {signal: sig}),
                        fetch(`${API_BASE}/system/info`,            {signal: sig}),
                    ]);
                    if (hostnameRes.ok) this.systemStatus.hostname = (await hostnameRes.json()).hostname || '';
                    if (upstreamRes.ok) this.upstreamHealth = await upstreamRes.json();
                    if (cacheRes.ok)    this.cacheMetrics   = await cacheRes.json();
                    if (sysRes.ok)      this.systemInfo      = await sysRes.json();
                } catch (e) {
                    if (e.name !== 'AbortError') console.error('loadSystemStatus error:', e);
                }
            },
            formatUptime(seconds) {
                if (!seconds) return '0s';
                const total = Math.floor(seconds);
                const d = Math.floor(total / 86400);
                const h = Math.floor((total % 86400) / 3600);
                const m = Math.floor((total % 3600) / 60);
                const s = total % 60;
                if (d > 0) return `${d}d ${h}h ${m}m`;
                if (h > 0) return `${h}h ${String(m).padStart(2,'0')}m`;
                return `${m}m ${s}s`;
            },
            kbToGb(kb) {
                return (kb / 1048576).toFixed(1);
            },
            get groupedUpstreams() {
                const pools = new Map();
                for (const group of this.upstreamHealth) {
                    const key = group.pool_name || 'default';
                    if (!pools.has(key)) {
                        pools.set(key, { pool_name: key, strategy: group.strategy || 'Parallel', servers: [] });
                    }
                    pools.get(key).servers.push(group);
                }
                return Array.from(pools.values());
            },
            strategyStyle(strategy) {
                if (strategy === 'Parallel') return 'background:rgba(168,85,247,0.12);color:#A855F7';
                if (strategy === 'Failover') return 'background:rgba(59,130,246,0.12);color:#3B82F6';
                if (strategy === 'Balanced') return 'background:rgba(16,185,129,0.12);color:#10B981';
                return 'background:var(--bg-tertiary);color:var(--text-secondary)';
            },
            poolStatusColor(status) {
                if (status === 'Healthy')   return 'var(--color-success)';
                if (status === 'Unhealthy') return 'var(--color-error)';
                if (status === 'Partial')   return 'var(--color-warning)';
                return 'var(--text-tertiary)';
            },
            toggleUpstream(addr) {
                const idx = this.expandedUpstreams.indexOf(addr);
                if (idx >= 0) this.expandedUpstreams.splice(idx, 1);
                else this.expandedUpstreams.push(addr);
            },
            isUpstreamExpanded(addr) {
                return this.expandedUpstreams.includes(addr);
            },
            formatNumber(n) {
                return (n || 0).toLocaleString();
            },
            formatTime(ms) {
                if (!ms) return '0 ms';
                if (ms < 1) return `${Math.round(ms * 1000)} µs`;
                return `${ms.toFixed(1)} ms`;
            },
            showAlert(type, msg) {
                this.alert = {show: true, type, message: msg};
                setTimeout(() => {
                    this.alert.show = false
                }, 5000)
            }
        }
    }
