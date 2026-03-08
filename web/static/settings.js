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
            alert: {show: false, type: 'success', message: ''},
            // Security tab state
            authConfig: {enabled: false, session_ttl_hours: 24, remember_me_days: 30, login_rate_limit_attempts: 5, login_rate_limit_window_secs: 300},
            changePass: {current: '', newPassword: '', confirm: ''},
            users: [],
            showAddUser: false,
            newUser: {username: '', password: '', role: 'viewer', display_name: ''},
            apiTokens: [],
            showCreateToken: false,
            newTokenName: '',
            newTokenCustomKey: '',
            generatedToken: '',
            editingToken: null,
            editTokenName: '',
            editTokenCustomKey: '',
            activeSessions: [],
            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                await checkAuth();
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadConfig(), this.loadDnsSettings(), this.loadHealthStatus(), this.loadCacheStats(), this.loadStats(), this.loadSystemStatus(), this.loadAuthConfig(), this.loadUsers(), this.loadApiTokens(), this.loadActiveSessions()]);
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
                    const r = await apiFetch(`${API_BASE}/stats`, {signal: this._ctrl.stats.signal});
                    if (r.ok) this.stats = await r.json()
                } catch (e) {
                    if (e.name !== 'AbortError') console.error(e)
                }
            },
            async loadConfig() {
                try {
                    this.loading = true;
                    const res = await apiFetch(`${API_BASE}/config`);
                    if (res.ok) {
                        const data = await res.json();
                        this.config = {
                            ...this.config, ...data,
                            server: {
                                dns_port: data.server?.dns_port ?? 53,
                                web_port: data.server?.web_port ?? 8080,
                                bind_address: data.server?.bind_address ?? '0.0.0.0',
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
                        if (data.auth) {
                            this.authConfig = {
                                enabled: data.auth.enabled,
                                session_ttl_hours: data.auth.session_ttl_hours,
                                remember_me_days: data.auth.remember_me_days,
                                login_rate_limit_attempts: data.auth.login_rate_limit_attempts,
                                login_rate_limit_window_secs: data.auth.login_rate_limit_window_secs
                            };
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
                    const r = await apiFetch(`${API_BASE}/settings`);
                    if (r.ok) this.settings = await r.json()
                } catch (e) {
                    console.log('Using default DNS settings', e)
                }
            },
            async loadHealthStatus() {
                this._ctrl.health?.abort();
                this._ctrl.health = new AbortController();
                try {
                    const res = await apiFetch(`${API_BASE}/health/upstreams`, {signal: this._ctrl.health.signal});
                    if (res.ok) this.healthStatus = await res.json()
                } catch (e) {
                    if (e.name !== 'AbortError') console.error('Load health error:', e)
                }
            },
            async loadCacheStats() {
                try {
                    const res = await apiFetch(`${API_BASE}/cache/stats`);
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
                    const res = await apiFetch(`${API_BASE}/config`, {
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
                    const r = await apiFetch(`${API_BASE}/settings`, {
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
            async savePiholeCompat() {
                try {
                    const r = await apiFetch(`${API_BASE}/config`, {
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
                        apiFetch(`${API_BASE}/hostname`,               {signal: sig}),
                        apiFetch(`${API_BASE}/upstream/health/detail`, {signal: sig}),
                        apiFetch(`${API_BASE}/cache/metrics`,          {signal: sig}),
                        apiFetch(`${API_BASE}/system/info`,            {signal: sig}),
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
            // --- Security tab methods ---
            async loadAuthConfig() {
                // Auth config is now populated by loadConfig() to avoid duplicate fetch
            },
            async saveAuthConfig() {
                try {
                    const r = await apiFetch(`${API_BASE}/config`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({auth: {
                            enabled: this.authConfig.enabled,
                            session_ttl_hours: this.authConfig.session_ttl_hours,
                            remember_me_days: this.authConfig.remember_me_days,
                            login_rate_limit_attempts: this.authConfig.login_rate_limit_attempts,
                            login_rate_limit_window_secs: this.authConfig.login_rate_limit_window_secs
                        }})
                    });
                    if (r.ok) {
                        this.showAlert('success', 'Authentication settings saved');
                    } else {
                        const data = await r.json().catch(() => ({}));
                        this.showAlert('error', 'Failed: ' + (data.error || 'Unknown error'));
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            async changePassword() {
                if (!this.changePass.current || !this.changePass.newPassword || this.changePass.newPassword !== this.changePass.confirm) return;
                try {
                    const r = await apiFetch(`${API_BASE}/auth/password`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({current_password: this.changePass.current, new_password: this.changePass.newPassword})
                    });
                    if (r.ok || r.status === 204) {
                        this.changePass = {current: '', newPassword: '', confirm: ''};
                        this.showAlert('success', 'Password updated successfully');
                    } else {
                        const data = await r.json().catch(() => ({}));
                        this.showAlert('error', data.error || 'Failed to change password');
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            async loadUsers() {
                try {
                    const r = await apiFetch(`${API_BASE}/users`);
                    if (r.ok) this.users = await r.json();
                } catch (e) { console.error('Load users:', e); }
            },
            resetNewUser() {
                this.newUser = {username: '', password: '', role: 'viewer', display_name: ''};
            },
            async createUser() {
                if (!this.newUser.username || !this.newUser.password) return;
                try {
                    const r = await apiFetch(`${API_BASE}/users`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(this.newUser)
                    });
                    if (r.ok || r.status === 201) {
                        this.showAddUser = false;
                        this.resetNewUser();
                        await this.loadUsers();
                        this.showAlert('success', 'User created');
                        scheduleLucide(50);
                    } else {
                        const data = await r.json().catch(() => ({}));
                        this.showAlert('error', data.error || 'Failed to create user');
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            async deleteUser(id) {
                if (!confirm('Delete this user?')) return;
                try {
                    const r = await apiFetch(`${API_BASE}/users/${id}`, {method: 'DELETE'});
                    if (r.ok || r.status === 204) {
                        await this.loadUsers();
                        this.showAlert('success', 'User deleted');
                        scheduleLucide(50);
                    } else {
                        const data = await r.json().catch(() => ({}));
                        this.showAlert('error', data.error || 'Failed to delete user');
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            async loadApiTokens() {
                try {
                    const r = await apiFetch(`${API_BASE}/api-tokens`);
                    if (r.ok) this.apiTokens = await r.json();
                } catch (e) { console.error('Load API tokens:', e); }
            },
            async createApiToken() {
                if (!this.newTokenName.trim()) return;
                try {
                    const payload = {name: this.newTokenName.trim()};
                    if (this.newTokenCustomKey.trim()) {
                        payload.token = this.newTokenCustomKey.trim();
                    }
                    const r = await apiFetch(`${API_BASE}/api-tokens`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(payload)
                    });
                    if (r.ok || r.status === 201) {
                        const data = await r.json();
                        this.generatedToken = data.token;
                        this.showCreateToken = false;
                        this.newTokenName = '';
                        this.newTokenCustomKey = '';
                        await this.loadApiTokens();
                        scheduleLucide(50);
                    } else {
                        const data = await r.json().catch(() => ({}));
                        this.showAlert('error', data.error || 'Failed to create token');
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            startEditToken(token) {
                this.editingToken = token.id;
                this.editTokenName = token.name;
                this.editTokenCustomKey = '';
                scheduleLucide(50);
            },
            cancelEditToken() {
                this.editingToken = null;
                this.editTokenName = '';
                this.editTokenCustomKey = '';
            },
            async saveApiTokenEdit(id) {
                if (!this.editTokenName.trim()) return;
                try {
                    const payload = {name: this.editTokenName.trim()};
                    if (this.editTokenCustomKey.trim()) {
                        payload.token = this.editTokenCustomKey.trim();
                    }
                    const r = await apiFetch(`${API_BASE}/api-tokens/${id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(payload)
                    });
                    if (r.ok) {
                        this.editingToken = null;
                        this.editTokenName = '';
                        this.editTokenCustomKey = '';
                        await this.loadApiTokens();
                        this.showAlert('success', 'Token updated');
                        scheduleLucide(50);
                    } else {
                        const data = await r.json().catch(() => ({}));
                        this.showAlert('error', data.error || 'Failed to update token');
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            async revokeApiToken(id) {
                if (!confirm('Revoke this API token?')) return;
                try {
                    const r = await apiFetch(`${API_BASE}/api-tokens/${id}`, {method: 'DELETE'});
                    if (r.ok || r.status === 204) {
                        await this.loadApiTokens();
                        this.showAlert('success', 'Token revoked');
                        scheduleLucide(50);
                    } else {
                        const data = await r.json().catch(() => ({}));
                        this.showAlert('error', data.error || 'Failed to revoke token');
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            async loadActiveSessions() {
                try {
                    const r = await apiFetch(`${API_BASE}/auth/sessions`);
                    if (r.ok) this.activeSessions = await r.json();
                } catch (e) { console.error('Load sessions:', e); }
            },
            async revokeSession(id) {
                if (!confirm('Revoke this session?')) return;
                try {
                    const r = await apiFetch(`${API_BASE}/auth/sessions/${id}`, {method: 'DELETE'});
                    if (r.ok || r.status === 204) {
                        await this.loadActiveSessions();
                        this.showAlert('success', 'Session revoked');
                    } else {
                        const data = await r.json().catch(() => ({}));
                        this.showAlert('error', data.error || 'Failed to revoke session');
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            showAlert(type, msg) {
                this.alert = {show: true, type, message: msg};
                setTimeout(() => {
                    this.alert.show = false
                }, 5000)
            }
        }
    }
