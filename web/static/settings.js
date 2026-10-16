    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            currentTab: 'systemstatus',
            loading: true,
            mfa: {
                totpEnabled: false,
                recoveryRemaining: 0,
                webauthnConfigured: false,
                passkeys: [],
                setup: null,
                confirmCode: '',
                recoveryCodes: [],
                disablePassword: '',
                msg: '',
                msgErr: false,
            },
            stats: {queries_total: 0},
            config: {
                dns: {
                    pools: [],
                    health_check: {enabled: true, interval_seconds: 30, timeout_ms: 2000, failure_threshold: 3},
                    dnssec_mode: 'permissive',
                    cache_enabled: true,
                    mdns_enabled: false,
                    cache_ttl: 3600,
                    cache_min_ttl: 0,
                    cache_max_ttl: 86400,
                    cache_max_entries: 10000,
                    cache_eviction_strategy: 'lfu',
                    cache_min_hit_rate: 0.3,
                    cache_refresh_threshold: 0.75,
                    cache_compaction_interval: 300,
                    cache_optimistic_refresh: true,
                    cache_adaptive_thresholds: true,
                    cache_access_window_secs: 7200,
                    rate_limit: {
                        enabled: false, queries_per_second: 1000, burst_size: 500,
                        ipv4_prefix_len: 24, ipv6_prefix_len: 48, whitelist: [],
                        nxdomain_per_second: 50, slip_ratio: 0, dry_run: false,
                        stale_entry_ttl_secs: 300, tcp_max_connections_per_ip: 30,
                        dot_max_connections_per_ip: 15, doq_max_connections_per_ip: 15
                    },
                    malware_detection_enabled: true,
                    rebinding_protection_enabled: true,
                    rebinding_allowlist: [],
                    tunneling_detection: {
                        enabled: true, action: 'block', max_fqdn_length: 120, max_label_length: 50,
                        block_null_queries: true, entropy_threshold: 3.8, query_rate_per_apex: 50,
                        unique_subdomain_threshold: 30, txt_proportion_threshold: 0.05,
                        nxdomain_ratio_threshold: 0.2, confidence_threshold: 0.7,
                        stale_entry_ttl_secs: 300, domain_whitelist: [], client_whitelist: []
                    },
                    dga_detection: {
                        enabled: true, action: 'block', hot_path_confidence_threshold: 0.4,
                        sld_entropy_threshold: 3.5, sld_max_length: 24, consonant_ratio_threshold: 0.75,
                        digit_ratio_threshold: 0.3, ngram_score_threshold: 0.6, dga_rate_per_client: 10,
                        confidence_threshold: 0.65, stale_entry_ttl_secs: 300,
                        domain_whitelist: [], client_whitelist: []
                    },
                    nxdomain_hijack: {
                        enabled: true, action: 'block', probe_interval_secs: 300,
                        probe_timeout_ms: 5000, probes_per_round: 3, hijack_ip_ttl_secs: 3600
                    },
                    response_ip_filter: {
                        enabled: false, action: 'block', ip_list_urls: [],
                        refresh_interval_secs: 86400, ip_ttl_secs: 604800
                    }
                }
            },
            // Malware Detection tab: its numeric settings and lists, rendered as rows. The
            // limits mirror `Config::validate` (crates/domain/src/config/malware_detection.rs
            // and the zero checks in root.rs) and must only flag what it rejects too.
            // `max` without `float` is a whole number from 1 to max; no `max`, at least 1.
            malwareTitles: {
                tunneling_detection: 'DNS Tunneling Detection',
                dga_detection: 'DGA Detection',
                rebinding: 'DNS Rebinding Protection',
                nxdomain_hijack: 'NXDomain Hijack Detection',
                response_ip_filter: 'Response IP Filtering',
            },
            malwareNumberRows: {
                tunneling_detection: [
                    {field: 'max_fqdn_length', label: 'Max FQDN Length', icon: 'ruler', unit: 'bytes', max: 253,
                        help: 'Phase 1, on every query: flags a name longer than this. Tunnels pack data into long names; ordinary names rarely pass 100 bytes.'},
                    {field: 'max_label_length', label: 'Max Label Length', icon: 'whole-word', unit: 'bytes', max: 63,
                        help: 'Phase 1: flags a name with any single label longer than this. Encoded payloads make long labels.'},
                    {field: 'entropy_threshold', label: 'Entropy Threshold', icon: 'sigma', unit: 'bits/char', float: true, max: 8, step: 0.1,
                        help: 'Phase 2: Shannon entropy of the subdomain above which it counts as encoded data. Random-looking labels score high, words low.'},
                    {field: 'query_rate_per_apex', label: 'Query Rate per Domain', icon: 'activity', unit: 'per min',
                        help: 'Phase 2: queries per minute from one client subnet to one domain above which the rate counts as suspicious.'},
                    {field: 'unique_subdomain_threshold', label: 'Unique Subdomains', icon: 'layers', unit: 'per min',
                        help: 'Phase 2: distinct subdomains per minute from one client subnet under one domain above which they count as suspicious. Each tunneled chunk is a new name.'},
                    {field: 'txt_proportion_threshold', label: 'TXT Proportion', icon: 'file-text', unit: '0–1', float: true, max: 1, step: 0.01,
                        help: 'Phase 2: share of a client\'s queries that ask for TXT records above which it counts as suspicious. 0.05 = 5%.'},
                    {field: 'nxdomain_ratio_threshold', label: 'NXDOMAIN Ratio', icon: 'circle-x', unit: '0–1', float: true, max: 1, step: 0.01,
                        help: 'Phase 2: share of NXDOMAIN answers for one client and domain above which it counts as suspicious. 0.2 = 20%.'},
                    {field: 'confidence_threshold', label: 'Confidence Threshold', icon: 'target', unit: '0–1', float: true, max: 1, step: 0.01,
                        help: 'Phase 2: combined score of the signals above at which the domain is flagged. Higher means fewer false positives, and fewer detections.'},
                    {field: 'stale_entry_ttl_secs', label: 'Stale Entry TTL', icon: 'hourglass', unit: 'seconds',
                        help: 'Idle per-client tracking entries are dropped from memory after this long.'},
                ],
                dga_detection: [
                    {field: 'hot_path_confidence_threshold', label: 'Instant Confidence Threshold', icon: 'zap', unit: '0–1', float: true, max: 1, step: 0.01,
                        help: 'Phase 1: weighted score the name signals below must reach to flag a name on the spot. 0.40 usually takes two signals at once, which keeps names that look odd in one way only, like CDN hosts, out.'},
                    {field: 'sld_entropy_threshold', label: 'Name Entropy', icon: 'sigma', unit: 'bits/char', float: true, max: 8, step: 0.1,
                        help: 'Shannon entropy of the second-level domain (example in example.com) above which it counts as random.'},
                    {field: 'sld_max_length', label: 'Max Name Length', icon: 'ruler', unit: 'characters', max: 63,
                        help: 'Second-level domains longer than this count as suspicious.'},
                    {field: 'consonant_ratio_threshold', label: 'Consonant Ratio', icon: 'case-sensitive', unit: '0–1', float: true, max: 1, step: 0.01,
                        help: 'Share of consonants among the letters above which a name counts as unpronounceable. 0.75 = 75%.'},
                    {field: 'digit_ratio_threshold', label: 'Digit Ratio', icon: 'binary', unit: '0–1', float: true, max: 1, step: 0.01,
                        help: 'Share of digits in the name above which it counts as suspicious. 0.3 = 30%.'},
                    {field: 'ngram_score_threshold', label: 'Letter-pair Score', icon: 'spell-check', unit: '0–1', float: true, max: 1, step: 0.01,
                        help: 'Phase 2: how far the name\'s letter pairs stray from English (0 = English-like, 1 = random) before it counts as suspicious.'},
                    {field: 'dga_rate_per_client', label: 'Suspicious Names per Client', icon: 'activity', unit: 'per min',
                        help: 'Phase 2: suspicious names per minute from one client above which the client counts as infected. DGA malware tries many names in a row.'},
                    {field: 'confidence_threshold', label: 'Confidence Threshold', icon: 'target', unit: '0–1', float: true, max: 1, step: 0.01,
                        help: 'Phase 2: combined score of all signals at which the domain is flagged.'},
                    {field: 'stale_entry_ttl_secs', label: 'Stale Entry TTL', icon: 'hourglass', unit: 'seconds',
                        help: 'Idle per-client tracking entries are dropped from memory after this long.'},
                ],
                nxdomain_hijack: [
                    {field: 'probe_interval_secs', label: 'Probe Interval', icon: 'timer', unit: 'seconds',
                        help: 'Time between probe rounds against each upstream.'},
                    {field: 'probe_timeout_ms', label: 'Probe Timeout', icon: 'clock', unit: 'milliseconds',
                        help: 'How long a probe waits for an upstream\'s answer.'},
                    {field: 'probes_per_round', label: 'Probes per Round', icon: 'hash', unit: 'probes', max: 255,
                        help: 'Random .invalid names sent to each upstream per round.'},
                    {field: 'hijack_ip_ttl_secs', label: 'Hijack IP TTL', icon: 'hourglass', unit: 'seconds',
                        help: 'A hijack IP the probes stop seeing is forgotten after this long.'},
                ],
                response_ip_filter: [
                    {field: 'refresh_interval_secs', label: 'Refresh Interval', icon: 'refresh-cw', unit: 'seconds',
                        help: 'Time between feed downloads.'},
                    {field: 'ip_ttl_secs', label: 'IP TTL', icon: 'hourglass', unit: 'seconds',
                        help: 'An IP no feed lists any more is dropped after this long. Keep it at or above the refresh interval, or IPs expire before the next download.'},
                ],
            },
            malwareListRows: {
                tunneling_detection: [
                    {field: 'domain_whitelist', kind: 'domain', label: 'Domain Whitelist', icon: 'list-checks', placeholder: 'cdn.example.com',
                        help: 'Exact domain names exempt from tunneling detection (no wildcards; subdomains are not included). For a one-off false positive, allowing the domain (allowlist, or Allow in the query log) works too and needs no restart.'},
                    {field: 'client_whitelist', kind: 'client', label: 'Client Whitelist', icon: 'network', placeholder: '10.0.0.50 or 192.168.10.0/24',
                        help: 'IPs or CIDRs of clients exempt from tunneling detection, such as a monitoring server.'},
                ],
                dga_detection: [
                    {field: 'domain_whitelist', kind: 'domain', label: 'Domain Whitelist', icon: 'list-checks', placeholder: 'xjk3-vendor-cloud.com',
                        help: 'Exact domain names exempt from DGA detection (no wildcards; subdomains are not included). For a one-off false positive, allowing the domain (allowlist, or Allow in the query log) works too and needs no restart.'},
                    {field: 'client_whitelist', kind: 'client', label: 'Client Whitelist', icon: 'network', placeholder: '10.0.0.50 or 192.168.10.0/24',
                        help: 'IPs or CIDRs of clients exempt from DGA detection.'},
                ],
                rebinding: [
                    {field: 'rebinding_allowlist', kind: 'domain', label: 'Rebinding Allowlist', icon: 'list-checks', placeholder: 'vpn.example.com',
                        help: 'Exact domain names allowed to resolve to a private address, such as split-horizon names for a VPN or a router admin page. Names under the local domain, answers from the local DNS server and internal pools are always exempt.'},
                ],
                response_ip_filter: [
                    {field: 'ip_list_urls', kind: 'url', label: 'Feed URLs', icon: 'rss', placeholder: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                        help: 'HTTP or HTTPS URLs of IP feeds: one IP per line, # comments allowed, up to 64 MiB each. At least one is needed while the filter is on.'},
                ],
            },
            settings: {
                never_forward_non_fqdn: false,
                never_forward_reverse_lookups: false,
                local_domain: '',
                local_dns_server: '',
                block_mode: 'null_ip',
                block_ttl: 60,
                sinkhole_ipv4: '',
                sinkhole_ipv6: '',
                dns64_enabled: false,
                nat64_prefix: '64:ff9b::/96'
            },
            cacheStats: {total_entries: 0, hit_rate: 0, total_hits: 0, total_misses: 0},
            healthStatus: {},
            systemStatus: {
                hostname: '',
            },
            upstreamHealth: [],
            expandedUpstreams: [],
            // Client groups a conditional pool can be routed for.
            clientGroups: [],
            clientGroupsLoaded: false,
            // Pool server fields show their format error once left, or all of them after a save attempt.
            serverTouched: {},
            showServerErrors: false,
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
            // TLS state
            webTls: { enabled: false, tls_cert_path: '', tls_key_path: '' },
            tlsStatus: { cert_exists: false, key_exists: false, cert_valid: false, cert_subject: '', cert_not_after: '' },
            tlsCertFile: null,
            tlsKeyFile: null,
            // Backup state
            backupImportResult: null,
            backupImportErrors: [],
            backupImporting: false,
            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                await checkAuth();
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadConfig(), this.loadDnsSettings(), this.loadHealthStatus(), this.loadCacheStats(), this.loadStats(), this.loadSystemStatus(), this.loadUsers(), this.loadApiTokens(), this.loadActiveSessions(), this.loadTlsStatus(), this.loadClientGroups()]);
                scheduleLucide(100);
                this.startPolling();
                this._onVisibility = () => {
                    if (document.hidden) this.stopPolling();
                    else this.startPolling();
                };
                document.addEventListener('visibilitychange', this._onVisibility);
            },
            destroy() {
                this.stopPolling();
                document.removeEventListener('visibilitychange', this._onVisibility);
                Object.values(this._ctrl).forEach(c => c?.abort());
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
                    if (this.restartRequired) this.refreshRestartRequired();
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
                    if (r.ok) this.stats = await r.json();
                } catch (e) {
                    if (e.name !== 'AbortError') console.error(e)
                }
            },
            // Lets the banner clear on its own once the server has restarted,
            // without reloading the form (which would drop unsaved edits).
            async refreshRestartRequired() {
                try {
                    const res = await apiFetch(`${API_BASE}/config`);
                    if (res.ok) this.restartRequired = !!(await res.json()).restart_required;
                } catch (e) {
                    // server unreachable (e.g. mid-restart): keep the banner until it answers
                }
            },
            async loadConfig() {
                try {
                    this.loading = true;
                    const res = await apiFetch(`${API_BASE}/config`);
                    if (res.ok) {
                        const data = await res.json();
                        this.restartRequired = !!data.restart_required;
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
                                cache_refresh_threshold: data.dns?.cache_refresh_threshold ?? 0.75,
                                cache_compaction_interval: data.dns?.cache_compaction_interval ?? 300,
                                cache_optimistic_refresh: data.dns?.cache_optimistic_refresh ?? true,
                                cache_adaptive_thresholds: data.dns?.cache_adaptive_thresholds ?? true,
                                cache_access_window_secs: data.dns?.cache_access_window_secs ?? 7200,
                                rate_limit: {
                                    ...this.config.dns.rate_limit,
                                    ...(data.dns?.rate_limit || {})
                                },
                                tunneling_detection: {
                                    ...this.config.dns.tunneling_detection,
                                    ...(data.dns?.tunneling_detection || {})
                                },
                                dga_detection: {
                                    ...this.config.dns.dga_detection,
                                    ...(data.dns?.dga_detection || {})
                                },
                                nxdomain_hijack: {
                                    ...this.config.dns.nxdomain_hijack,
                                    ...(data.dns?.nxdomain_hijack || {})
                                },
                                response_ip_filter: {
                                    ...this.config.dns.response_ip_filter,
                                    ...(data.dns?.response_ip_filter || {})
                                }
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
                        // Snapshot the loaded pools so a later save can tell whether the
                        // user actually changed them — if not, we omit `pools` from the
                        // payload and skip a needless upstream rebuild + DNS re-resolution.
                        this._savedPoolsJson = this.normalizedPools(this.config.dns.pools);
                        if (data.server?.web_tls) {
                            this.webTls = {
                                enabled: data.server.web_tls.enabled ?? false,
                                tls_cert_path: data.server.web_tls.tls_cert_path ?? '/data/cert.pem',
                                tls_key_path: data.server.web_tls.tls_key_path ?? '/data/key.pem',
                            };
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
            async loadClientGroups() {
                try {
                    const res = await apiFetch(`${API_BASE}/groups`);
                    if (res.ok) {
                        this.clientGroups = await res.json();
                        this.clientGroupsLoaded = true;
                    }
                } catch (e) {
                    console.error('Load client groups error:', e)
                }
            },
            getServerHealth(s) {
                return this.healthStatus[s] || 'Unknown'
            },
            addPool() {
                this.config.dns.pools.push({name: '', strategy: 'parallel', priority: 1, servers: [''], domains: [], groups: [], internal: false});
                scheduleLucide(50)
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
            normalizedPools(pools) {
                // Canonical JSON of just the fields the backend consumes, so pool
                // comparisons ignore key ordering and fields the form never edits.
                return JSON.stringify((pools || []).map(p => ({
                    name: p.name,
                    strategy: p.strategy,
                    priority: p.priority,
                    servers: (p.servers || []).map(s => s.trim()).filter(s => s.length > 0),
                    weight: p.weight ?? null,
                    ...this.poolRouting(p)
                })));
            },
            // The routing fields as saved: blank domains dropped, and groups and
            // the internal flag only on a pool that has domains, as the form shows them.
            poolRouting(p) {
                const domains = (p.domains || []).map(d => d.trim()).filter(d => d.length > 0);
                return {
                    domains,
                    groups: domains.length > 0 ? [...(p.groups || [])].sort((a, b) => a - b) : [],
                    internal: domains.length > 0 && !!p.internal
                };
            },
            hasDomains(pool) {
                return (pool.domains || []).some(d => d.trim().length > 0);
            },
            domainsText(pool) {
                return (pool.domains || []).join('\n');
            },
            setDomainsText(pool, text) {
                pool.domains = text.split('\n');
            },
            togglePoolGroup(pool, id) {
                const groups = pool.groups || [];
                pool.groups = groups.includes(id) ? groups.filter(g => g !== id) : [...groups, id];
            },
            // Every client group, then each id the pool still names that no longer
            // exists, so it shows checked and can be unchecked.
            poolGroupOptions(pool) {
                const known = new Set(this.clientGroups.map(g => g.id));
                const missing = (pool.groups || []).filter(id => !known.has(id)).map(id => ({
                    id,
                    name: this.clientGroupsLoaded ? `Group ${id} (deleted)` : `Group ${id}`,
                    missing: this.clientGroupsLoaded
                }));
                return [...this.clientGroups, ...missing];
            },
            // Mirrors check_pool_groups (crates/api/src/handlers/config/update.rs), message included.
            missingGroupError(pools) {
                if (!this.clientGroupsLoaded) return '';
                const known = new Set(this.clientGroups.map(g => g.id));
                const wanted = [...new Set(pools.flatMap(p => this.poolRouting(p).groups))].sort((a, b) => a - b);
                const id = wanted.find(g => !known.has(g));
                return id === undefined ? '' : `A pool is routed for client group ${id}, which does not exist`;
            },
            // Mirrors normalize_route_domain (crates/domain/src/config/upstream.rs):
            // only what the backend rejects too is flagged, with its message.
            routeDomainError(domain) {
                let d = domain.trim();
                if (d.startsWith('.')) d = d.slice(1);
                if (d.endsWith('.')) d = d.slice(0, -1);
                if (d.includes('*')) return 'a wildcard is not needed: a domain already covers every name under it';
                if (!/^[\x00-\x7F]*$/.test(d)) {
                    try {
                        d = new URL(`http://${d}/`).hostname;
                    } catch {
                        return 'not a valid domain name';
                    }
                }
                d = d.toLowerCase();
                if (!d) return 'Domain cannot be empty';
                if (d.length > 253) return 'Domain cannot exceed 253 characters';
                for (const label of d.split('.')) {
                    if (!label) return 'Domain cannot contain an empty label';
                    if (label.length > 63) return 'Domain label cannot exceed 63 characters';
                    if (!/^[A-Za-z0-9_-]+$/.test(label)) {
                        return 'Domain contains invalid characters (only alphanumeric, hyphens and underscores are allowed)';
                    }
                }
                return '';
            },
            // The domain as the resolver matches it, for spotting one claimed twice.
            routeDomainKey(domain) {
                let d = domain.trim().replace(/^\./, '').replace(/\.$/, '');
                if (!/^[\x00-\x7F]*$/.test(d)) {
                    try { d = new URL(`http://${d}/`).hostname; } catch { /* reported above */ }
                }
                return d.toLowerCase();
            },
            // Mirrors validate_pool_routes, messages included.
            firstRoutingError(pools) {
                if (pools.length > 0 && pools.every(p => this.poolRouting(p).domains.length > 0)) {
                    return 'At least one pool must have no domains, to answer every other query';
                }
                const claimed = new Map();
                for (const p of pools) {
                    const routing = this.poolRouting(p);
                    for (const domain of routing.domains) {
                        const reason = this.routeDomainError(domain);
                        if (reason) return `Pool '${p.name}': domain '${domain}': ${reason}`;
                    }
                    const scopes = routing.groups.length > 0 ? routing.groups : [null];
                    for (const domain of new Set(routing.domains.map(d => this.routeDomainKey(d)))) {
                        for (const scope of scopes) {
                            const key = `${domain}\u0000${scope}`;
                            const owner = claimed.get(key);
                            if (owner !== undefined && owner !== p.name) {
                                const clients = scope === null ? 'every client' : `client group ${scope}`;
                                return `Domain '${domain}' is routed to both pool '${owner}' and pool '${p.name}' for ${clients}`;
                            }
                            claimed.set(key, p.name);
                        }
                    }
                }
                return '';
            },
            // Mirrors DnsProtocol::from_str (crates/domain/src/value_objects/dns_protocol.rs),
            // messages included, so a mistyped upstream is explained before saving. It only
            // flags what the backend rejects too; the backend stays the authority on save.
            upstreamUrlError(value) {
                const s = (value || '').trim();
                if (!s) return '';
                const sep = s.indexOf('://');
                if (sep < 0) return this.bareUpstreamError(s);
                const scheme = s.slice(0, sep);
                const rest = s.slice(sep + 3);
                switch (scheme) {
                    case 'udp': case 'tcp': case 'tls': case 'doq': {
                        const error = this.hostPortError(rest);
                        return error === null ? this.missingPortHint(scheme, rest.replace(/\/+$/, '')) : error;
                    }
                    case 'https': case 'h3':
                        return this.urlAuthorityError(rest);
                    case 'quic': {
                        const written = rest.replace(/\/+$/, '');
                        const port = this.hostPortError(written) === null ? ':853' : '';
                        return `'quic://' is not a supported scheme — write DNS-over-QUIC as doq://${written}${port}`;
                    }
                    default:
                        return `unknown scheme '${scheme}://' — use udp://, tcp://, tls://, doq://, https:// or h3://`;
                }
            },
            // '' when `s` is HOST:PORT or [IPv6]:PORT, null when only the port is missing.
            hostPortError(s) {
                let host, port;
                if (s.startsWith('[')) {
                    const end = s.indexOf(']');
                    if (end < 0) return 'unterminated IPv6 literal';
                    const after = s.slice(end + 1);
                    if (!after) return null;
                    if (!after.startsWith(':')) return 'unexpected characters after IPv6 literal';
                    host = s.slice(1, end);
                    port = after.slice(1);
                } else {
                    const colon = s.lastIndexOf(':');
                    if (colon < 0) return null;
                    host = s.slice(0, colon);
                    port = s.slice(colon + 1);
                }
                if (!host) return 'missing host';
                return this.portError(port);
            },
            portError(port) {
                return /^\+?\d+$/.test(port) && Number(port) <= 65535
                    ? '' : `invalid port '${port}' — use a number from 0 to 65535`;
            },
            missingPortHint(scheme, written) {
                const [protocol, port] = scheme === 'tls' ? ['DNS-over-TLS', 853]
                    : scheme === 'doq' ? ['DNS-over-QUIC', 853] : ['plain DNS', 53];
                const prefix = scheme ? `${scheme}://` : '';
                return `missing port — ${protocol} usually uses ${port}, e.g. ${prefix}${written}:${port}`;
            },
            urlAuthorityError(rest) {
                const authority = rest.split(/[/?#]/)[0];
                let host = authority;
                let port = null;
                if (authority.startsWith('[')) {
                    // The backend also checks the literal is IPv6; that message comes from Rust.
                    const end = authority.indexOf(']');
                    if (end < 0) return 'unterminated IPv6 literal';
                    host = authority.slice(1, end);
                    const after = authority.slice(end + 1);
                    if (after && !after.startsWith(':')) return 'unexpected characters after IPv6 literal';
                    if (after) port = after.slice(1);
                } else if ((authority.match(/:/g) || []).length > 1) {
                    return `IPv6 addresses must be in brackets, e.g. [${authority}]`;
                } else if (authority.includes(':')) {
                    [host, port] = authority.split(':');
                }
                if (!host) return 'missing host';
                return port === null ? '' : this.portError(port);
            },
            // Only IP:PORT may omit the scheme. A bracketed IPv6 one is left to the backend.
            bareUpstreamError(s) {
                const octet = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
                const ipv4 = `${octet}(\\.${octet}){3}`;
                const ipv4WithPort = s.match(new RegExp(`^${ipv4}:(\\d+)$`));
                if (ipv4WithPort && Number(ipv4WithPort.at(-1)) <= 65535) return '';
                if (/^\[[^\]]*\]:\d+$/.test(s)) return '';
                if (new RegExp(`^${ipv4}$`).test(s)) return this.missingPortHint('', s);
                if (s.includes(':') && this.isIpv6(s)) return this.missingPortHint('', `[${s}]`);
                const hostLike = s.match(/^[A-Za-z0-9._-]+(:\d+)?$/);
                if (hostLike) return `add a scheme, e.g. udp://${s}${hostLike[1] ? '' : ':53'} — only IP:PORT may omit it`;
                return 'unrecognized server address — use a URL such as doq://dns.adguard-dns.com:853 or IP:PORT such as 8.8.8.8:53';
            },
            isIpv6(s) {
                try {
                    new URL(`http://[${s}]/`);
                    return true;
                } catch {
                    return false;
                }
            },
            touchServer(idx, sidx) {
                this.serverTouched[`${idx}:${sidx}`] = true;
            },
            serverFieldError(idx, sidx, value) {
                if (!this.showServerErrors && !this.serverTouched[`${idx}:${sidx}`]) return '';
                return this.upstreamUrlError(value);
            },
            firstInvalidServer(pools) {
                for (const p of pools) {
                    for (const s of p.servers) {
                        const hint = this.upstreamUrlError(s);
                        if (hint) return `Pool '${p.name}': Invalid server '${s}': ${hint}`;
                    }
                }
                return '';
            },
            // The object a Malware Detection row edits: the rebinding settings sit in `dns` itself.
            malwareTarget(section) {
                return section === 'rebinding' ? this.config.dns : this.config.dns[section];
            },
            malwareNumberError(section, row) {
                const value = this.malwareTarget(section)[row.field];
                if (value === '' || value === null || value === undefined) return 'Required';
                if (typeof value !== 'number' || Number.isNaN(value)) return 'Must be a number';
                if (row.float) {
                    return value > 0 && value <= row.max ? '' : `Must be greater than 0 and at most ${row.max}`;
                }
                if (!Number.isInteger(value)) return 'Must be a whole number';
                if (row.max !== undefined) {
                    return value >= 1 && value <= row.max ? '' : `Must be from 1 to ${row.max}`;
                }
                return value >= 1 ? '' : 'Must be at least 1';
            },
            // Mirrors validate_exact_domain, validate_ip_or_cidr and validate_url in
            // crates/domain/src/value_objects/validators.rs. Blank entries are dropped on save.
            malwareEntryError(kind, entry) {
                const value = (entry || '').trim();
                if (!value) return '';
                if (kind === 'domain') {
                    if (value.length > 253) return 'Domain cannot exceed 253 characters';
                    if (value.includes('*')) return 'Wildcards are not supported: entries match the exact name';
                    for (const label of value.split('.')) {
                        if (!label) return 'Domain cannot contain an empty label (no leading, trailing or double dots)';
                        if (label.length > 63) return 'Domain label cannot exceed 63 characters';
                        if (!/^[A-Za-z0-9_-]+$/.test(label)) {
                            return 'Domain contains invalid characters (only letters, digits, hyphens and underscores; use punycode for internationalized names)';
                        }
                    }
                    return '';
                }
                if (kind === 'client') {
                    const slash = value.indexOf('/');
                    const addr = slash === -1 ? value : value.slice(0, slash);
                    const prefix = slash === -1 ? null : value.slice(slash + 1);
                    const v4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(addr) && addr.split('.').every(o => Number(o) <= 255);
                    const v6 = !v4 && addr.includes(':') && /^[0-9A-Fa-f:.]+$/.test(addr);
                    if (!v4 && !v6) return 'Not an IP address or CIDR (e.g. 10.0.0.5 or 10.0.0.0/24)';
                    const max = v4 ? 32 : 128;
                    if (prefix !== null && !(/^\+?\d+$/.test(prefix) && Number(prefix) <= max)) {
                        return `CIDR prefix must be 0-${max}`;
                    }
                    return '';
                }
                if (value.length > 2048) return 'URL cannot exceed 2048 characters';
                if (!value.startsWith('http://') && !value.startsWith('https://')) {
                    return 'URL must start with http:// or https://';
                }
                return '';
            },
            responseIpFilterNeedsFeed() {
                const filter = this.config.dns.response_ip_filter;
                return filter.enabled && !filter.ip_list_urls.some(url => (url || '').trim());
            },
            // First Malware Detection setting the backend would reject, for the save alert.
            malwareSettingsError() {
                for (const [section, rows] of Object.entries(this.malwareNumberRows)) {
                    for (const row of rows) {
                        const error = this.malwareNumberError(section, row);
                        if (error) return `${this.malwareTitles[section]} › ${row.label}: ${error}`;
                    }
                }
                for (const [section, lists] of Object.entries(this.malwareListRows)) {
                    for (const list of lists) {
                        for (const entry of this.malwareTarget(section)[list.field]) {
                            const error = this.malwareEntryError(list.kind, entry);
                            if (error) return `${this.malwareTitles[section]} › ${list.label}: '${entry}': ${error}`;
                        }
                    }
                }
                if (this.responseIpFilterNeedsFeed()) {
                    return 'Response IP Filtering › Feed URLs: add at least one feed URL, or turn the filter off';
                }
                return '';
            },
            // Trims list entries and drops blank ones, which the "Add Entry" button leaves behind.
            cleanMalwareLists() {
                for (const [section, lists] of Object.entries(this.malwareListRows)) {
                    const target = this.malwareTarget(section);
                    for (const list of lists) {
                        target[list.field] = target[list.field].map(entry => (entry || '').trim()).filter(Boolean);
                    }
                }
            },
            async saveConfig() {
                // Strip blank server inputs and drop empty pools before saving — an empty
                // or malformed upstream would otherwise break the server on its next boot.
                const cleanedPools = (this.config.dns.pools || [])
                    .map(p => ({...p, servers: (p.servers || []).map(s => s.trim()).filter(s => s.length > 0), ...this.poolRouting(p)}))
                    .filter(p => p.servers.length > 0);
                if ((this.config.dns.pools || []).length > 0 && cleanedPools.length === 0) {
                    this.showAlert('error', 'Each pool needs at least one server. Add a server or remove the empty pool.');
                    return;
                }
                // Only send `pools` when they actually changed since load/last save —
                // including them makes the backend rebuild and re-resolve every upstream,
                // so an unrelated edit (cache, rate-limit) shouldn't pay for that.
                const poolsChanged = this.normalizedPools(cleanedPools) !== this._savedPoolsJson;
                // Pools that did not change were loaded from the running config, so only edits are checked.
                const invalidServer = poolsChanged ? this.firstInvalidServer(cleanedPools) : '';
                if (invalidServer) {
                    this.showServerErrors = true;
                    this.showAlert('error', 'Failed to save: ' + invalidServer);
                    return;
                }
                const routingError = poolsChanged
                    ? this.firstRoutingError(cleanedPools) || this.missingGroupError(cleanedPools)
                    : '';
                if (routingError) {
                    this.showAlert('error', 'Failed to save: ' + routingError);
                    return;
                }
                this.cleanMalwareLists();
                const malwareError = this.malwareSettingsError();
                if (malwareError) {
                    this.showAlert('error', 'Failed to save: ' + malwareError);
                    return;
                }
                const dnsPayload = {...this.config.dns};
                if (poolsChanged) {
                    dnsPayload.pools = cleanedPools;
                } else {
                    delete dnsPayload.pools;
                }
                try {
                    const res = await apiFetch(`${API_BASE}/config`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({dns: dnsPayload, blocking: this.config.blocking})
                    });
                    const data = await res.json();
                    if (res.ok && data.success !== false) {
                        // Reflect the cleaned pools back into the form and re-baseline
                        // the snapshot so the next unrelated save won't resend them.
                        this.config.dns.pools = cleanedPools;
                        this._savedPoolsJson = this.normalizedPools(cleanedPools);
                        this.serverTouched = {};
                        this.showServerErrors = false;
                        // Only upstream pools are hot-applied; honor the backend flag for everything else.
                        if (data.restart_required) this.restartRequired = true;
                        this.showAlert('success', data.message || 'Configuration saved.');
                        scheduleLucide(50);
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
                        if (data.restart_required) {
                            this.restartRequired = true;
                            this.showAlert('success', 'DNS settings saved. Restart the server to apply changes.');
                        } else {
                            this.showAlert('success', 'DNS settings saved.');
                        }
                        scheduleLucide(50);
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
                        if (data.restart_required) {
                            this.restartRequired = true;
                            this.showAlert('success', 'Pi-hole compatibility setting saved. Restart required.');
                        } else {
                            this.showAlert('success', 'Pi-hole compatibility setting saved.');
                        }
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
            mfaMsg(text, isErr) { this.mfa.msg = text; this.mfa.msgErr = !!isErr; },
            async loadMfa() {
                try {
                    const r = await apiFetch(`${API_BASE}/auth/2fa/status`);
                    if (r.ok) {
                        const d = await r.json();
                        this.mfa.totpEnabled = d.totp_enabled;
                        this.mfa.recoveryRemaining = d.recovery_codes_remaining;
                        this.mfa.webauthnConfigured = d.webauthn_configured;
                        this.mfa.passkeys = d.passkeys || [];
                        scheduleLucide(50);
                    }
                } catch (e) { console.error('Load MFA:', e); }
            },
            async startTotp() {
                this.mfaMsg('');
                try {
                    const r = await apiFetch(`${API_BASE}/auth/2fa/setup`, {method: 'POST'});
                    if (r.ok) {
                        this.mfa.setup = await r.json();
                        this.mfa.confirmCode = '';
                        scheduleLucide(50);
                    } else {
                        const d = await r.json().catch(() => ({}));
                        this.mfaMsg(d.error || 'Could not start setup', true);
                    }
                } catch (e) { this.mfaMsg('Error: ' + e.message, true); }
            },
            async confirmTotp() {
                if (!this.mfa.confirmCode) return;
                this.mfaMsg('');
                try {
                    const r = await apiFetch(`${API_BASE}/auth/2fa/confirm`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({code: this.mfa.confirmCode.trim()})
                    });
                    if (r.ok) {
                        const d = await r.json();
                        this.mfa.setup = null;
                        this.mfa.confirmCode = '';
                        this.mfa.recoveryCodes = d.recovery_codes || [];
                        await this.loadMfa();
                        this.mfaMsg('Authenticator enabled', false);
                    } else {
                        const d = await r.json().catch(() => ({}));
                        this.mfaMsg(d.error || 'Invalid code', true);
                    }
                } catch (e) { this.mfaMsg('Error: ' + e.message, true); }
            },
            async disableMfa() {
                if (!this.mfa.disablePassword) return;
                this.mfaMsg('');
                try {
                    const r = await apiFetch(`${API_BASE}/auth/2fa`, {
                        method: 'DELETE',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({password: this.mfa.disablePassword})
                    });
                    if (r.ok || r.status === 204) {
                        this.mfa.disablePassword = '';
                        await this.loadMfa();
                        this.mfaMsg('Two-factor authentication disabled', false);
                    } else {
                        const d = await r.json().catch(() => ({}));
                        this.mfaMsg(d.error || 'Failed to disable', true);
                    }
                } catch (e) { this.mfaMsg('Error: ' + e.message, true); }
            },
            async registerPasskey() {
                if (!webauthnSupported()) { this.mfaMsg('Passkeys not supported in this browser', true); return; }
                this.mfaMsg('');
                try {
                    const startRes = await apiFetch(`${API_BASE}/auth/webauthn/register/start`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({})
                    });
                    if (!startRes.ok) {
                        const d = await startRes.json().catch(() => ({}));
                        this.mfaMsg(d.error || 'Could not start registration', true);
                        return;
                    }
                    const start = await startRes.json();
                    const attestation = await webauthnCreate(start.challenge);
                    const finishRes = await apiFetch(`${API_BASE}/auth/webauthn/register/finish`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ceremony_token: start.ceremony_token, response: attestation})
                    });
                    if (finishRes.ok || finishRes.status === 204) {
                        await this.loadMfa();
                        this.mfaMsg('Passkey registered', false);
                    } else {
                        const d = await finishRes.json().catch(() => ({}));
                        this.mfaMsg(d.error || 'Registration failed', true);
                    }
                } catch (e) {
                    this.mfaMsg((e && e.name === 'NotAllowedError') ? 'Passkey prompt dismissed' : 'Error: ' + e.message, true);
                }
            },
            async deletePasskey(id) {
                try {
                    const r = await apiFetch(`${API_BASE}/auth/webauthn/${id}`, {method: 'DELETE'});
                    if (r.ok || r.status === 204) {
                        await this.loadMfa();
                        this.mfaMsg('Passkey removed', false);
                    } else {
                        const d = await r.json().catch(() => ({}));
                        this.mfaMsg(d.error || 'Failed to remove passkey', true);
                    }
                } catch (e) { this.mfaMsg('Error: ' + e.message, true); }
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
            // --- TLS methods ---
            async loadTlsStatus() {
                try {
                    const r = await apiFetch(`${API_BASE}/tls/status`);
                    if (r.ok) this.tlsStatus = await r.json();
                } catch (e) { console.error('Load TLS status:', e); }
            },
            async saveWebTlsConfig() {
                try {
                    const r = await apiFetch(`${API_BASE}/config`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({server: {web_tls: {
                            enabled: this.webTls.enabled,
                            tls_cert_path: this.webTls.tls_cert_path,
                            tls_key_path: this.webTls.tls_key_path
                        }}})
                    });
                    const data = await r.json();
                    if (r.ok && data.success !== false) {
                        this.showAlert('success', 'HTTPS settings saved');
                        if (data.restart_required) this.restartRequired = true;
                    } else {
                        this.showAlert('error', 'Failed: ' + (data.error || data.message || 'Unknown error'));
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            async uploadCerts() {
                const certInput = document.getElementById('tls-cert-input');
                const keyInput = document.getElementById('tls-key-input');
                if (!certInput?.files[0] || !keyInput?.files[0]) {
                    this.showAlert('error', 'Please select both certificate and key files');
                    return;
                }
                const fd = new FormData();
                fd.append('cert', certInput.files[0]);
                fd.append('key', keyInput.files[0]);
                try {
                    const r = await apiFetch(`${API_BASE}/tls/upload`, {method: 'POST', body: fd});
                    const data = await r.json();
                    if (data.success) {
                        this.showAlert('success', data.message);
                        await this.loadTlsStatus();
                        if (data.restart_required) this.restartRequired = true;
                        scheduleLucide(50);
                    } else {
                        this.showAlert('error', data.message || 'Upload failed');
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            async generateSelfSigned() {
                const force = this.tlsStatus.cert_exists ? '?force=true' : '';
                try {
                    const r = await apiFetch(`${API_BASE}/tls/generate${force}`, {method: 'POST'});
                    const data = await r.json();
                    if (data.success) {
                        this.showAlert('success', data.message);
                        await this.loadTlsStatus();
                        if (data.restart_required) this.restartRequired = true;
                        scheduleLucide(50);
                    } else {
                        this.showAlert('error', data.message || 'Generation failed');
                    }
                } catch (e) { this.showAlert('error', 'Error: ' + e.message); }
            },
            // --- Backup methods ---
            async exportConfig() {
                try {
                    const res = await apiFetch(`${API_BASE}/config/export`);
                    if (!res.ok) { this.showAlert('error', 'Export failed'); return; }
                    const blob = await res.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `ferrous-backup-${new Date().toISOString().slice(0, 10)}.bin`;
                    a.click();
                    URL.revokeObjectURL(url);
                    this.showAlert('success', 'Backup downloaded successfully');
                } catch (e) {
                    this.showAlert('error', 'Export failed: ' + e.message);
                }
            },
            async importConfig() {
                const input = document.getElementById('backup-import-input');
                if (!input?.files[0]) { this.showAlert('error', 'Please select a backup file'); return; }
                this.backupImporting = true;
                this.backupImportResult = null;
                this.backupImportErrors = [];
                const fd = new FormData();
                fd.append('file', input.files[0]);
                try {
                    const res = await apiFetch(`${API_BASE}/config/import`, { method: 'POST', body: fd });
                    if (res.status === 401) { window.location.href = '/login.html'; return; }
                    const data = await res.json().catch(() => ({}));
                    if (res.ok && data.success !== false) {
                        this.backupImportResult = data.summary;
                        this.backupImportErrors = data.errors || [];
                        this.showAlert('success', 'Import completed successfully');
                        scheduleLucide(50);
                    } else {
                        this.showAlert('error', data.error || data.message || `Import failed (HTTP ${res.status})`);
                    }
                } catch (e) {
                    this.showAlert('error', 'Import failed: ' + e.message);
                } finally {
                    this.backupImporting = false;
                }
            },
            showAlert(type, msg) {
                this.alert = {show: true, type, message: msg};
                setTimeout(() => {
                    this.alert.show = false
                }, 5000)
            }
        }
    }
