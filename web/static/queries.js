    /* Inbound transports, keyed by the `protocol` field of a query log row.
       Icons are the Lucide glyphs used by the Protocol Reference card in
       settings.html, inlined as SVG because Alpine re-renders these rows on
       every poll while Lucide only substitutes `<i data-lucide>` once. */
    const PROTOCOL_BADGES = {
        udp: {
            label: 'UDP', color: '#6B7280', bg: 'rgba(107,114,128,0.15)',
            icon: '<path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/><circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/><path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/>'
        },
        tcp: {
            label: 'TCP', color: '#6B7280', bg: 'rgba(107,114,128,0.15)',
            icon: '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>'
        },
        dot: {
            label: 'DoT', color: '#10B981', bg: 'rgba(16,185,129,0.12)',
            icon: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>'
        },
        doh: {
            label: 'DoH', color: '#3B82F6', bg: 'rgba(59,130,246,0.12)',
            icon: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>'
        },
        doq: {
            label: 'DoQ', color: '#A855F7', bg: 'rgba(168,85,247,0.12)',
            icon: '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>'
        }
    };

    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            queries: [],
            total: 0,
            pageSize: 25,
            currentPage: 1,
            category: '',
            protocol: '',
            searchDomain: '',
            searchClient: '',
            clients: [],
            autoRefresh: false,
            _hasMore: false,
            stats: {allowed: 0, blocked: 0, cacheHits: 0, upstream: 0, queries_total: 0},
            serverStats: null,
            _ctrl: {},
            _pollId: null,
            _cursors: {},

            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                await checkAuth();
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadQueries(), this.loadStats(), this.loadClients()]);
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
                scheduleLucide();
            },

            async loadQueries() {
                this._ctrl.queries?.abort();
                this._ctrl.queries = new AbortController();
                try {
                    const cursor = this._cursors[this.currentPage];
                    const pageParam = cursor
                        ? `cursor=${cursor}`
                        : `offset=${(this.currentPage - 1) * this.pageSize}`;
                    const domainParam = this.searchDomain
                        ? `&domain=${encodeURIComponent(this.searchDomain)}`
                        : '';
                    const clientParam = this.searchClient
                        ? `&client=${encodeURIComponent(this.searchClient)}`
                        : '';
                    const categoryParam = this.category
                        ? `&category=${encodeURIComponent(this.category)}`
                        : '';
                    const protocolParam = this.protocol
                        ? `&protocol=${encodeURIComponent(this.protocol)}`
                        : '';
                    const res = await fetch(
                        `${API_BASE}/queries?limit=${this.pageSize}&${pageParam}&period=24h${domainParam}${clientParam}${categoryParam}${protocolParam}`,
                        {signal: this._ctrl.queries.signal}
                    );
                    if (res.ok) {
                        const result = await res.json();
                        this.queries = result.data || result;
                        this.total = result.total ?? this.queries.length;
                        this._hasMore = result.next_cursor != null;
                        if (result.next_cursor != null) {
                            this._cursors[this.currentPage + 1] = result.next_cursor;
                        }
                        this.calculateStats();
                    }
                } catch (e) {
                    if (e.name !== 'AbortError') console.error('Error loading queries:', e);
                }
            },

            calculateStats() {
                if (this.serverStats) {
                    this.stats.blocked = this.serverStats.queries_blocked || 0;
                    this.stats.allowed = (this.serverStats.queries_total || 0) - this.stats.blocked;
                } else {
                    this.stats.allowed = this.queries.filter(q => !q.blocked).length;
                    this.stats.blocked = this.queries.filter(q => q.blocked).length;
                }
                this.stats.cacheHits = this.queries.filter(q => q.cache_hit).length;
                this.stats.upstream = this.queries.filter(q => !q.cache_hit && !q.blocked).length;
            },

            get paginatedQueries() {
                return this.queries;
            },

            get totalPages() {
                return Math.max(1, Math.ceil(this.total / this.pageSize));
            },

            async changePage(delta) {
                const next = this.currentPage + delta;
                if (next < 1) return;
                if (delta > 0 && !this._hasMore) return;
                this.currentPage = next;
                await this.loadQueries();
            },

            startPolling() {
                this.stopPolling();
                this._pollId = setInterval(() => {
                    if (this.autoRefresh) {
                        this.loadQueries();
                        this.loadStats();
                    }
                }, 1000);
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
                    const res = await fetch(`${API_BASE}/stats`, {signal: this._ctrl.stats.signal});
                    if (res.ok) {
                        this.serverStats = await res.json();
                        this.stats.queries_total = this.serverStats.queries_total || 0;
                        this.calculateStats();
                    }
                } catch (e) {
                    if (e.name !== 'AbortError') console.error('Failed to load stats:', e);
                }
            },

            async loadClients() {
                try {
                    const res = await fetch(`${API_BASE}/clients?limit=1000`);
                    if (res.ok) {
                        const clients = await res.json();
                        clients.sort((a, b) =>
                            this.clientLabel(a).localeCompare(this.clientLabel(b)));
                        this.clients = clients;
                    }
                } catch (e) {
                    console.error('Failed to load clients:', e);
                }
            },

            clientLabel(client) {
                return client.hostname
                    ? `${client.hostname} (${client.ip_address})`
                    : client.ip_address;
            },

            escapeHtml(str) {
                const d = document.createElement('div');
                d.textContent = str;
                return d.innerHTML;
            },

            formatSource(query) {
                if (query.block_source === 'dns_tunneling') return '<span class="badge-malware">DNS Tunneling</span>';
                if (query.block_source === 'dns_rebinding') return '<span class="badge-malware">DNS Rebinding</span>';
                if (query.block_source === 'dga_detection') return '<span class="badge-malware">DGA Detection</span>';
                if (query.response_status === 'RATE_LIMITED') return '<span class="badge-rate-limited">Rate Limited</span>';
                if (query.response_status === 'RATE_LIMITED_TC') return '<span class="badge-rate-limited">Rate Limited (TC)</span>';
                if (query.cache_hit) return 'Cache';
                if (query.block_source === 'blocklist') return 'Blocklist';
                if (query.block_source === 'managed_domain') return 'Managed Domain';
                if (query.block_source === 'regex_filter') return 'Regex Filter';
                if (query.block_source === 'rate_limit') return '<span class="badge-rate-limited">Rate Limited</span>';
                if (query.response_status === 'LOCAL_DNS') return 'Local DNS';
                if (query.upstream_pool && query.upstream_server) {
                    const host = query.upstream_server
                        .replace(/^[a-z0-9]+:\/\//, '')
                        .replace(/\/.*$/, '')
                        .replace(/:\d+$/, '');
                    const pool = this.escapeHtml(query.upstream_pool);
                    const safeHost = this.escapeHtml(host);
                    return '<span style="color:#F97316">' + pool
                        + '</span><span style="color:var(--text-secondary)">:</span>' + safeHost;
                }
                return 'Upstream';
            },

            formatTime(timestamp) {
                if (!timestamp) return '-';
                const utc = timestamp.endsWith('Z') ? timestamp : timestamp + 'Z';
                return new Date(utc).toLocaleTimeString();
            },

            /* Static markup built from PROTOCOL_BADGES — no query data is
               interpolated, so this is safe to render with `x-html`. */
            formatProtocol(query) {
                const badge = PROTOCOL_BADGES[query.protocol];
                if (!badge) return '<span style="color:var(--text-secondary)">—</span>';
                return `<span class="badge" style="background:${badge.bg};color:${badge.color}" title="${badge.label}">`
                    + '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"'
                    + ' fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"'
                    + ` stroke-linejoin="round" style="flex-shrink:0">${badge.icon}</svg>${badge.label}</span>`;
            },

            formatResponseTime(query) {
                const us = query.response_time_us;
                if (us == null) return '-';
                if (us < 1000) return `${Math.round(us)} µs`;
                if (us < 1000000) return `${Math.round(us / 1000)} ms`;
                return `${(us / 1000000).toFixed(2)} s`;
            },

            async handleDomainAction(query) {
                const domain = query.domain.replace(/\.$/, '');
                const isBlocked = query.blocked;
                const action = isBlocked ? 'allow' : 'deny';
                const label = isBlocked ? 'Allow' : 'Block';

                if (!isBlocked && !confirm(`Block domain "${domain}"?`)) return;

                try {
                    const res = await fetch(`${API_BASE}/managed-domains`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            name: `qlog-${action}-${domain}`,
                            domain: domain,
                            action: action,
                            group_id: 1,
                            comment: `Added from Query Log (${label})`,
                            enabled: true
                        })
                    });
                    if (res.ok) {
                        alert(`Domain "${domain}" ${isBlocked ? 'allowed' : 'blocked'} successfully.`);
                    } else if (res.status === 409) {
                        alert(`A rule for "${domain}" already exists. Manage it in DNS Filter.`);
                    } else {
                        console.error('Failed to create managed domain:', await res.text());
                        alert(`Failed to create rule for "${domain}".`);
                    }
                } catch (e) {
                    alert(`Network error: ${e.message}`);
                }
            }
        };
    }
