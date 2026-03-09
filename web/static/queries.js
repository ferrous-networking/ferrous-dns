    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            queries: [],
            total: 0,
            pageSize: 25,
            currentPage: 1,
            category: '',
            searchDomain: '',
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
                await Promise.all([this.loadQueries(), this.loadStats()]);
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
                    const res = await fetch(
                        `${API_BASE}/queries?limit=${this.pageSize}&${pageParam}&period=24h${domainParam}`,
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

            get filteredQueries() {
                let filtered = this.queries;
                if (this.category === 'allowed') filtered = filtered.filter(q => !q.blocked);
                if (this.category === 'blocked') filtered = filtered.filter(q => q.blocked);
                if (this.category === 'cache') filtered = filtered.filter(q => q.cache_hit);
                if (this.category === 'upstream') filtered = filtered.filter(q => !q.cache_hit && !q.blocked);
                if (this.category === 'rate-limited') filtered = filtered.filter(q => q.response_status === 'RATE_LIMITED' || q.response_status === 'RATE_LIMITED_TC');
                return filtered;
            },

            get paginatedQueries() {
                return this.filteredQueries;
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

            escapeHtml(str) {
                const d = document.createElement('div');
                d.textContent = str;
                return d.innerHTML;
            },

            formatSource(query) {
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
