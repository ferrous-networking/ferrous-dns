    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            stats: {total: 0, validated: 0, secure: 0, insecure: 0, bogus: 0, indeterminate: 0},
            queries: [],
            total: 0,
            pageSize: 25,
            currentPage: 1,
            statusFilter: 'any',
            autoRefresh: false,
            _hasMore: false,
            _ctrl: {},
            _pollId: null,
            _cursors: {},

            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                await checkAuth();
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadStats(), this.loadQueries()]);
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

            get coverage() {
                if (!this.stats.total) return '0.0';
                return (this.stats.validated / this.stats.total * 100).toFixed(1);
            },

            async loadStats() {
                this._ctrl.stats?.abort();
                this._ctrl.stats = new AbortController();
                try {
                    const res = await apiFetch(`${API_BASE}/dnssec/stats?period=24h`, {signal: this._ctrl.stats.signal});
                    if (res.ok) this.stats = await res.json();
                } catch (e) {
                    if (e.name !== 'AbortError') console.error('Failed to load DNSSEC stats:', e);
                }
            },

            async loadQueries() {
                this._ctrl.queries?.abort();
                this._ctrl.queries = new AbortController();
                try {
                    const cursor = this._cursors[this.currentPage];
                    const pageParam = cursor
                        ? `cursor=${cursor}`
                        : `offset=${(this.currentPage - 1) * this.pageSize}`;
                    const res = await apiFetch(
                        `${API_BASE}/queries?limit=${this.pageSize}&${pageParam}&period=24h&dnssec_status=${encodeURIComponent(this.statusFilter)}`,
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
                    }
                } catch (e) {
                    if (e.name !== 'AbortError') console.error('Error loading queries:', e);
                }
            },

            applyFilter() {
                this.currentPage = 1;
                this._cursors = {};
                this.loadQueries();
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

            statusClass(status) {
                return ({
                    Secure: 'secure',
                    Insecure: 'insecure',
                    Bogus: 'bogus',
                    Indeterminate: 'indeterminate'
                })[status] || 'indeterminate';
            },

            clientLabel(query) {
                return query.client_hostname
                    ? `${query.client_hostname} (${query.client})`
                    : query.client;
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
            }
        };
    }
