    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            entries: [],
            total: 0,
            recordsTotal: 0,
            pageSize: 25,
            currentPage: 1,
            searchDomain: '',
            sortField: 'cached_at',
            sortOrder: 'desc',
            autoRefresh: false,
            removing: null,
            stats: {queries_total: 0},
            _ctrl: {},
            _pollId: null,

            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                await checkAuth();
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadEntries(), this.loadStats()]);
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

            async loadEntries() {
                this._ctrl.entries?.abort();
                this._ctrl.entries = new AbortController();
                try {
                    const offset = (this.currentPage - 1) * this.pageSize;
                    const domainParam = this.searchDomain
                        ? `&domain=${encodeURIComponent(this.searchDomain)}`
                        : '';
                    const res = await apiFetch(
                        `${API_BASE}/cache/entries?limit=${this.pageSize}&offset=${offset}`
                        + `&sort=${this.sortField}&order=${this.sortOrder}${domainParam}`,
                        {signal: this._ctrl.entries.signal}
                    );
                    if (res.ok) {
                        const result = await res.json();
                        this.entries = result.data || [];
                        this.total = result.total ?? this.entries.length;
                        this.recordsTotal = result.records_total ?? this.total;
                    }
                } catch (e) {
                    if (e.name !== 'AbortError') console.error('Error loading cache entries:', e);
                }
            },

            async loadStats() {
                this._ctrl.stats?.abort();
                this._ctrl.stats = new AbortController();
                try {
                    const res = await fetch(`${API_BASE}/stats`, {signal: this._ctrl.stats.signal});
                    if (res.ok) {
                        const stats = await res.json();
                        this.stats.queries_total = stats.queries_total || 0;
                    }
                } catch (e) {
                    if (e.name !== 'AbortError') console.error('Failed to load stats:', e);
                }
            },

            get hasMore() {
                return this.currentPage * this.pageSize < this.total;
            },

            async changePage(delta) {
                const next = this.currentPage + delta;
                if (next < 1) return;
                if (delta > 0 && !this.hasMore) return;
                this.currentPage = next;
                await this.loadEntries();
            },

            // Clicking the active column flips the direction; a new column
            // starts on `desc`, which is the useful end for every field here.
            async sortBy(field) {
                if (this.sortField === field) {
                    this.sortOrder = this.sortOrder === 'desc' ? 'asc' : 'desc';
                } else {
                    this.sortField = field;
                    this.sortOrder = 'desc';
                }
                this.currentPage = 1;
                await this.loadEntries();
            },

            sortArrow(field) {
                if (this.sortField !== field) return '';
                return this.sortOrder === 'desc' ? ' ↓' : ' ↑';
            },

            startPolling() {
                this.stopPolling();
                this._pollId = setInterval(() => {
                    if (this.autoRefresh) {
                        this.loadEntries();
                        this.loadStats();
                    }
                }, 1000);
            },

            stopPolling() {
                clearInterval(this._pollId);
                this._pollId = null;
                stopRatePolling();
            },

            formatCachedAt(cachedAt) {
                if (!cachedAt) return '-';
                return new Date(cachedAt * 1000).toLocaleTimeString();
            },

            // Permanent entries never expire; stale ones already hit zero and
            // are flagged separately by the badge next to this value.
            formatTtl(entry) {
                if (entry.permanent) return '—';
                const secs = entry.remaining_ttl ?? 0;
                if (secs < 60) return `${secs}s`;
                if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
                return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
            },

            async removeEntry(entry) {
                const marker = entry.domain + '|' + entry.type;
                this.removing = marker;
                try {
                    const res = await apiFetch(
                        `${API_BASE}/cache/entries?domain=${encodeURIComponent(entry.domain)}`
                        + `&type=${encodeURIComponent(entry.type)}`,
                        {method: 'DELETE'}
                    );
                    if (res.ok || res.status === 404) {
                        await this.loadEntries();
                    } else {
                        console.error('Failed to remove cache entry:', await res.text());
                        alert(`Failed to remove "${entry.domain}" (${entry.type}).`);
                    }
                } catch (e) {
                    alert(`Network error: ${e.message}`);
                } finally {
                    this.removing = null;
                }
            }
        };
    }
