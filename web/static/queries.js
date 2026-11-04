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
            cookie: '',
            searchDomain: '',
            searchClient: '',
            clients: [],
            groupNames: {},
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
                await Promise.all([
                    this.loadQueries(), this.loadStats(), this.loadClients(), this.loadGroups()
                ]);
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
                    const cookieParam = this.cookie
                        ? `&cookie=${encodeURIComponent(this.cookie)}`
                        : '';
                    const res = await fetch(
                        `${API_BASE}/queries?limit=${this.pageSize}&${pageParam}&period=24h${domainParam}${clientParam}${categoryParam}${protocolParam}${cookieParam}`,
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
                        const clients = (await res.json()).data;
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

            async loadGroups() {
                try {
                    const res = await fetch(`${API_BASE}/groups`);
                    if (res.ok) {
                        this.groupNames = Object.fromEntries(
                            (await res.json()).map(g => [g.id, g.name]));
                    }
                } catch (e) {
                    console.error('Failed to load groups:', e);
                }
            },

            groupLabel(groupId) {
                const name = this.groupNames[groupId];
                return name ? `group "${name}"` : `group #${groupId}`;
            },

            coalescedTip(query) {
                return query.coalesced === 'leader'
                    ? 'Coalesced: identical queries that arrived\nwhile this one was in flight shared its answer'
                    : 'Coalesced: shared the answer of an identical\nquery already in flight, with no upstream\nrequest of its own';
            },

            cookieTip(query) {
                if (query.cookie === 'valid') {
                    return 'DNS Cookie: a server cookie this server issued\nto the client, still in its rotation window';
                }
                if (query.cookie === 'client') {
                    return 'DNS Cookie: a client cookie only, from a first\nquery or a client that did not keep ours';
                }
                return 'DNS Cookie: a server cookie that is not ours:\nexpired by rotation or a restart, or forged';
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
                if (query.block_source === 'nxdomain_hijack') return '<span class="badge-malware">NXDomain Hijack</span>';
                if (query.block_source === 'response_ip_filter') return '<span class="badge-malware">Response IP Filter</span>';
                if (query.response_status === 'RATE_LIMITED') return '<span class="badge-rate-limited">Rate Limited</span>';
                if (query.response_status === 'RATE_LIMITED_TC') return '<span class="badge-rate-limited">Rate Limited (TC)</span>';
                if (query.cache_hit) return 'Cache';
                if (query.block_source === 'blocklist') return 'Blocklist';
                if (query.block_source === 'managed_domain') return 'Managed Domain';
                if (query.block_source === 'regex_filter') return 'Regex Filter';
                if (query.block_source === 'non_fqdn') return 'Non-FQDN';
                if (query.block_source === 'private_ptr') return 'Private PTR';
                if (query.block_source === 'dns_cookie') return 'DNS Cookie';
                if (query.block_source === 'cname_cloaking') return 'CNAME Cloaking';
                if (query.block_source === 'schedule') return 'Schedule';
                if (query.block_source === 'rate_limit') return '<span class="badge-rate-limited">Rate Limited</span>';
                // Any other block, such as a source added later, still reads as one.
                if (query.blocked) return 'Blocked';
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
                // The rule goes where the query was decided: a rule in any other
                // group would not apply to this client. Rows logged before queries
                // carried a group fall back to the default group.
                const groupId = query.group_id ?? 1;
                const group = this.groupLabel(groupId);

                if (!isBlocked && !confirm(`Block domain "${domain}" for ${group}?`)) return;

                try {
                    const res = await fetch(`${API_BASE}/managed-domains`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            name: `qlog-${action}-${domain}`,
                            domain: domain,
                            action: action,
                            group_id: groupId,
                            comment: `Added from Query Log (${label})`,
                            enabled: true
                        })
                    });
                    if (res.ok) {
                        alert(`Domain "${domain}" ${isBlocked ? 'allowed' : 'blocked'} for ${group}.`);
                    } else if (res.status === 409) {
                        alert(`A rule for "${domain}" already exists in ${group}. Manage it in DNS Filter.`);
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
