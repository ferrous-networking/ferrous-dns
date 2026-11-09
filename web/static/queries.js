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
                    const [clientsRes, dohRes] = await Promise.all([
                        fetch(`${API_BASE}/clients?limit=1000`),
                        fetch(`${API_BASE}/doh-ids`)
                    ]);
                    const list = [];
                    if (clientsRes.ok) {
                        const clients = (await clientsRes.json()).data || [];
                        for (const c of clients) {
                            list.push(c);
                        }
                    }
                    if (dohRes.ok) {
                        const dohIds = await dohRes.json();
                        for (const d of dohIds) {
                            list.push({
                                ip_address: d.client_id,
                                hostname: d.name
                            });
                        }
                    }
                    list.sort((a, b) =>
                        this.clientLabel(a).localeCompare(this.clientLabel(b)));
                    this.clients = list;
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
                return name ? t("group \"{0}\"", {0: name}) : t("group #{0}", {0: groupId});
            },

            coalescedTip(query) {
                return query.coalesced === 'leader'
                    ? t("Coalesced: identical queries that arrived\nwhile this one was in flight shared its answer")
                    : t("Coalesced: shared the answer of an identical\nquery already in flight, with no upstream\nrequest of its own");
            },

            cookieTip(query) {
                if (query.cookie === 'valid') {
                    return t("DNS Cookie: a server cookie this server issued\nto the client, still in its rotation window");
                }
                if (query.cookie === 'client') {
                    return t("DNS Cookie: a client cookie only, from a first\nquery or a client that did not keep ours");
                }
                return t("DNS Cookie: a server cookie that is not ours:\nexpired by rotation or a restart, or forged");
            },

            escapeHtml(str) {
                const d = document.createElement('div');
                d.textContent = str;
                return d.innerHTML;
            },

            formatSource(query) {
                if (query.block_source === 'dns_tunneling') return t("DNS Tunneling");
                if (query.block_source === 'dns_rebinding') return t("DNS Rebinding");
                if (query.block_source === 'dga_detection') return t("DGA Detection");
                if (query.block_source === 'nxdomain_hijack') return t("NXDomain Hijack");
                if (query.block_source === 'response_ip_filter') return t("Response IP Filter");
                if (query.response_status === 'RATE_LIMITED') return t("Rate Limited");
                if (query.response_status === 'RATE_LIMITED_TC') return t("Rate Limited (TC)");
                if (query.cache_hit) return 'Cache';
                if (query.block_source === 'blocklist') return t("Blocklist");
                if (query.block_source === 'managed_domain') return t("Managed Domain");
                if (query.block_source === 'regex_filter') return t("Regex Filter");
                if (query.block_source === 'non_fqdn') return t("Non-FQDN");
                if (query.block_source === 'private_ptr') return t("Private PTR");
                if (query.block_source === 'dns_cookie') return t("DNS Cookie");
                if (query.block_source === 'cname_cloaking') return t("CNAME Cloaking");
                if (query.block_source === 'schedule') return t("Schedule");
                if (query.block_source === 'rate_limit') return t("Rate Limited");
                // Any other block, such as a source added later, still reads as one.
                if (query.blocked) return t("Blocked");
                if (query.response_status === 'LOCAL_DNS') return t("Local DNS");
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
                return t("Upstream");
            },

            formatTime(timestamp) {
                if (!timestamp) return '-';
                const utc = timestamp.endsWith('Z') ? timestamp : timestamp + 'Z';
                return new Date(utc).toLocaleTimeString(FerrousI18n.formatLocale());
            },

            formatResponseTime(query) {
                const us = query.response_time_us;
                if (us == null) return '-';
                if (us < 1000) return `${Math.round(us)} µs`;
                if (us < 1000000) return `${Math.round(us / 1000)} ms`;
                return `${FerrousI18n.decimal(us / 1000000, 2)} s`;
            },

            async handleDomainAction(query) {
                const domain = query.domain.replace(/\.$/, '');
                const isBlocked = query.blocked;
                const action = isBlocked ? 'allow' : 'deny';
                // Stored with the rule, so it stays English like other saved data.
                const label = isBlocked ? 'Allow' : 'Block';
                // The rule goes where the query was decided: a rule in any other
                // group would not apply to this client. Rows logged before queries
                // carried a group fall back to the default group.
                const groupId = query.group_id ?? 1;
                const group = this.groupLabel(groupId);

                if (!isBlocked && !confirm(t("Block domain \"{0}\" for {1}?", {0: domain, 1: group}))) return;

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
                        alert(t("Domain \"{0}\" {1} for {2}.", {0: domain, 1: isBlocked ? t('allowed') : t('blocked'), 2: group}));
                    } else if (res.status === 409) {
                        alert(t("A rule for \"{0}\" already exists in {1}. Manage it in DNS Filter.", {0: domain, 1: group}));
                    } else {
                        console.error('Failed to create managed domain:', await res.text());
                        alert(t("Failed to create rule for \"{0}\".", {0: domain}));
                    }
                } catch (e) {
                    alert(t("Network error: {0}", {0: e.message}));
                }
            }
        };
    }
