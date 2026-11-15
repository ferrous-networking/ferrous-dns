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
            groups: [],
            autoRefresh: false,
            // Live feed: rows waiting to appear, oldest first; the latest page the
            // API returned; the pending step's timer and when the last row landed;
            // the smoothed arrival rate (rows a second), when the last poll came,
            // and the ms between rows until the next poll; how far up the rows are
            // drawn while they glide down, the glide's frame and its last frame time.
            _queue: [],
            _latest: [],
            _dripTimer: null,
            _lastDrip: 0,
            _rate: 0,
            _lastPoll: 0,
            _pace: 600,
            _shift: 0,
            _rowHeight: 41,
            _glideFrame: null,
            _glideAt: 0,
            _hasMore: false,
            stats: {allowed: 0, blocked: 0, cacheHits: 0, upstream: 0, queries_total: 0},
            serverStats: null,
            _ctrl: {},
            _pollId: null,
            _cursors: {},
            // One row-actions menu and one Why? popover serve the whole table,
            // each anchored to the ⋯ button it was opened from and hidden until
            // `placed`.
            menu: {open: false, query: null, section: null, button: null, top: 0, left: 0, placed: false},
            why: {open: false, query: null, button: null, top: 0, left: 0, placed: false, loading: false, error: '', result: null},
            allowDurations: [[900, '15 minutes'], [3600, '1 hour'], [86400, '1 day']],

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
                // The menu and the popover are fixed to the viewport, so they follow
                // their row through a scroll, and close once it leaves the screen.
                const menuEl = this.$refs.rowMenu;
                const whyEl = this.$refs.whyPopover;
                const followRow = (e) => {
                    if (e.target instanceof Node && (menuEl.contains(e.target) || whyEl.contains(e.target))) return;
                    this.followAnchor(menuEl, this.menu);
                    this.followAnchor(whyEl, this.why);
                };
                window.addEventListener('scroll', followRow, true);
                window.addEventListener('resize', followRow);
            },

            toggleTheme() {
                this.theme = this.theme === 'light' ? 'dark' : 'light';
                localStorage.setItem('theme', this.theme);
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                scheduleLucide();
            },

            // `live` is a Live update poll: rows already on screen glide to their
            // new place and the new ones fade in, instead of the page jumping.
            async loadQueries(live = false) {
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
                        const rows = result.data || result;
                        if (live && this.queries.length && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
                            this.showLiveRows(rows);
                        } else {
                            this.stopFeed();
                            this.queries = rows;
                        }
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
                        this.loadQueries(true);
                        this.loadStats();
                    }
                }, 1000);
            },

            // Live update as a feed that runs on its own clock: a poll only queues
            // the rows it brought, and the feed lets them in one at a time, oldest
            // first, each pushing the rows below it down a place. Its pace follows
            // the smoothed arrival rate, so a steady query rate comes out as an even
            // stream instead of a burst after each poll.
            showLiveRows(rows) {
                this._latest = rows;
                const known = new Set([...this.queries, ...this._queue].map(q => q.id));
                const incoming = rows.filter(q => !known.has(q.id)).reverse();
                const now = Date.now();
                if (this._lastPoll) {
                    const seconds = Math.max(0.25, (now - this._lastPoll) / 1000);
                    const measured = incoming.length / seconds;
                    this._rate = this._rate ? 0.7 * this._rate + 0.3 * measured : measured;
                }
                this._lastPoll = now;
                // Only a page's worth can still be on screen once it lands.
                this._queue = [...this._queue, ...incoming].slice(-rows.length);
                // The queue is a buffer of about 1.5 polls' worth of rows, so the
                // feed never runs dry between polls. The pace is set once a poll,
                // so the rows move at one speed until the next: the arrival rate,
                // a little slower while the buffer is short and faster while it is
                // long, 80 to 600 ms apart.
                const target = Math.max(1, this._rate * 1.5);
                const fill = Math.min(1.5, Math.max(0.75, this._queue.length / target));
                const perSecond = Math.max(this._rate * fill, this._queue.length / 3, 1);
                this._pace = Math.max(80, Math.min(600, 1000 / perSecond));
                this.scheduleDrip();
            },

            // One row per `_pace`.
            scheduleDrip() {
                if (this._dripTimer) return;
                if (!this._queue.length) {
                    // Caught up: settle on exactly the rows the API returned.
                    const shown = this.queries.map(q => q.id).join();
                    if (shown !== this._latest.map(q => q.id).join()) this.queries = this._latest;
                    return;
                }
                const wait = Math.max(0, this._pace - (Date.now() - this._lastDrip));
                this._dripTimer = setTimeout(() => {
                    this._dripTimer = null;
                    this._lastDrip = Date.now();
                    this.dropIn(this._queue.shift());
                    this.scheduleDrip();
                }, wait);
            },

            stopFeed() {
                clearTimeout(this._dripTimer);
                this._dripTimer = null;
                this._queue = [];
                this._rate = 0;
                this._lastPoll = 0;
                this._pace = 600;
                cancelAnimationFrame(this._glideFrame);
                this._glideFrame = null;
                this._shift = 0;
                const tbody = this.$refs.queryRows;
                if (!tbody) return;
                tbody.style.transform = '';
                for (const tr of tbody.querySelectorAll('tr[data-entering]')) {
                    delete tr.dataset.entering;
                    tr.style.opacity = '';
                }
            },

            // A new row goes on top and the whole body is drawn one row higher,
            // so nothing moves on screen and the new row sits, hidden, under the
            // header. Then the body glides down. Not $nextTick: Alpine runs it from
            // a setTimeout, so the browser could paint the rows in their new places
            // first; a microtask queued now runs right after Alpine's DOM update.
            dropIn(query) {
                const tbody = this.$refs.queryRows;
                this.queries = [query, ...this.queries].slice(0, this._latest.length);
                queueMicrotask(() => {
                    const tr = tbody.querySelector(`tr[data-id="${query.id}"]`);
                    if (!tr) return;
                    this._rowHeight = tr.offsetHeight;
                    this._shift -= tr.offsetHeight;
                    tbody.style.transform = `translateY(${this._shift}px)`;
                    tr.dataset.entering = '1';
                    tr.style.opacity = '0';
                    this.glide();
                });
            },

            // One frame loop moves the body down at a steady speed, a row per
            // `_pace`, faster only when it falls more than a row and a half behind.
            // A new row adds distance to the same motion instead of restarting it,
            // so the rows never stop between one and the next. A new row stays
            // invisible while any of it is under the header, and appears whole,
            // fading in with its glow (a class on the element, so no other row
            // re-renders), once its place below the header is clear.
            glide() {
                if (this._glideFrame) return;
                const tbody = this.$refs.queryRows;
                this._glideAt = performance.now();
                const frame = now => {
                    const speed = Math.max(this._rowHeight / this._pace, -this._shift / (this._pace * 1.5));
                    this._shift = Math.min(0, this._shift + speed * (now - this._glideAt));
                    this._glideAt = now;
                    tbody.style.transform = this._shift ? `translateY(${this._shift}px)` : '';
                    const first = tbody.querySelector('tr[data-id]');
                    for (const tr of tbody.querySelectorAll('tr[data-entering]')) {
                        if (tr.offsetTop - first.offsetTop + this._shift < 0) continue;
                        delete tr.dataset.entering;
                        tr.style.opacity = '';
                        tr.classList.add('row-fresh');
                        setTimeout(() => tr.classList.remove('row-fresh'), 1100);
                    }
                    this._glideFrame = this._shift ? requestAnimationFrame(frame) : null;
                };
                this._glideFrame = requestAnimationFrame(frame);
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
                        this.groups = await res.json();
                        this.groupNames = Object.fromEntries(this.groups.map(g => [g.id, g.name]));
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
                if (query.block_source === 'dns_tunneling') return 'DNS Tunneling';
                if (query.block_source === 'dns_rebinding') return 'DNS Rebinding';
                if (query.block_source === 'dga_detection') return 'DGA Detection';
                if (query.block_source === 'nxdomain_hijack') return 'NXDomain Hijack';
                if (query.block_source === 'response_ip_filter') return 'Response IP Filter';
                if (query.response_status === 'RATE_LIMITED') return 'Rate Limited';
                if (query.response_status === 'RATE_LIMITED_TC') return 'Rate Limited (TC)';
                if (query.cache_hit) return 'Cache';
                if (query.block_source === 'blocklist') return 'Blocklist';
                if (query.block_source === 'managed_domain') return 'Managed Domain';
                if (query.block_source === 'regex_filter') return 'Regex Filter';
                if (query.block_source === 'non_fqdn') return 'Non-FQDN';
                if (query.block_source === 'private_ptr') return 'Private PTR';
                if (query.block_source === 'dns_cookie') return 'DNS Cookie';
                if (query.block_source === 'cname_cloaking') return 'CNAME Cloaking';
                if (query.block_source === 'schedule') return 'Schedule';
                if (query.block_source === 'rate_limit') return 'Rate Limited';
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
                    return '<span style="color:var(--color-orange)">' + pool
                        + '</span><span style="color:var(--text-secondary)">:</span>' + safeHost;
                }
                return 'Upstream';
            },

            // The SOURCE badge's colour, in the same order as formatSource.
            sourceBadgeClass(query) {
                const src = query.block_source;
                if (query.cache_hit) return 'badge-purple';
                if (['dns_tunneling', 'dns_rebinding', 'nxdomain_hijack', 'response_ip_filter', 'dga_detection', 'rate_limit'].includes(src)
                    || this.isRateLimited(query)) return 'badge-warning';
                if (src === 'blocklist' || src === 'cname_cloaking') return 'badge-danger';
                if (src === 'managed_domain' || src === 'schedule') return 'badge-orange';
                if (src === 'regex_filter') return 'badge-indigo';
                if (this.isFilterRefused(query)) return 'badge-neutral';
                if (query.blocked) return 'badge-danger';
                if (query.response_status === 'LOCAL_DNS') return 'badge-success';
                return 'badge-info';
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
                const groupId = this.ruleGroupId(query);
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
                        showToast(`Domain "${domain}" ${isBlocked ? 'allowed' : 'blocked'} for ${group}.`);
                    } else if (res.status === 409) {
                        showToast(`A rule for "${domain}" already exists in ${group}. Manage it in DNS Filter.`, 'error');
                    } else {
                        console.error('Failed to create managed domain:', await res.text());
                        showToast(`Failed to create rule for "${domain}".`, 'error');
                    }
                } catch (e) {
                    showToast(`Network error: ${e.message}`, 'error');
                }
            },

            // The group a rule from this row goes in: where the query was decided,
            // since a rule in any other group would not apply to this client. Rows
            // logged before queries carried a group fall back to the default group.
            ruleGroupId(query) {
                return query.group_id ?? 1;
            },

            plainDomain(query) {
                return query.domain.replace(/\.$/, '');
            },

            // A managed allow cannot lift block_non_fqdn / block_private_ptr or a
            // strict DNS Cookie refusal.
            isFilterRefused(query) {
                return ['non_fqdn', 'private_ptr', 'dns_cookie'].includes(query.block_source);
            },

            isRateLimited(query) {
                return query.response_status === 'RATE_LIMITED' || query.response_status === 'RATE_LIMITED_TC';
            },

            async errorMessage(res, fallback) {
                try {
                    return (await res.json()).error || fallback;
                } catch (e) {
                    return fallback;
                }
            },

            postManagedDomain(rule) {
                return fetch(`${API_BASE}/managed-domains`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(rule)
                });
            },

            // --- Row actions menu ---

            // Every caller takes its $refs before the next render: they resolve
            // through the calling element's ancestors, and a row or popover item
            // that re-renders leaves them pointing nowhere.
            openMenu(query, button) {
                if (this.menu.open && this.menu.query === query) {
                    this.closeMenu();
                    return;
                }
                this.closeWhy();
                const el = this.$refs.rowMenu;
                this.menu = {open: true, query, section: null, button, top: 0, left: 0, placed: false};
                this.$nextTick(() => this.placeFloating(el, this.menu));
            },

            closeMenu() {
                this.menu.open = false;
            },

            toggleMenuSection(name) {
                const el = this.$refs.rowMenu;
                this.menu.section = this.menu.section === name ? null : name;
                this.$nextTick(() => this.placeFloating(el, this.menu));
            },

            // Below the ⋯ button and right-aligned with it, flipped above it when
            // it would run past the bottom of the viewport; the client box leaves
            // out the scrollbar. A button an auto-refresh re-rendered away leaves
            // the element where it is.
            placeFloating(el, state, framesLeft = 10) {
                if (!state.open || !state.button.isConnected) return;
                // x-show reveals the element a timer after `open` turns true, so
                // until then it has no size to place by.
                if (el.offsetWidth === 0) {
                    if (framesLeft > 0) requestAnimationFrame(() => this.placeFloating(el, state, framesLeft - 1));
                    return;
                }
                const anchor = state.button.getBoundingClientRect();
                const viewport = document.documentElement;
                const margin = 8;
                const width = el.offsetWidth;
                const height = el.offsetHeight;
                state.left = Math.max(margin, Math.min(anchor.right - width, viewport.clientWidth - width - margin));
                const below = anchor.bottom + 4;
                state.top = below + height > viewport.clientHeight - margin
                    ? Math.max(margin, anchor.top - height - 4)
                    : below;
                state.placed = true;
            },

            followAnchor(el, state) {
                if (!state.open) return;
                const anchor = state.button.isConnected ? state.button.getBoundingClientRect() : null;
                if (!anchor || anchor.bottom < 0 || anchor.top > document.documentElement.clientHeight) {
                    state.open = false;
                    return;
                }
                this.placeFloating(el, state);
            },

            // The row's name and each parent down to two labels.
            domainLevels(query) {
                const labels = this.plainDomain(query).split('.');
                const levels = [];
                for (let i = 0; i + 2 <= labels.length; i++) levels.push(labels.slice(i).join('.'));
                return levels;
            },

            // The Clients entry behind the row, when it has one: DoH IDs and
            // addresses never seen as a client cannot change group here.
            menuClient(query) {
                if (query.doh_client_id) return null;
                return this.clients.find(c => c.id != null && c.ip_address === query.client) || null;
            },

            clientGroupId(query) {
                return this.menuClient(query)?.group_id ?? 1;
            },

            filterByDomain(query) {
                this.closeMenu();
                this.searchDomain = this.plainDomain(query);
                this.currentPage = 1;
                this._cursors = {};
                this.loadQueries();
            },

            filterByClient(query) {
                this.closeMenu();
                const value = query.doh_client_id || query.client;
                if (!this.clients.some(c => c.ip_address === value)) {
                    this.clients.push({ip_address: value, hostname: query.client_hostname});
                }
                // After the option renders, or the select would show nothing.
                this.$nextTick(() => {
                    this.searchClient = value;
                    this.currentPage = 1;
                    this._cursors = {};
                    this.loadQueries();
                });
            },

            async copyDomain(query) {
                this.closeMenu();
                const domain = this.plainDomain(query);
                try {
                    await navigator.clipboard.writeText(domain);
                } catch (e) {
                    // navigator.clipboard needs a secure context, which plain HTTP
                    // on a LAN address is not.
                    const area = document.createElement('textarea');
                    area.value = domain;
                    document.body.appendChild(area);
                    area.select();
                    document.execCommand('copy');
                    area.remove();
                }
            },

            // A `*.x` rule leaves `x` itself alone, so a level takes both rules.
            async addSubtreeRules(query, level) {
                this.closeMenu();
                const isBlocked = query.blocked;
                const action = isBlocked ? 'allow' : 'deny';
                const label = isBlocked ? 'Allow' : 'Block';
                const groupId = this.ruleGroupId(query);
                const group = this.groupLabel(groupId);
                if (!confirm(`${label} "${level}" and all its subdomains for ${group}?`)) return;

                try {
                    for (const domain of [level, `*.${level}`]) {
                        const res = await this.postManagedDomain({
                            name: `qlog-${action}-${domain}`,
                            domain: domain,
                            action: action,
                            group_id: groupId,
                            comment: `Added from Query Log (${label} with subdomains)`,
                            enabled: true
                        });
                        // 409: that rule is already there, which is what we want.
                        if (!res.ok && res.status !== 409) {
                            showToast(await this.errorMessage(res, `Failed to create the rule for "${domain}".`), 'error');
                            return;
                        }
                    }
                    showToast(`"${level}" and its subdomains ${isBlocked ? 'allowed' : 'blocked'} for ${group}.`);
                } catch (e) {
                    showToast(`Network error: ${e.message}`, 'error');
                }
            },

            async allowFor(query, seconds, label) {
                this.closeMenu();
                const domain = this.plainDomain(query);
                const groupId = this.ruleGroupId(query);
                const group = this.groupLabel(groupId);
                try {
                    const res = await this.postManagedDomain({
                        name: `qlog-allow-for-${domain}`,
                        domain: domain,
                        action: 'allow',
                        group_id: groupId,
                        comment: `Added from Query Log (Allow for ${label})`,
                        enabled: true,
                        expires_in_secs: seconds
                    });
                    if (res.ok) {
                        const rule = await res.json();
                        showToast(`Domain "${domain}" allowed for ${group} until ${formatExpiry(rule.expires_at)}.`);
                    } else if (res.status === 409) {
                        showToast(`A temporary allow for "${domain}" already exists in ${group}. Manage it in DNS Filter.`, 'error');
                    } else {
                        showToast(await this.errorMessage(res, `Failed to allow "${domain}".`), 'error');
                    }
                } catch (e) {
                    showToast(`Network error: ${e.message}`, 'error');
                }
            },

            async removeFromCache(query) {
                this.closeMenu();
                const domain = this.plainDomain(query);
                const groupId = this.ruleGroupId(query);
                // The shared cache, and the group's own view when its pool routes
                // give it one.
                const views = groupId !== 1 ? [null, groupId] : [null];
                try {
                    let removed = false;
                    let refusal = '';
                    for (const view of views) {
                        const res = await fetch(
                            `${API_BASE}/cache/entries?domain=${encodeURIComponent(domain)}&type=${encodeURIComponent(query.type)}`
                            + (view != null ? `&group_id=${view}` : ''),
                            {method: 'DELETE'}
                        );
                        if (res.ok) removed = true;
                        else if (res.status === 400) refusal = await this.errorMessage(res, '');
                    }
                    if (removed) showToast(`${query.type} ${domain} removed from the cache.`);
                    else if (refusal) showToast(refusal, 'error');
                    else showToast(`${query.type} ${domain} is not in the cache.`, 'error');
                } catch (e) {
                    showToast(`Network error: ${e.message}`, 'error');
                }
            },

            async moveClient(query, group) {
                this.closeMenu();
                const client = this.menuClient(query);
                if (!client) return;
                const label = this.clientLabel(client);
                if (!confirm(`Move ${label} to group "${group.name}"? Its next queries follow that group's rules.`)) return;
                try {
                    const res = await fetch(`${API_BASE}/clients/${client.id}/group`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({group_id: group.id})
                    });
                    if (res.ok) {
                        client.group_id = group.id;
                        showToast(`${label} moved to group "${group.name}".`);
                    } else {
                        showToast(await this.errorMessage(res, `Failed to move ${label}.`), 'error');
                    }
                } catch (e) {
                    showToast(`Network error: ${e.message}`, 'error');
                }
            },

            // The rate limiter reads its whitelist once, at startup.
            async exemptFromRateLimit(query) {
                this.closeMenu();
                const ip = query.client;
                try {
                    const cfgRes = await fetch(`${API_BASE}/config`);
                    if (!cfgRes.ok) {
                        showToast(await this.errorMessage(cfgRes, 'Failed to load the configuration.'), 'error');
                        return;
                    }
                    const cfg = await cfgRes.json();
                    if (cfg.writable === false) {
                        showToast('The configuration file is read-only, so the rate-limit whitelist cannot change here.', 'error');
                        return;
                    }
                    const whitelist = cfg.dns.rate_limit.whitelist || [];
                    if (whitelist.includes(ip)) {
                        showToast(`${ip} is already on the rate-limit whitelist.`, 'error');
                        return;
                    }
                    if (!confirm(`Exempt ${ip} from rate limiting? It applies after a server restart.`)) return;
                    const res = await fetch(`${API_BASE}/config`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({dns: {rate_limit: {whitelist: [...whitelist, ip]}}})
                    });
                    if (res.ok) {
                        showRestartBanner();
                        showToast(`${ip} added to the rate-limit whitelist. Restart the server to apply it.`);
                    } else {
                        showToast(await this.errorMessage(res, 'Failed to update the rate-limit whitelist.'), 'error');
                    }
                } catch (e) {
                    showToast(`Network error: ${e.message}`, 'error');
                }
            },

            // --- Why? popover ---

            async openWhy(query) {
                const el = this.$refs.whyPopover;
                const button = this.menu.button;
                this.closeMenu();
                this.why = {open: true, query, button, top: 0, left: 0, placed: false, loading: true, error: '', result: null};
                this.$nextTick(() => this.placeFloating(el, this.why));
                await this.loadWhy(el);
            },

            closeWhy() {
                this.why.open = false;
            },

            async loadWhy(el) {
                const query = this.why.query;
                this.why.loading = true;
                this.why.error = '';
                try {
                    const res = await fetch(`${API_BASE}/block-filter/test`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({domain: this.plainDomain(query), group_id: this.ruleGroupId(query)})
                    });
                    if (res.ok) this.why.result = await res.json();
                    else this.why.error = await this.errorMessage(res, 'Failed to test the domain.');
                } catch (e) {
                    this.why.error = `Network error: ${e.message}`;
                } finally {
                    this.why.loading = false;
                    this.$nextTick(() => this.placeFloating(el, this.why));
                }
            },

            // Blocks decided at query time, which the filter test cannot see.
            runtimeBlockLabel(query) {
                if (!query.blocked) return '';
                if (['blocklist', 'managed_domain', 'regex_filter'].includes(query.block_source)) return '';
                return this.formatSource(query);
            },

            dnsFilterTestLink(query) {
                return `/dns-filter.html#test=${encodeURIComponent(this.plainDomain(query))}&group=${this.ruleGroupId(query)}`;
            },

            async removeManagedRule(match) {
                const el = this.$refs.whyPopover;
                const group = this.groupLabel(this.ruleGroupId(this.why.query));
                try {
                    const ruleRes = await fetch(`${API_BASE}/managed-domains/${match.source_id}`);
                    if (!ruleRes.ok) {
                        showToast(await this.errorMessage(ruleRes, 'Failed to load the rule.'), 'error');
                        return;
                    }
                    const rule = await ruleRes.json();
                    if (rule.service_id) {
                        showToast(`"${rule.domain}" is blocked by the ${rule.service_id} service. Unblock the service in Block Services.`, 'error');
                        return;
                    }
                    if (!confirm(`Remove the rule "${rule.name}" (${rule.domain}) from ${group}?`)) return;
                    const res = await fetch(`${API_BASE}/managed-domains/${rule.id}`, {method: 'DELETE'});
                    if (!res.ok) {
                        showToast(await this.errorMessage(res, 'Failed to remove the rule.'), 'error');
                        return;
                    }
                    await this.loadWhy(el);
                } catch (e) {
                    showToast(`Network error: ${e.message}`, 'error');
                }
            }
        };
    }
