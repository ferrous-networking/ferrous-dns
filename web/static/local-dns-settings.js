    function localDnsApp() {
        return {
            theme: localStorage.getItem('theme') || 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            stats: {queries_total: 0},
            records: [],
            newRecord: {hostname: '', domain: '', ip: '', record_type: 'A', ttl: 300},
            editingRecord: null,
            addError: '',
            _ctrl: {},
            _pollId: null,
            async init() {
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                await checkAuth();
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadRecords(), this.loadStats()]);
                this.startPolling();
                scheduleLucide(100);
                document.addEventListener('visibilitychange', () => {
                    if (document.hidden) this.stopPolling();
                    else this.startPolling();
                });
            },
            switchTab(tab) {
                this.activeTab = tab;
                this.$nextTick(() => scheduleLucide());
            },
            toggleTheme() {
                this.theme = this.theme === 'light' ? 'dark' : 'light';
                localStorage.setItem('theme', this.theme);
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                scheduleLucide();
            },
            startPolling() {
                this.stopPolling();
                this._pollId = setInterval(() => this.loadStats(), 5000);
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
                    if (r.ok) this.stats = await r.json();
                } catch (e) {
                    if (e.name !== 'AbortError') console.error(e);
                }
            },
            get form() {
                return this.editingRecord ?? this.newRecord;
            },
            // Mirrors the server-side validator so a malformed hostname is caught
            // before the round trip. Anything the browser cannot know — whether
            // dns.local_domain can anchor a bare `*` — is left to the API.
            validateRecord(record) {
                const hostname = (record.hostname || '').trim();
                const domain = (record.domain || '').trim();
                const labels = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;

                if (!hostname || !record.ip) {
                    return 'Hostname and IP address are required.';
                }
                if (hostname.includes('*') && hostname !== '*' && !hostname.startsWith('*.')) {
                    return "Wildcard must be the leftmost label: use '*' or '*.sub'.";
                }
                if (hostname !== '*' && !labels.test(hostname.replace(/^\*\./, ''))) {
                    return 'Hostname may only contain letters, digits, hyphens and underscores.';
                }
                if (domain.includes('*')) {
                    return "Domain cannot contain a wildcard: put the '*' in the hostname.";
                }
                if (domain && !labels.test(domain)) {
                    return 'Domain may only contain letters, digits, hyphens and underscores.';
                }
                return '';
            },
            async errorText(response, fallback) {
                try {
                    const body = await response.json();
                    return body.error || fallback;
                } catch (e) {
                    return fallback;
                }
            },
            async loadRecords() {
                try {
                    const r = await fetch(`${API_BASE}/local-records`);
                    if (r.ok) this.records = await r.json();
                } catch (e) {
                    console.error(e);
                }
            },
            editRecord(record) {
                this.editingRecord = {
                    id: record.id,
                    hostname: record.hostname,
                    domain: record.domain ?? '',
                    ip: record.ip,
                    record_type: record.record_type,
                    ttl: record.ttl,
                };
                this.addError = '';
            },
            cancelEdit() {
                this.editingRecord = null;
                this.newRecord = {hostname: '', domain: '', ip: '', record_type: 'A', ttl: 300};
                this.addError = '';
            },
            async updateRecord() {
                this.addError = this.validateRecord(this.editingRecord);
                if (this.addError) return;
                try {
                    const r = await fetch(`${API_BASE}/local-records/${this.editingRecord.id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            hostname: this.editingRecord.hostname,
                            domain: (this.editingRecord.domain || '').trim() || null,
                            ip: this.editingRecord.ip,
                            record_type: this.editingRecord.record_type,
                            ttl: parseInt(this.editingRecord.ttl) || 300
                        })
                    });
                    if (r.ok) {
                        this.editingRecord = null;
                        await this.loadRecords();
                        this.$nextTick(() => scheduleLucide());
                    } else {
                        this.addError = await this.errorText(r, 'Failed to update record');
                    }
                } catch (e) {
                    console.error(e);
                    this.addError = 'Network error: ' + e.message;
                }
            },
            async addRecord() {
                this.addError = this.validateRecord(this.newRecord);
                if (this.addError) return;
                try {
                    const r = await fetch(`${API_BASE}/local-records`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            hostname: this.newRecord.hostname,
                            domain: (this.newRecord.domain || '').trim() || null,
                            ip: this.newRecord.ip,
                            record_type: this.newRecord.record_type,
                            ttl: parseInt(this.newRecord.ttl) || 300
                        })
                    });
                    if (r.ok) {
                        await this.loadRecords();
                        this.newRecord = {hostname: '', domain: '', ip: '', record_type: 'A', ttl: 300};
                        this.$nextTick(() => scheduleLucide());
                    } else {
                        this.addError = await this.errorText(r, 'Failed to add record');
                    }
                } catch (e) {
                    console.error(e);
                    this.addError = 'Network error: ' + e.message;
                }
            },
            async deleteRecord(id) {
                if (!confirm('Delete this DNS record?')) return;
                try {
                    const r = await fetch(`${API_BASE}/local-records/${id}`, {method: 'DELETE'});
                    if (r.ok) {
                        await this.loadRecords();
                        this.$nextTick(() => scheduleLucide());
                    } else {
                        alert('Failed to delete record');
                    }
                } catch (e) {
                    console.error(e);
                    alert('Network error: ' + e.message);
                }
            },
        }
    }
