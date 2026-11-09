    function randomUuidV4() {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
    }

    async function copyToClipboard(text) {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            await navigator.clipboard.writeText(text);
            return;
        }
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        document.body.removeChild(area);
    }

    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            dohIds: [],
            groups: [],
            allowUnregisteredIds: false,
            configWritable: true,
            policySaving: false,
            editingEntry: null,
            copiedId: null,
            copyTimer: null,
            form: {
                name: '',
                client_id: '',
                group_id: 1,
                comment: ''
            },
            error: '',

            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                await checkAuth();
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadGroups(), this.loadDohIds(), this.loadPolicy()]);
                await this.$nextTick();
                scheduleLucide(0);
            },

            async loadPolicy() {
                try {
                    const res = await apiFetch(`${API_BASE}/config`);
                    if (res.ok) {
                        const cfg = await res.json();
                        this.configWritable = cfg.writable !== false;
                        this.allowUnregisteredIds = Boolean(
                            cfg.server &&
                            cfg.server.encrypted_dns &&
                            cfg.server.encrypted_dns.doh_allow_unregistered_ids
                        );
                    }
                } catch (e) {
                    console.error('Failed to load DoH policy:', e);
                }
            },

            async toggleAllowUnregisteredIds() {
                if (!this.configWritable || this.policySaving) return;
                const next = !this.allowUnregisteredIds;
                this.policySaving = true;
                try {
                    const res = await apiFetch(`${API_BASE}/config`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            server: {
                                encrypted_dns: {
                                    doh_allow_unregistered_ids: next
                                }
                            }
                        })
                    });
                    if (res.ok) {
                        this.allowUnregisteredIds = next;
                    } else {
                        let message = t('Failed to update DoH policy');
                        try {
                            const data = await res.json();
                            if (data && data.error) message = data.error;
                        } catch (_) {}
                        alert(message);
                    }
                } catch (e) {
                    console.error('Error updating DoH policy:', e);
                    alert(t('Network error: {0}', {0: e.message}));
                } finally {
                    this.policySaving = false;
                }
            },

            defaultGroupId() {
                const def = this.groups.find(g => g.is_default);
                if (def) return def.id;
                return this.groups.length > 0 ? this.groups[0].id : 1;
            },

            async loadGroups() {
                try {
                    const res = await apiFetch(`${API_BASE}/groups`);
                    if (res.ok) {
                        this.groups = await res.json();
                        if (!this.editingEntry) {
                            this.form.group_id = this.defaultGroupId();
                        }
                    }
                } catch (e) {
                    console.error('Failed to load groups:', e);
                }
            },

            async loadDohIds() {
                try {
                    const res = await apiFetch(`${API_BASE}/doh-ids`);
                    if (res.ok) {
                        this.dohIds = await res.json();
                        await this.$nextTick();
                        scheduleLucide(0);
                    }
                } catch (e) {
                    console.error('Failed to load DoH IDs:', e);
                }
            },

            generateUuid() {
                this.form.client_id = randomUuidV4();
            },

            editEntry(entry) {
                this.editingEntry = entry;
                this.form = {
                    name: entry.name,
                    client_id: entry.client_id,
                    group_id: entry.group_id,
                    comment: entry.comment || ''
                };
                this.error = '';
                this.$nextTick(() => scheduleLucide());
            },

            cancelForm() {
                this.editingEntry = null;
                this.form = {
                    name: '',
                    client_id: '',
                    group_id: this.defaultGroupId(),
                    comment: ''
                };
                this.error = '';
            },

            async saveEntry() {
                try {
                    this.error = '';
                    const trimmedId = this.form.client_id.trim();
                    const payload = {
                        name: this.form.name.trim(),
                        client_id: trimmedId || null,
                        group_id: Number(this.form.group_id),
                        comment: this.form.comment.trim() || null
                    };

                    let res;
                    if (this.editingEntry) {
                        if (trimmedId && trimmedId !== this.editingEntry.client_id) {
                            const ok = confirm(
                                t('Changing the Client ID from "{0}" to "{1}" will cut off any device still configured with /dns-query/{0}.\n\nContinue?', {0: this.editingEntry.client_id, 1: trimmedId})
                            );
                            if (!ok) return;
                        }
                        res = await apiFetch(`${API_BASE}/doh-ids/${this.editingEntry.id}`, {
                            method: 'PUT',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    } else {
                        res = await apiFetch(`${API_BASE}/doh-ids`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    }

                    if (res.ok) {
                        await this.loadDohIds();
                        this.cancelForm();
                    } else {
                        let message = t('Failed to save DoH ID');
                        try {
                            const data = await res.json();
                            if (data && data.error) message = data.error;
                        } catch (_) {}
                        this.error = message;
                    }
                } catch (e) {
                    console.error('Error saving DoH ID:', e);
                    this.error = t('Network error: {0}', {0: e.message});
                }
            },

            async deleteEntry(entry) {
                if (!confirm(t('Are you sure you want to delete the DoH ID "{0}"?', {0: entry.name}))) {
                    return;
                }

                try {
                    const res = await apiFetch(`${API_BASE}/doh-ids/${entry.id}`, {
                        method: 'DELETE'
                    });

                    if (res.ok) {
                        if (this.editingEntry && this.editingEntry.id === entry.id) {
                            this.cancelForm();
                        }
                        await this.loadDohIds();
                    } else {
                        let message = t('Failed to delete DoH ID');
                        try {
                            const data = await res.json();
                            if (data && data.error) message = data.error;
                        } catch (_) {}
                        alert(message);
                    }
                } catch (e) {
                    console.error('Error deleting DoH ID:', e);
                    alert(t('Network error: {0}', {0: e.message}));
                }
            },

            async copyEndpoint(entry) {
                try {
                    await copyToClipboard(`/dns-query/${entry.client_id}`);
                    this.copiedId = entry.id;
                    clearTimeout(this.copyTimer);
                    this.copyTimer = setTimeout(() => {
                        if (this.copiedId === entry.id) this.copiedId = null;
                    }, 1500);
                } catch (e) {
                    console.error('Failed to copy DoH path:', e);
                }
            }
        };
    }
