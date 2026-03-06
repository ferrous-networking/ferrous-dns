    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            activeTab: 'blocklist',

            // --- BLOCKLIST ---
            sources: [],
            groups: [],
            loading: false,
            editingSource: null,
            form: {
                name: '',
                url: '',
                group_ids: [1],
                comment: '',
                enabled: true
            },
            formError: '',

            // --- ALLOWLIST ---
            wSources: [],
            wLoading: false,
            wEditingSource: null,
            wForm: {
                name: '',
                url: '',
                group_ids: [1],
                comment: '',
                enabled: true
            },
            wFormError: '',

            // --- MANAGED DOMAINS ---
            mSources: [],
            mLoading: false,
            mEditingDomain: null,
            mForm: {
                name: '',
                domain: '',
                action: 'deny',
                group_id: 1,
                comment: '',
                enabled: true
            },
            mFormError: '',

            // --- REGEX FILTERS ---
            rgFilters: [],
            rgLoading: false,
            rgEditingFilter: null,
            rgForm: {
                name: '',
                pattern: '',
                action: 'deny',
                group_id: 1,
                comment: '',
                enabled: true
            },
            rgFormError: '',

            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadSources(), this.loadWhitelistSources(), this.loadGroups(), this.loadManagedDomains(), this.loadRegexFilters()]);
                await this.$nextTick();
                scheduleLucide(0);
            },

            switchTab(tab) {
                this.activeTab = tab;
                this.$nextTick(() => scheduleLucide());
            },

            async loadSources() {
                this.loading = true;
                try {
                    const res = await fetch(`${API_BASE}/blocklist-sources`);
                    if (res.ok) {
                        this.sources = await res.json();
                        await this.$nextTick();
                        scheduleLucide(0);
                    }
                } catch (e) {
                    console.error('Failed to load blocklist sources:', e);
                } finally {
                    this.loading = false;
                }
            },

            async loadGroups() {
                try {
                    const res = await fetch(`${API_BASE}/groups`);
                    if (res.ok) {
                        this.groups = await res.json();
                    }
                } catch (e) {
                    console.error('Failed to load groups:', e);
                }
            },

            defaultGroupId() {
                const def = this.groups.find(g => g.is_default);
                return def ? def.id : (this.groups.length > 0 ? this.groups[0].id : 1);
            },

            groupName(gid) {
                const g = this.groups.find(g => g.id === gid);
                return g ? g.name : '?';
            },

            async toggleGroup(source, groupId, add) {
                const newIds = add
                    ? [...source.group_ids, groupId]
                    : source.group_ids.filter(id => id !== groupId);
                try {
                    const res = await fetch(`${API_BASE}/blocklist-sources/${source.id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({group_ids: newIds})
                    });
                    if (res.ok) {
                        source.group_ids = newIds;
                    } else {
                        const errorText = await res.text();
                        alert('Failed to update groups: ' + errorText);
                        await this.loadSources();
                    }
                } catch (e) {
                    console.error('Error updating groups:', e);
                    await this.loadSources();
                }
            },

            editSource(source) {
                this.editingSource = source;
                this.form = {
                    name: source.name,
                    url: source.url || '',
                    group_ids: [...(source.group_ids || [])],
                    comment: source.comment || '',
                    enabled: source.enabled
                };
                this.formError = '';
                this.$nextTick(() => scheduleLucide());
            },

            cancelForm() {
                this.editingSource = null;
                this.formError = '';
                this.form = {
                    name: '',
                    url: '',
                    group_ids: [this.defaultGroupId()],
                    comment: '',
                    enabled: true
                };
            },

            async saveSource() {
                this.formError = '';

                const payload = {
                    name: this.form.name.trim(),
                    url: this.form.url.trim() || null,
                    group_ids: this.form.group_ids,
                    comment: this.form.comment.trim() || null,
                    enabled: this.form.enabled
                };

                try {
                    let res;
                    if (this.editingSource) {
                        res = await fetch(`${API_BASE}/blocklist-sources/${this.editingSource.id}`, {
                            method: 'PUT',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    } else {
                        res = await fetch(`${API_BASE}/blocklist-sources`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    }

                    if (res.ok) {
                        await this.loadSources();
                        this.cancelForm(); 
                    } else {
                        const errorText = await res.text();
                        this.formError = errorText || 'Failed to save blocklist source';
                    }
                } catch (e) {
                    console.error('Error saving source:', e);
                    this.formError = 'Network error: ' + e.message;
                }
            },

            async toggleStatus(source) {
                try {
                    const res = await fetch(`${API_BASE}/blocklist-sources/${source.id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({enabled: !source.enabled})
                    });
                    if (res.ok) {
                        source.enabled = !source.enabled;
                    } else {
                        alert('Failed to toggle status');
                    }
                } catch (e) {
                    console.error('Error toggling status:', e);
                }
            },


            async deleteSource(source) {
                if (!confirm(`Delete blocklist source "${source.name}"? This cannot be undone.`)) {
                    return;
                }

                try {
                    const res = await fetch(`${API_BASE}/blocklist-sources/${source.id}`, {
                        method: 'DELETE'
                    });
                    if (res.ok) {
                        await this.loadSources();
                    } else {
                        const errorText = await res.text();
                        alert('Failed to delete: ' + errorText);
                    }
                } catch (e) {
                    console.error('Error deleting source:', e);
                    alert('Network error: ' + e.message);
                }
            },

            // ===================== ALLOWLIST =====================

            async loadWhitelistSources() {
                this.wLoading = true;
                try {
                    const res = await fetch(`${API_BASE}/whitelist-sources`);
                    if (res.ok) {
                        this.wSources = await res.json();
                        await this.$nextTick();
                        scheduleLucide(0);
                    }
                } catch (e) {
                    console.error('Failed to load whitelist sources:', e);
                } finally {
                    this.wLoading = false;
                }
            },

            async wToggleGroup(source, groupId, add) {
                const newIds = add
                    ? [...source.group_ids, groupId]
                    : source.group_ids.filter(id => id !== groupId);
                try {
                    const res = await fetch(`${API_BASE}/whitelist-sources/${source.id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({group_ids: newIds})
                    });
                    if (res.ok) {
                        source.group_ids = newIds;
                    } else {
                        const errorText = await res.text();
                        alert('Failed to update groups: ' + errorText);
                        await this.loadWhitelistSources();
                    }
                } catch (e) {
                    console.error('Error updating allowlist groups:', e);
                    await this.loadWhitelistSources();
                }
            },

            wEditSource(source) {
                this.wEditingSource = source;
                this.wForm = {
                    name: source.name,
                    url: source.url || '',
                    group_ids: [...(source.group_ids || [])],
                    comment: source.comment || '',
                    enabled: source.enabled
                };
                this.wFormError = '';
                this.$nextTick(() => scheduleLucide());
            },

            wCancelForm() {
                this.wEditingSource = null;
                this.wFormError = '';
                this.wForm = {
                    name: '',
                    url: '',
                    group_ids: [this.defaultGroupId()],
                    comment: '',
                    enabled: true
                };
            },

            async wSaveSource() {
                this.wFormError = '';

                const payload = {
                    name: this.wForm.name.trim(),
                    url: this.wForm.url.trim() || null,
                    group_ids: this.wForm.group_ids,
                    comment: this.wForm.comment.trim() || null,
                    enabled: this.wForm.enabled
                };

                try {
                    let res;
                    if (this.wEditingSource) {
                        res = await fetch(`${API_BASE}/whitelist-sources/${this.wEditingSource.id}`, {
                            method: 'PUT',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    } else {
                        res = await fetch(`${API_BASE}/whitelist-sources`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    }

                    if (res.ok) {
                        await this.loadWhitelistSources();
                        this.wCancelForm();
                    } else {
                        const errorText = await res.text();
                        this.wFormError = errorText || 'Failed to save allowlist source';
                    }
                } catch (e) {
                    console.error('Error saving allowlist source:', e);
                    this.wFormError = 'Network error: ' + e.message;
                }
            },

            async wToggleStatus(source) {
                try {
                    const res = await fetch(`${API_BASE}/whitelist-sources/${source.id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({enabled: !source.enabled})
                    });
                    if (res.ok) {
                        source.enabled = !source.enabled;
                    } else {
                        alert('Failed to toggle status');
                    }
                } catch (e) {
                    console.error('Error toggling allowlist status:', e);
                }
            },


            async wDeleteSource(source) {
                if (!confirm(`Delete allowlist source "${source.name}"? This cannot be undone.`)) {
                    return;
                }

                try {
                    const res = await fetch(`${API_BASE}/whitelist-sources/${source.id}`, {
                        method: 'DELETE'
                    });
                    if (res.ok) {
                        await this.loadWhitelistSources();
                    } else {
                        const errorText = await res.text();
                        alert('Failed to delete: ' + errorText);
                    }
                } catch (e) {
                    console.error('Error deleting allowlist source:', e);
                    alert('Network error: ' + e.message);
                }
            },

            // ===================== MANAGED DOMAINS =====================

            async loadManagedDomains() {
                this.mLoading = true;
                try {
                    const res = await fetch(`${API_BASE}/managed-domains`);
                    if (res.ok) {
                        const result = await res.json();
                        this.mSources = result.data;
                        await this.$nextTick();
                        scheduleLucide(0);
                    }
                } catch (e) {
                    console.error('Failed to load managed domains:', e);
                } finally {
                    this.mLoading = false;
                }
            },

            mEditDomain(domain) {
                this.mEditingDomain = domain;
                this.mForm = {
                    name: domain.name,
                    domain: domain.domain,
                    action: domain.action,
                    group_id: domain.group_id,
                    comment: domain.comment || '',
                    enabled: domain.enabled
                };
                this.mFormError = '';
                this.$nextTick(() => scheduleLucide());
            },

            mCancelForm() {
                this.mEditingDomain = null;
                this.mFormError = '';
                this.mForm = {
                    name: '',
                    domain: '',
                    action: 'deny',
                    group_id: this.defaultGroupId(),
                    comment: '',
                    enabled: true
                };
            },

            async mSaveDomain() {
                this.mFormError = '';

                const payload = {
                    name: this.mForm.name.trim(),
                    domain: this.mForm.domain.trim().toLowerCase(),
                    action: this.mForm.action,
                    group_id: parseInt(this.mForm.group_id),
                    comment: this.mForm.comment.trim() || null,
                    enabled: this.mForm.enabled
                };

                try {
                    let res;
                    if (this.mEditingDomain) {
                        res = await fetch(`${API_BASE}/managed-domains/${this.mEditingDomain.id}`, {
                            method: 'PUT',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    } else {
                        res = await fetch(`${API_BASE}/managed-domains`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    }

                    if (res.ok) {
                        await this.loadManagedDomains();
                        this.mCancelForm();
                    } else {
                        const errorText = await res.text();
                        this.mFormError = errorText || 'Failed to save managed domain';
                    }
                } catch (e) {
                    console.error('Error saving managed domain:', e);
                    this.mFormError = 'Network error: ' + e.message;
                }
            },

            async mToggleStatus(domain) {
                try {
                    const res = await fetch(`${API_BASE}/managed-domains/${domain.id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({enabled: !domain.enabled})
                    });
                    if (res.ok) {
                        domain.enabled = !domain.enabled;
                    } else {
                        alert('Failed to toggle status');
                    }
                } catch (e) {
                    console.error('Error toggling managed domain status:', e);
                }
            },

            async mChangeGroup(domain, newGroupId) {
                try {
                    const res = await fetch(`${API_BASE}/managed-domains/${domain.id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({group_id: newGroupId})
                    });
                    if (res.ok) {
                        domain.group_id = newGroupId;
                    } else {
                        const errorText = await res.text();
                        alert('Failed to change group: ' + errorText);
                        await this.loadManagedDomains();
                    }
                } catch (e) {
                    console.error('Error changing managed domain group:', e);
                    await this.loadManagedDomains();
                }
            },

            async mDeleteDomain(domain) {
                if (!confirm(`Delete managed domain "${domain.name}" (${domain.domain})? This cannot be undone.`)) {
                    return;
                }

                try {
                    const res = await fetch(`${API_BASE}/managed-domains/${domain.id}`, {
                        method: 'DELETE'
                    });
                    if (res.ok) {
                        await this.loadManagedDomains();
                    } else {
                        const errorText = await res.text();
                        alert('Failed to delete: ' + errorText);
                    }
                } catch (e) {
                    console.error('Error deleting managed domain:', e);
                    alert('Network error: ' + e.message);
                }
            },

            // ===================== REGEX FILTERS =====================

            async loadRegexFilters() {
                this.rgLoading = true;
                try {
                    const res = await fetch(`${API_BASE}/regex-filters`);
                    if (res.ok) {
                        this.rgFilters = await res.json();
                        await this.$nextTick();
                        scheduleLucide(0);
                    }
                } catch (e) {
                    console.error('Failed to load regex filters:', e);
                } finally {
                    this.rgLoading = false;
                }
            },

            rgEditFilter(filter) {
                this.rgEditingFilter = filter;
                this.rgForm = {
                    name: filter.name,
                    pattern: filter.pattern,
                    action: filter.action,
                    group_id: filter.group_id,
                    comment: filter.comment || '',
                    enabled: filter.enabled
                };
                this.rgFormError = '';
                this.$nextTick(() => scheduleLucide());
            },

            rgCancelForm() {
                this.rgEditingFilter = null;
                this.rgFormError = '';
                this.rgForm = {
                    name: '',
                    pattern: '',
                    action: 'deny',
                    group_id: this.defaultGroupId(),
                    comment: '',
                    enabled: true
                };
            },

            async rgSaveFilter() {
                this.rgFormError = '';

                const payload = {
                    name: this.rgForm.name.trim(),
                    pattern: this.rgForm.pattern.trim(),
                    action: this.rgForm.action,
                    group_id: parseInt(this.rgForm.group_id),
                    comment: this.rgForm.comment.trim() || null,
                    enabled: this.rgForm.enabled
                };

                try {
                    let res;
                    if (this.rgEditingFilter) {
                        res = await fetch(`${API_BASE}/regex-filters/${this.rgEditingFilter.id}`, {
                            method: 'PUT',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    } else {
                        res = await fetch(`${API_BASE}/regex-filters`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    }

                    if (res.ok) {
                        await this.loadRegexFilters();
                        this.rgCancelForm();
                    } else {
                        const errorText = await res.text();
                        this.rgFormError = errorText || 'Failed to save regex filter';
                    }
                } catch (e) {
                    console.error('Error saving regex filter:', e);
                    this.rgFormError = 'Network error: ' + e.message;
                }
            },

            async rgToggleStatus(filter) {
                try {
                    const res = await fetch(`${API_BASE}/regex-filters/${filter.id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({enabled: !filter.enabled})
                    });
                    if (res.ok) {
                        filter.enabled = !filter.enabled;
                    } else {
                        alert('Failed to toggle status');
                    }
                } catch (e) {
                    console.error('Error toggling regex filter status:', e);
                }
            },

            async rgChangeGroup(filter, newGroupId) {
                try {
                    const res = await fetch(`${API_BASE}/regex-filters/${filter.id}`, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({group_id: newGroupId})
                    });
                    if (res.ok) {
                        filter.group_id = newGroupId;
                    } else {
                        const errorText = await res.text();
                        alert('Failed to change group: ' + errorText);
                        await this.loadRegexFilters();
                    }
                } catch (e) {
                    console.error('Error changing regex filter group:', e);
                    await this.loadRegexFilters();
                }
            },

            async rgDeleteFilter(filter) {
                if (!confirm(`Delete regex filter "${filter.name}" (${filter.pattern})? This cannot be undone.`)) {
                    return;
                }

                try {
                    const res = await fetch(`${API_BASE}/regex-filters/${filter.id}`, {
                        method: 'DELETE'
                    });
                    if (res.ok) {
                        await this.loadRegexFilters();
                    } else {
                        const errorText = await res.text();
                        alert('Failed to delete: ' + errorText);
                    }
                } catch (e) {
                    console.error('Error deleting regex filter:', e);
                    alert('Network error: ' + e.message);
                }
            },

            toggleTheme() {
                this.theme = this.theme === 'light' ? 'dark' : 'light';
                localStorage.setItem('theme', this.theme);
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                scheduleLucide();
            }
        }
    }
