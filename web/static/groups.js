    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            groups: [],
            editingGroup: null,
            form: {
                name: '',
                enabled: true,
                comment: ''
            },
            error: '',

            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                startRatePolling(rate => { this.queryRate = rate; });
                await this.loadGroups();
                await this.$nextTick();
                scheduleLucide(0);
            },

            async loadGroups() {
                try {
                    const res = await fetch(`${API_BASE}/groups`);
                    if (res.ok) {
                        this.groups = await res.json();
                        await this.$nextTick();
                        scheduleLucide(0);
                    }
                } catch (e) {
                    console.error('Failed to load groups:', e);
                }
            },

            editGroup(group) {
                this.editingGroup = group;
                this.form = {
                    name: group.name,
                    enabled: group.enabled,
                    comment: group.comment || ''
                };
                this.error = '';
                this.$nextTick(() => scheduleLucide());
            },

            cancelForm() {
                this.editingGroup = null;
                this.form = {name: '', enabled: true, comment: ''};
                this.error = '';
            },

            async saveGroup() {
                try {
                    this.error = '';
                    const payload = {
                        name: this.form.name.trim(),
                        enabled: this.form.enabled,
                        comment: this.form.comment.trim() || null
                    };

                    let res;
                    if (this.editingGroup) {
                        res = await fetch(`${API_BASE}/groups/${this.editingGroup.id}`, {
                            method: 'PUT',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    } else {
                        res = await fetch(`${API_BASE}/groups`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(payload)
                        });
                    }

                    if (res.ok) {
                        await this.loadGroups();
                        this.cancelForm();
                    } else {
                        const errorText = await res.text();
                        this.error = errorText || 'Failed to save group';
                    }
                } catch (e) {
                    console.error('Error saving group:', e);
                    this.error = 'Network error: ' + e.message;
                }
            },

            async deleteGroup(group) {
                if (group.is_default) {
                    alert('Cannot delete the Protected group');
                    return;
                }

                if (!confirm(`Are you sure you want to delete the group "${group.name}"?`)) {
                    return;
                }

                try {
                    const res = await fetch(`${API_BASE}/groups/${group.id}`, {
                        method: 'DELETE'
                    });

                    if (res.ok) {
                        await this.loadGroups();
                    } else {
                        const errorText = await res.text();
                        if (res.status === 409) {
                            alert('Cannot delete group with assigned clients');
                        } else {
                            alert('Failed to delete group: ' + errorText);
                        }
                    }
                } catch (e) {
                    console.error('Error deleting group:', e);
                    alert('Network error: ' + e.message);
                }
            },

            toggleTheme() {
                this.theme = this.theme === 'light' ? 'dark' : 'light';
                localStorage.setItem('theme', this.theme);
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
            }
        }
    }
