    function app() {
        return {
            theme: 'light',
            queryRate: {queries: 0, rate: '0 q/s'},
            groups: [],
            // The Settings master switch: off turns every detector off for every
            // group, so the per-group switch has nothing to say.
            malwareDetectionEnabled: true,
            editingGroup: null,
            form: {
                name: '',
                enabled: true,
                comment: '',
                malware_detection_enabled: true
            },
            error: '',

            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                await checkAuth();
                startRatePolling(rate => { this.queryRate = rate; });
                await Promise.all([this.loadGroups(), this.loadMalwareDetectionSwitch()]);
                await this.$nextTick();
                scheduleLucide(0);
            },

            async loadMalwareDetectionSwitch() {
                try {
                    const res = await fetch(`${API_BASE}/config`);
                    if (res.ok) {
                        this.malwareDetectionEnabled = (await res.json()).dns.malware_detection_enabled !== false;
                    }
                } catch (e) {
                    console.error('Failed to load the malware detection switch:', e);
                }
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
                    comment: group.comment || '',
                    malware_detection_enabled: group.malware_detection_enabled
                };
                this.error = '';
                this.$nextTick(() => scheduleLucide());
            },

            cancelForm() {
                this.editingGroup = null;
                this.form = {name: '', enabled: true, comment: '', malware_detection_enabled: true};
                this.error = '';
            },

            async saveGroup() {
                try {
                    this.error = '';
                    const payload = {
                        name: this.form.name.trim(),
                        enabled: this.form.enabled,
                        comment: this.form.comment.trim() || null,
                        malware_detection_enabled: this.form.malware_detection_enabled
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

                if (!confirm(
                    `Are you sure you want to delete the group "${group.name}"?\n\n` +
                    `Any DoH IDs assigned to this group will also be deleted, and devices using those IDs will be rejected unless unregistered DoH IDs are allowed.`
                )) {
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
                            // Assigned clients, or a pool that routes for the group: the server says which.
                            alert(JSON.parse(errorText).error);
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
