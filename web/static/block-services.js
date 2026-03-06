const SS_ENGINES = [
    { id: 'google',     name: 'Google',     icon: 'search'  },
    { id: 'bing',       name: 'Bing',       icon: 'search'  },
    { id: 'youtube',    name: 'YouTube',    icon: 'youtube' },
    { id: 'duckduckgo', name: 'DuckDuckGo', icon: 'feather' },
    { id: 'yandex',     name: 'Yandex',     icon: 'globe'   },
    { id: 'brave',      name: 'Brave',      icon: 'shield'  },
    { id: 'ecosia',     name: 'Ecosia',     icon: 'leaf'    },
];

function app() {
    return {
        theme: 'light',
        queryRate: {queries: 0, rate: '0 q/s'},
        activeTab: 'catalog',
        groups: [],
        selectedGroupId: null,
        catalog: [],
        blockedServices: [],
        selectedCategory: 'all',
        searchQuery: '',
        loading: true,
        toggling: {},
        customServices: [],
        showCustomForm: false,
        customForm: { name: '', category_name: 'Custom', domains: '' },
        customFormError: '',
        customFormSubmitting: false,
        editingCustomId: null,
        engines: SS_ENGINES,
        safeSearchConfigs: [],
        ssToggling: {},
        ssLoading: false,

        // --- Schedule ---
        scheduleInfoOpen: false,
        scheduleProfiles: [],
        profileSlots: {},        // { profileId: [TimeSlotResponse] }
        groupSchedule: null,     // { group_id, profile_id } or null
        scheduleAssignId: '',
        showProfileForm: false,
        editingProfileId: null,
        profileForm: { name: '', timezone: 'UTC', comment: '' },
        profileFormError: '',
        addingSlotFor: null,
        slotForm: { days: 127, start_time: '', end_time: '', action: 'block_all' },
        slotFormError: '',

        async init() {
            this.theme = localStorage.getItem('theme') || 'light';
            document.documentElement.classList.toggle('dark', this.theme === 'dark');
            startRatePolling(rate => { this.queryRate = rate; });
            try {
                const [groupsRes, catalogRes, customRes] = await Promise.all([
                    fetch(`${API_BASE}/groups`).then(r => r.json()),
                    fetch(`${API_BASE}/services/catalog`).then(r => r.json()),
                    fetch(`${API_BASE}/custom-services`).then(r => r.json()),
                ]);
                this.groups = groupsRes || [];
                this.catalog = catalogRes || [];
                this.customServices = customRes || [];
                if (this.groups.length > 0) {
                    this.selectedGroupId = this.groups[0].id;
                    await Promise.all([
                        this.loadBlockedServices(),
                        this.loadSafeSearchConfigs(),
                        this.loadScheduleProfiles(),
                        this.loadGroupSchedule(),
                    ]);
                }
            } catch (e) {
                console.error('Failed to initialize:', e);
            } finally {
                this.loading = false;
                this.$nextTick(() => scheduleLucide());
            }
        },

        switchTab(tab) {
            this.activeTab = tab;
            this.$nextTick(() => scheduleLucide());
        },

        get categories() {
            const seen = new Map();
            for (const svc of this.catalog) {
                if (!seen.has(svc.category_id)) seen.set(svc.category_id, svc.category_name);
            }
            const cats = [{ id: 'all', name: 'All' }];
            for (const [id, name] of [...seen.entries()].sort((a, b) => a[1].localeCompare(b[1]))) {
                cats.push({ id, name });
            }
            return cats;
        },

        get filteredServices() {
            let result = this.catalog;
            if (this.selectedCategory !== 'all') result = result.filter(s => s.category_id === this.selectedCategory);
            if (this.searchQuery.trim()) {
                const q = this.searchQuery.trim().toLowerCase();
                result = result.filter(s => s.name.toLowerCase().includes(q));
            }
            return [...result].sort((a, b) => (this.isBlocked(a.id) ? 0 : 1) - (this.isBlocked(b.id) ? 0 : 1));
        },

        get blockedCount() { return this.blockedServices.length },

        isBlocked(serviceId) { return this.blockedServices.some(s => s.service_id === serviceId) },

        async toggleService(serviceId) {
            if (this.toggling[serviceId] || !this.selectedGroupId) return;
            this.toggling[serviceId] = true;
            try {
                if (this.isBlocked(serviceId)) {
                    await fetch(`${API_BASE}/services/${serviceId}/groups/${this.selectedGroupId}`, { method: 'DELETE' });
                } else {
                    await fetch(`${API_BASE}/services`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ service_id: serviceId, group_id: Number(this.selectedGroupId) }),
                    });
                }
                await this.loadBlockedServices();
            } catch (e) {
                console.error('Failed to toggle service:', e);
            } finally {
                this.toggling[serviceId] = false;
            }
        },

        async loadBlockedServices() {
            if (!this.selectedGroupId) return;
            try {
                const res = await fetch(`${API_BASE}/services?group_id=${this.selectedGroupId}`);
                this.blockedServices = await res.json();
            } catch (e) {
                console.error('Failed to load blocked services:', e);
                this.blockedServices = [];
            }
            this.$nextTick(() => scheduleLucide());
        },

        async selectGroup(groupId) {
            this.selectedGroupId = groupId;
            await Promise.all([
                this.loadBlockedServices(),
                this.loadSafeSearchConfigs(),
                this.loadGroupSchedule(),
            ]);
        },

        serviceName(serviceId) {
            const svc = this.catalog.find(s => s.id === serviceId);
            return svc ? svc.name : serviceId;
        },

        serviceCategory(serviceId) {
            const svc = this.catalog.find(s => s.id === serviceId);
            return svc ? svc.category_name : '—';
        },

        groupName(groupId) {
            const g = this.groups.find(gr => gr.id == groupId);
            return g ? g.name : '—';
        },

        async unblockService(serviceId) {
            try {
                await fetch(`${API_BASE}/services/${serviceId}/groups/${this.selectedGroupId}`, { method: 'DELETE' });
                await this.loadBlockedServices();
            } catch (e) {
                console.error('Failed to unblock service:', e);
            }
        },

        async loadCustomServices() {
            try {
                const res = await fetch(`${API_BASE}/custom-services`);
                this.customServices = await res.json();
            } catch (e) {
                console.error('Failed to load custom services:', e);
                this.customServices = [];
            }
            this.$nextTick(() => scheduleLucide());
        },

        async reloadCatalog() {
            try {
                const res = await fetch(`${API_BASE}/services/catalog`);
                this.catalog = await res.json();
            } catch (e) {
                console.error('Failed to reload catalog:', e);
            }
            this.$nextTick(() => scheduleLucide());
        },

        async saveCustomService() {
            if (this.customFormSubmitting) return;
            this.customFormError = '';
            this.customFormSubmitting = true;
            try {
                const domains = this.customForm.domains.split('\n').map(d => d.trim()).filter(d => d);
                if (!this.customForm.name.trim()) throw new Error('Name is required');
                if (domains.length === 0) throw new Error('At least one domain is required');
                const body = { name: this.customForm.name.trim(), category_name: this.customForm.category_name.trim() || 'Custom', domains };
                const isNew = !this.editingCustomId;
                const url = isNew ? `${API_BASE}/custom-services` : `${API_BASE}/custom-services/${this.editingCustomId}`;
                const method = isNew ? 'POST' : 'PATCH';
                const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
                if (!res.ok) { const err = await res.text(); throw new Error(err || `HTTP ${res.status}`); }
                const saved = await res.json();
                // Auto-block new custom services for the selected group so domains
                // are immediately created in Managed Domains and the block filter.
                if (isNew && this.selectedGroupId) {
                    try {
                        await fetch(`${API_BASE}/services`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ service_id: saved.service_id, group_id: Number(this.selectedGroupId) }),
                        });
                    } catch (e) {
                        console.warn('Auto-block after custom service create failed:', e);
                    }
                }
                this.resetCustomForm();
                await Promise.all([this.loadCustomServices(), this.reloadCatalog(), this.loadBlockedServices()]);
            } catch (e) {
                this.customFormError = e.message;
            } finally {
                this.customFormSubmitting = false;
            }
        },

        async deleteCustomService(serviceId) {
            if (!confirm('Delete this custom service? All blocked entries and managed domains will be removed.')) return;
            try {
                await fetch(`${API_BASE}/custom-services/${serviceId}`, { method: 'DELETE' });
                await Promise.all([this.loadCustomServices(), this.reloadCatalog(), this.loadBlockedServices()]);
            } catch (e) {
                console.error('Failed to delete custom service:', e);
            }
        },

        editCustomService(cs) {
            this.editingCustomId = cs.service_id;
            this.customForm.name = cs.name;
            this.customForm.category_name = cs.category_name;
            this.customForm.domains = cs.domains.join('\n');
            this.showCustomForm = true;
            this.customFormError = '';
        },

        resetCustomForm() {
            this.showCustomForm = false;
            this.editingCustomId = null;
            this.customForm = { name: '', category_name: 'Custom', domains: '' };
            this.customFormError = '';
        },

        // --- Safe Search ---

        async loadSafeSearchConfigs() {
            if (!this.selectedGroupId) return;
            this.ssLoading = true;
            try {
                const res = await fetch(`${API_BASE}/safe-search/configs/${this.selectedGroupId}`);
                this.safeSearchConfigs = res.ok ? await res.json() : [];
            } catch (e) {
                console.error('Failed to load safe search configs:', e);
                this.safeSearchConfigs = [];
            } finally {
                this.ssLoading = false;
                this.$nextTick(() => scheduleLucide());
            }
        },

        ssEnabled(engineId) {
            const cfg = this.safeSearchConfigs.find(c => c.engine === engineId);
            return cfg ? cfg.enabled : false;
        },

        ssMode(engineId) {
            const cfg = this.safeSearchConfigs.find(c => c.engine === engineId);
            return cfg ? cfg.youtube_mode : 'strict';
        },

        async toggleSafeSearch(engineId) {
            if (this.ssToggling[engineId] || !this.selectedGroupId) return;
            this.ssToggling[engineId] = true;
            try {
                const res = await fetch(`${API_BASE}/safe-search/configs/${this.selectedGroupId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ engine: engineId, enabled: !this.ssEnabled(engineId), youtube_mode: this.ssMode(engineId) }),
                });
                if (res.ok) {
                    const updated = await res.json();
                    const idx = this.safeSearchConfigs.findIndex(c => c.engine === engineId);
                    if (idx >= 0) { this.safeSearchConfigs[idx] = updated; } else { this.safeSearchConfigs.push(updated); }
                }
            } catch (e) {
                console.error('Failed to toggle safe search:', e);
            } finally {
                this.ssToggling[engineId] = false;
                this.$nextTick(() => scheduleLucide());
            }
        },

        async setSafeSearchMode(engineId, mode) {
            if (!this.selectedGroupId || !this.ssEnabled(engineId)) return;
            try {
                const res = await fetch(`${API_BASE}/safe-search/configs/${this.selectedGroupId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ engine: engineId, enabled: true, youtube_mode: mode }),
                });
                if (res.ok) {
                    const updated = await res.json();
                    const idx = this.safeSearchConfigs.findIndex(c => c.engine === engineId);
                    if (idx >= 0) this.safeSearchConfigs[idx] = updated;
                }
            } catch (e) {
                console.error('Failed to update youtube mode:', e);
            }
        },

        // --- Schedule ---

        async loadScheduleProfiles() {
            try {
                const res = await fetch(`${API_BASE}/schedule-profiles`);
                this.scheduleProfiles = res.ok ? await res.json() : [];
                for (const p of this.scheduleProfiles) {
                    await this.loadProfileSlots(p.id);
                }
            } catch (e) {
                console.error('Failed to load schedule profiles:', e);
                this.scheduleProfiles = [];
            }
            this.$nextTick(() => scheduleLucide());
        },

        async loadProfileSlots(profileId) {
            try {
                const res = await fetch(`${API_BASE}/schedule-profiles/${profileId}`);
                if (res.ok) {
                    const data = await res.json();
                    this.profileSlots[profileId] = data.slots || [];
                }
            } catch (e) {
                console.error('Failed to load slots for profile', profileId, e);
                this.profileSlots[profileId] = [];
            }
        },

        async loadGroupSchedule() {
            if (!this.selectedGroupId) return;
            try {
                const res = await fetch(`${API_BASE}/groups/${this.selectedGroupId}/schedule`);
                this.groupSchedule = res.ok ? await res.json() : null;
            } catch (e) {
                this.groupSchedule = null;
            }
        },

        profileName(profileId) {
            const p = this.scheduleProfiles.find(p => p.id == profileId);
            return p ? p.name : '—';
        },

        profileTimezone(profileId) {
            const p = this.scheduleProfiles.find(p => p.id == profileId);
            return p ? '(' + p.timezone + ')' : '';
        },

        async assignSchedule() {
            if (!this.scheduleAssignId || !this.selectedGroupId) return;
            try {
                const res = await fetch(`${API_BASE}/groups/${this.selectedGroupId}/schedule`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ profile_id: Number(this.scheduleAssignId) }),
                });
                if (res.ok) {
                    this.groupSchedule = await res.json();
                    this.scheduleAssignId = '';
                }
            } catch (e) {
                console.error('Failed to assign schedule:', e);
            }
        },

        async unassignSchedule() {
            if (!this.selectedGroupId) return;
            try {
                await fetch(`${API_BASE}/groups/${this.selectedGroupId}/schedule`, { method: 'DELETE' });
                this.groupSchedule = null;
            } catch (e) {
                console.error('Failed to unassign schedule:', e);
            }
        },

        openNewProfile() {
            this.editingProfileId = null;
            this.profileForm = { name: '', timezone: 'UTC', comment: '' };
            this.profileFormError = '';
            this.showProfileForm = true;
        },

        editProfile(profile) {
            this.editingProfileId = profile.id;
            this.profileForm = { name: profile.name, timezone: profile.timezone, comment: profile.comment || '' };
            this.profileFormError = '';
            this.showProfileForm = true;
        },

        async saveProfile() {
            this.profileFormError = '';
            if (!this.profileForm.name.trim()) { this.profileFormError = 'Name is required'; return; }
            try {
                const body = { name: this.profileForm.name.trim(), timezone: this.profileForm.timezone.trim() || 'UTC', comment: this.profileForm.comment.trim() || null };
                const isNew = !this.editingProfileId;
                const url = isNew ? `${API_BASE}/schedule-profiles` : `${API_BASE}/schedule-profiles/${this.editingProfileId}`;
                const method = isNew ? 'POST' : 'PUT';
                const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
                if (!res.ok) { const err = await res.json(); throw new Error(err.error || `HTTP ${res.status}`); }
                this.showProfileForm = false;
                this.editingProfileId = null;
                await this.loadScheduleProfiles();
            } catch (e) {
                this.profileFormError = e.message;
            }
        },

        async deleteProfile(profileId) {
            if (!confirm('Delete this schedule profile? It will be unassigned from all groups.')) return;
            try {
                await fetch(`${API_BASE}/schedule-profiles/${profileId}`, { method: 'DELETE' });
                await Promise.all([this.loadScheduleProfiles(), this.loadGroupSchedule()]);
            } catch (e) {
                console.error('Failed to delete profile:', e);
            }
        },

        openAddSlot(profileId) {
            this.addingSlotFor = profileId;
            this.slotForm = { days: 127, start_time: '', end_time: '', action: 'block_all' };
            this.slotFormError = '';
        },

        async saveSlot(profileId) {
            this.slotFormError = '';
            if (!this.slotForm.start_time || !this.slotForm.end_time) { this.slotFormError = 'Start and end time are required'; return; }
            if (this.slotForm.start_time >= this.slotForm.end_time) { this.slotFormError = 'Start time must be before end time'; return; }
            if (!this.slotForm.days) { this.slotFormError = 'Select at least one day'; return; }
            try {
                const res = await fetch(`${API_BASE}/schedule-profiles/${profileId}/slots`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ days: this.slotForm.days, start_time: this.slotForm.start_time, end_time: this.slotForm.end_time, action: this.slotForm.action }),
                });
                if (!res.ok) { const err = await res.json(); throw new Error(err.error || `HTTP ${res.status}`); }
                this.addingSlotFor = null;
                await this.loadProfileSlots(profileId);
            } catch (e) {
                this.slotFormError = e.message;
            }
        },

        async deleteSlot(profileId, slotId) {
            try {
                await fetch(`${API_BASE}/schedule-profiles/${profileId}/slots/${slotId}`, { method: 'DELETE' });
                await this.loadProfileSlots(profileId);
            } catch (e) {
                console.error('Failed to delete slot:', e);
            }
        },

        daysLabel(mask) {
            const names = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
            const days = names.filter((_, i) => mask & (1 << i));
            if (days.length === 7) return 'Every day';
            if (days.length === 5 && !(mask & 32) && !(mask & 64)) return 'Mon–Fri';
            if (days.length === 2 && (mask & 32) && (mask & 64)) return 'Sat–Sun';
            return days.join(', ');
        },
    };
}
