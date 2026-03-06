    function app() {
        return {
            clients: [],
            groups: [],
            subnets: [],
            stats: {},
            queryRate: {queries: 0, rate: '0 q/s'},
            selectedSubnets: [],
            selectAllSubnets: false,
            editingId: null,
            editForm: { hostname: '', group_id: '' },
            form: {
                address: '',
                group_id: '',
                metadata: '',
                type: null,
                error: ''
            },

            async init() {
                this.theme = localStorage.getItem('theme') || 'light';
                document.documentElement.classList.toggle('dark', this.theme === 'dark');
                startRatePolling(rate => { this.queryRate = rate; });
                await this.loadAll();
                scheduleLucide(100);
            },

            async loadAll() {
                await Promise.all([
                    this.loadClients(),
                    this.loadGroups(),
                    this.loadStats(),
                    this.loadSubnets(),
                ]);
            },

            async loadClients() {
                try {
                    const res = await fetch(`${API_BASE}/clients?limit=1000`);
                    if (res.ok) this.clients = await res.json();
                } catch (e) {
                    console.error('Failed to load clients:', e);
                }
            },

            async loadGroups() {
                try {
                    const res = await fetch(`${API_BASE}/groups`);
                    if (res.ok) {
                        this.groups = await res.json();
                        const defaultGroup = this.groups.find(g => g.name === 'Protected') || this.groups[0];
                        if (defaultGroup && !this.form.group_id) this.form.group_id = defaultGroup.id;
                    }
                } catch (e) {
                    console.error('Failed to load groups:', e);
                }
            },

            async loadStats() {
                try {
                    const res = await fetch(`${API_BASE}/clients/stats`);
                    if (res.ok) this.stats = await res.json();
                } catch (e) {
                    console.error('Failed to load stats:', e);
                }
            },

            async loadSubnets() {
                try {
                    const res = await fetch(`${API_BASE}/client-subnets`);
                    if (res.ok) this.subnets = await res.json();
                } catch (e) {
                    console.error('Failed to load subnets:', e);
                }
            },

            getGroupName(id) {
                const g = this.groups.find(x => x.id === id);
                return g ? g.name : '-';
            },

            startEdit(c) {
                this.editingId = c.id;
                const defaultGroup = this.groups.find(g => g.name === 'Protected') || this.groups[0];
                this.editForm = {
                    hostname: c.hostname || '',
                    group_id: c.group_id ? String(c.group_id) : (defaultGroup ? String(defaultGroup.id) : ''),
                };
                this.$nextTick(() => scheduleLucide(50));
            },

            cancelEdit() {
                this.editingId = null;
                this.editForm = { hostname: '', group_id: '' };
                scheduleLucide(50);
            },

            async saveEdit(id) {
                const payload = {
                    hostname: this.editForm.hostname.trim() || null,
                    group_id: this.editForm.group_id ? parseInt(this.editForm.group_id) : null,
                };
                try {
                    const res = await fetch(`${API_BASE}/clients/${id}`, {
                        method: 'PATCH',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload),
                    });
                    if (res.ok) {
                        const updated = await res.json();
                        const idx = this.clients.findIndex(c => c.id === id);
                        if (idx !== -1) this.clients[idx] = updated;
                        this.cancelEdit();
                        await this.loadStats();
                        scheduleLucide(50);
                    } else {
                        alert('Failed: ' + await res.text());
                    }
                } catch (e) {
                    console.error(e);
                    alert('Error saving client');
                }
            },

            detectType() {
                const v = this.form.address.trim();
                this.form.error = '';
                if (!v) { this.form.type = null; return; }
                if (v.includes('/')) {
                    if (this.isValidCIDR(v)) { this.form.type = 'subnet'; }
                    else { this.form.type = null; this.form.error = 'Invalid CIDR format (e.g., 192.168.1.0/24)'; }
                    return;
                }
                if (this.isValidMAC(v)) {
                    this.form.type = 'mac';
                    this.form.error = 'MAC detected! Please enter the IP address.';
                    return;
                }
                if (this.isValidIP(v)) { this.form.type = 'ip'; }
                else { this.form.type = null; this.form.error = 'Invalid IP, CIDR or MAC address'; }
            },

            isValidIP(ip) {
                const parts = ip.split('.');
                if (parts.length === 4) {
                    return parts.every(p => {
                        const num = parseInt(p, 10);
                        return p === num.toString() && num >= 0 && num <= 255;
                    });
                }
                return false;
            },

            isValidCIDR(cidr) {
                const parts = cidr.split('/');
                if (parts.length !== 2) return false;
                const prefix = parseInt(parts[1]);
                if (!this.isValidIP(parts[0])) return false;
                return prefix >= 0 && prefix <= 32;
            },

            isValidMAC(mac) {
                return /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^[0-9A-Fa-f]{12}$/.test(mac);
            },

            getBadgeClass() {
                if (this.form.type === 'ip') return 'badge-ip';
                if (this.form.type === 'subnet') return 'badge-subnet';
                if (this.form.type === 'mac') return 'badge-mac';
                return '';
            },

            getTypeLabel() {
                return { ip: 'IP Address → Individual Client', subnet: 'CIDR Subnet → Multiple Clients', mac: 'MAC Address → Requires IP' }[this.form.type] || '';
            },

            getButtonText() {
                if (!this.form.type) return 'Enter address...';
                if (this.form.type === 'mac') return 'Add IP address';
                return this.form.type === 'subnet' ? 'Add Subnet' : 'Add Client';
            },

            async submitForm() {
                if (!this.form.type || this.form.type === 'mac' || this.form.error) {
                    alert(this.form.error || 'Invalid address');
                    return;
                }
                try {
                    if (this.form.type === 'subnet') { await this.submitSubnet(); }
                    else { await this.submitClient(); }
                } catch (e) {
                    console.error('Submission error:', e);
                    alert('Error: ' + e.message);
                }
            },

            async submitClient() {
                const res = await fetch(`${API_BASE}/clients`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: this.form.address,
                        group_id: this.form.group_id ? parseInt(this.form.group_id) : null,
                        hostname: this.form.metadata || null,
                        mac_address: null
                    })
                });
                if (res.ok) { this.resetForm(); await this.loadAll(); scheduleLucide(); alert('Client added successfully!'); }
                else { alert('Failed: ' + await res.text()); }
            },

            async submitSubnet() {
                const res = await fetch(`${API_BASE}/client-subnets`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        subnet_cidr: this.form.address,
                        group_id: this.form.group_id ? parseInt(this.form.group_id) : null,
                        comment: this.form.metadata || null
                    })
                });
                if (res.ok) { this.resetForm(); await this.loadAll(); scheduleLucide(); alert('Subnet added successfully!'); }
                else { alert('Failed: ' + await res.text()); }
            },

            resetForm() {
                this.form = { address: '', group_id: '', metadata: '', type: null, error: '' };
            },

            async deleteClient(id) {
                if (!confirm('Delete this client?')) return;
                try {
                    const res = await fetch(`${API_BASE}/clients/${id}`, { method: 'DELETE' });
                    if (res.ok) { await this.loadAll(); scheduleLucide(); }
                    else { alert('Failed: ' + await res.text()); }
                } catch (e) {
                    console.error(e);
                    alert('Error deleting client');
                }
            },

            async deleteSubnet(id) {
                if (!confirm('Delete this subnet?')) return;
                try {
                    const res = await fetch(`${API_BASE}/client-subnets/${id}`, { method: 'DELETE' });
                    if (res.ok) { await this.loadAll(); scheduleLucide(); }
                    else { alert('Failed: ' + await res.text()); }
                } catch (e) {
                    console.error(e);
                    alert('Error deleting subnet');
                }
            },

            toggleSelectAllSubnets() {
                this.selectedSubnets = this.selectAllSubnets ? this.subnets.map(s => s.id) : [];
            },

            updateSelectAllSubnets() {
                this.selectAllSubnets = this.selectedSubnets.length === this.subnets.length && this.subnets.length > 0;
            },

            async bulkDeleteSubnets() {
                const count = this.selectedSubnets.length;
                if (count === 0) return;
                if (!confirm(`Delete ${count} selected subnet${count > 1 ? 's' : ''}? This action cannot be undone.`)) return;
                try {
                    let deleted = 0, failed = 0;
                    for (let i = 0; i < this.selectedSubnets.length; i += 10) {
                        const batch = this.selectedSubnets.slice(i, i + 10);
                        await Promise.all(batch.map(id =>
                            fetch(`${API_BASE}/client-subnets/${id}`, { method: 'DELETE' })
                                .then(res => res.ok ? deleted++ : failed++)
                                .catch(() => failed++)
                        ));
                    }
                    await this.loadAll();
                    scheduleLucide(100);
                    this.selectedSubnets = [];
                    this.selectAllSubnets = false;
                    if (failed === 0) alert(`${deleted} subnet${deleted > 1 ? 's' : ''} deleted successfully!`);
                    else alert(`Deleted ${deleted}. Failed to delete ${failed}.`);
                } catch (e) {
                    console.error('Bulk delete error:', e);
                    alert('Error during bulk delete operation');
                }
            },

            formatDateTime(timestamp) {
                if (!timestamp) return '-';
                return new Date(timestamp).toLocaleString();
            }
        }
    }
