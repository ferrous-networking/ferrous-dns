function loginApp() {
    return {
        username: '',
        password: '',
        rememberMe: false,
        setupRequired: false,
        setupPassword: '',
        setupConfirm: '',
        error: '',
        loading: false,
        // Second-factor step
        mfaRequired: false,
        mfaMethods: [],
        challengeToken: '',
        mfaCode: '',
        // Passwordless (discoverable) passkey login
        passkeysAvailable: false,

        async init() {
            const theme = localStorage.getItem('theme') || 'light';
            document.documentElement.classList.toggle('dark', theme === 'dark');
            this.passkeysAvailable = webauthnSupported();
            try {
                const res = await fetch(`${API_BASE}/auth/status`);
                if (res.ok) {
                    const data = await res.json();
                    if (!data.enabled) {
                        window.location.href = '/dashboard.html';
                        return;
                    }
                    this.setupRequired = data.setup_required;
                }
            } catch (e) {
                this.error = 'Cannot connect to server';
                scheduleLucide(100);
                return;
            }
            // If already authenticated, redirect
            if (!this.setupRequired) {
                try {
                    const probe = await apiFetch(`${API_BASE}/auth/sessions`);
                    if (probe.ok) {
                        window.location.href = '/dashboard.html';
                        return;
                    }
                } catch (e) {}
            }
            scheduleLucide(100);
        },

        async setupAdmin() {
            if (!this.setupPassword || this.setupPassword.length < 8 || this.setupPassword !== this.setupConfirm) return;
            this.error = '';
            this.loading = true;
            try {
                const res = await fetch(`${API_BASE}/auth/setup`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({password: this.setupPassword})
                });
                if (res.ok || res.status === 204) {
                    this.setupRequired = false;
                    this.password = this.setupPassword;
                    this.username = 'admin';
                    this.setupPassword = '';
                    this.setupConfirm = '';
                    await this.login();
                    this.password = '';
                } else {
                    const data = await res.json().catch(() => ({}));
                    this.error = data.error || 'Setup failed';
                }
            } catch (e) {
                this.error = 'Connection error. Please try again.';
            } finally {
                this.loading = false;
            }
        },

        async login() {
            if (!this.username || !this.password) return;
            this.error = '';
            this.loading = true;
            try {
                const res = await fetch(`${API_BASE}/auth/login`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: this.username,
                        password: this.password,
                        remember_me: this.rememberMe
                    })
                });
                if (res.ok) {
                    const data = await res.json().catch(() => ({}));
                    if (data.mfa_required) {
                        this.password = '';
                        this.mfaRequired = true;
                        this.mfaMethods = data.methods || [];
                        this.challengeToken = data.challenge_token || '';
                        scheduleLucide(100);
                        return;
                    }
                    this.password = '';
                    window.location.href = '/dashboard.html';
                } else {
                    const data = await res.json().catch(() => ({}));
                    this.error = data.error || 'Invalid username or password';
                }
            } catch (e) {
                this.error = 'Connection error. Please try again.';
            } finally {
                this.loading = false;
            }
        },

        async verifyMfa() {
            if (!this.mfaCode) return;
            this.error = '';
            this.loading = true;
            try {
                const res = await fetch(`${API_BASE}/auth/2fa/verify`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({challenge_token: this.challengeToken, code: this.mfaCode.trim()})
                });
                if (res.ok) {
                    this.mfaCode = '';
                    window.location.href = '/dashboard.html';
                } else {
                    const data = await res.json().catch(() => ({}));
                    this.error = data.error || 'Invalid or expired code';
                }
            } catch (e) {
                this.error = 'Connection error. Please try again.';
            } finally {
                this.loading = false;
            }
        },

        async loginPasskey() {
            if (!webauthnSupported()) {
                this.error = 'Passkeys are not supported in this browser';
                return;
            }
            this.error = '';
            this.loading = true;
            try {
                const startRes = await fetch(`${API_BASE}/auth/webauthn/authenticate/start`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({challenge_token: this.challengeToken})
                });
                if (!startRes.ok) {
                    const data = await startRes.json().catch(() => ({}));
                    this.error = data.error || 'Could not start passkey login';
                    return;
                }
                const challenge = await startRes.json();
                const assertion = await webauthnGet(challenge);
                const finishRes = await fetch(`${API_BASE}/auth/webauthn/authenticate/finish`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({challenge_token: this.challengeToken, response: assertion})
                });
                if (finishRes.ok) {
                    window.location.href = '/dashboard.html';
                } else {
                    const data = await finishRes.json().catch(() => ({}));
                    this.error = data.error || 'Passkey verification failed';
                }
            } catch (e) {
                this.error = (e && e.name === 'NotAllowedError') ? 'Passkey prompt was dismissed' : 'Passkey error. Please try again.';
            } finally {
                this.loading = false;
            }
        },

        async loginPasskeyDirect() {
            if (!webauthnSupported()) {
                this.error = 'Passkeys are not supported in this browser';
                return;
            }
            this.error = '';
            this.loading = true;
            try {
                const startRes = await fetch(`${API_BASE}/auth/webauthn/discoverable/start`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: '{}'
                });
                if (!startRes.ok) {
                    const data = await startRes.json().catch(() => ({}));
                    this.error = data.error || 'Passkey login is not available';
                    return;
                }
                const data = await startRes.json();
                const assertion = await webauthnGet(data.challenge);
                const finishRes = await fetch(`${API_BASE}/auth/webauthn/discoverable/finish`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        challenge_token: data.challenge_token,
                        response: assertion,
                        remember_me: this.rememberMe
                    })
                });
                if (finishRes.ok) {
                    window.location.href = '/dashboard.html';
                } else {
                    const d = await finishRes.json().catch(() => ({}));
                    this.error = d.error || 'Passkey verification failed';
                }
            } catch (e) {
                this.error = (e && e.name === 'NotAllowedError') ? 'Passkey prompt was dismissed' : 'Passkey error. Please try again.';
            } finally {
                this.loading = false;
            }
        },

        cancelMfa() {
            this.mfaRequired = false;
            this.mfaMethods = [];
            this.challengeToken = '';
            this.mfaCode = '';
            this.error = '';
        }
    };
}
