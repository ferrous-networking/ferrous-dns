// API base URL — injected at runtime via /ferrous-config.js
// In normal mode: /api  |  In Pi-hole compat mode: /ferrous/api
const API_BASE = window.FERROUS_API_BASE || '/api';

// --- Lucide icon refresh ---

let _lucideTimer = null;

function scheduleLucide(delay = 50) {
    clearTimeout(_lucideTimer);
    _lucideTimer = setTimeout(() => lucide.createIcons(), delay);
}

// --- Query rate polling ---

let _rateInterval = null;
let _rateAbort = null;
let _rateCallback = null;
let _visibilityHandler = null;

async function _fetchRate() {
    if (_rateAbort) _rateAbort.abort();
    _rateAbort = new AbortController();
    try {
        const res = await apiFetch(`${API_BASE}/stats/rate?unit=second`, {signal: _rateAbort.signal});
        if (res.ok) {
            const data = await res.json();
            if (_rateCallback) _rateCallback(data);
        }
    } catch (e) {
        if (e.name !== 'AbortError') console.error('Rate fetch error:', e);
    }
}

function _startRateInterval() {
    clearInterval(_rateInterval);
    _fetchRate();
    _rateInterval = setInterval(_fetchRate, 1000);
}

function _stopRateInterval() {
    clearInterval(_rateInterval);
    _rateInterval = null;
    if (_rateAbort) {
        _rateAbort.abort();
        _rateAbort = null;
    }
}

function startRatePolling(onUpdate) {
    stopRatePolling();
    _rateCallback = onUpdate;
    _startRateInterval();
    _visibilityHandler = () => {
        if (document.hidden) {
            _stopRateInterval();
        } else {
            _startRateInterval();
        }
    };
    document.addEventListener('visibilitychange', _visibilityHandler);
}

function stopRatePolling() {
    _stopRateInterval();
    _rateCallback = null;
    if (_visibilityHandler) {
        document.removeEventListener('visibilitychange', _visibilityHandler);
        _visibilityHandler = null;
    }
}

// --- Dashboard API key (stored in localStorage) ---

function apiKey() {
    return localStorage.getItem('ferrous_api_key') || '';
}

function apiFetch(url, options = {}) {
    const key = apiKey();
    if (key) {
        options.headers = { ...options.headers, 'X-Api-Key': key };
    }
    return fetch(url, options);
}

// --- Auth guard ---

async function checkAuth() {
    try {
        const res = await fetch(`${API_BASE}/auth/status`);
        if (!res.ok) return;
        const data = await res.json();
        if (!data.enabled) return;
        // Auth is enabled — check if we have a valid session
        const probe = await apiFetch(`${API_BASE}/auth/sessions`);
        if (probe.status === 401) {
            window.location.href = '/login.html';
        }
    } catch (e) {
        console.error('Auth check failed:', e);
    }
}

async function logout() {
    try {
        await apiFetch(`${API_BASE}/auth/logout`, {method: 'POST'});
    } catch (e) {
        console.error('Logout error:', e);
    }
    localStorage.removeItem('ferrous_api_key');
    window.location.href = '/login.html';
}

// --- User-agent parser ---

function parseBrowser(ua) {
    if (!ua || ua === 'unknown') return 'Unknown';
    if (ua.includes('Edg/')) return 'Edge';
    if (ua.includes('OPR/') || ua.includes('Opera')) return 'Opera';
    if (ua.includes('Vivaldi/')) return 'Vivaldi';
    if (ua.includes('Brave')) return 'Brave';
    if (ua.includes('Chrome/') && ua.includes('Safari/')) return 'Chrome';
    if (ua.includes('Firefox/')) return 'Firefox';
    if (ua.includes('Safari/') && !ua.includes('Chrome')) return 'Safari';
    if (ua.includes('curl/')) return 'curl';
    return ua.length > 30 ? ua.substring(0, 30) + '...' : ua;
}

// --- Global restart-required banner ---

function isRestartRequired() {
    return !!localStorage.getItem('ferrous_config_saved_at');
}

function markRestartRequired() {
    localStorage.setItem('ferrous_config_saved_at', String(Date.now()));
}

function clearRestartRequired() {
    localStorage.removeItem('ferrous_config_saved_at');
    hideRestartBanner();
}

function showRestartBanner() {
    if (document.getElementById('global-restart-banner')) return;
    const main = document.querySelector('main');
    if (!main) return;
    const banner = document.createElement('div');
    banner.id = 'global-restart-banner';
    banner.style.cssText = 'background:#FEF3C7;border:1px solid #F59E0B;border-radius:8px;padding:12px 20px;margin-bottom:20px;display:flex;align-items:center;gap:12px';
    banner.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg><p style="font-size:14px;color:#92400E;margin:0;font-weight:500">Configuration saved. Restart the server to apply changes.</p>';
    main.insertBefore(banner, main.children[1] || null);
}

function hideRestartBanner() {
    const banner = document.getElementById('global-restart-banner');
    if (banner) banner.remove();
}

// --- Server version label (sidebar footer) ---

function showServerVersion() {
    const el = document.getElementById('server-version');
    if (el && window.FERROUS_VERSION) el.textContent = 'v' + window.FERROUS_VERSION;
}

// --- Hide DNSSEC UI (sidebar item + dashboard "DNSSEC Bogus" card) when DNSSEC is disabled (mode = Off) ---

async function hideDnssecUiWhenDisabled() {
    try {
        const res = await apiFetch(`${API_BASE}/config`);
        if (!res.ok) return;
        const dns = (await res.json()).dns || {};
        // `dnssec_enabled` is the server-derived "mode validates" flag (false when Off);
        // fall back to the mode string for older payloads. Fail-open: only hide on a definite Off.
        let disabled = false;
        if (typeof dns.dnssec_enabled === 'boolean') {
            disabled = !dns.dnssec_enabled;
        } else if (typeof dns.dnssec_mode === 'string') {
            disabled = dns.dnssec_mode.toLowerCase() === 'off';
        }
        if (!disabled) return;
        // Sidebar item (every page) + the "DNSSEC Bogus" stat card (dashboard only).
        document.querySelectorAll('a[href="/dnssec.html"], #dnssec-bogus-card')
            .forEach(el => { el.style.display = 'none'; });
    } catch (e) {
        // fail-open: keep the DNSSEC UI visible on any error
    }
}

document.addEventListener('DOMContentLoaded', function() {
    showServerVersion();
    hideDnssecUiWhenDisabled();
    if (document.body.dataset.page === 'settings') return;
    if (isRestartRequired()) showRestartBanner();
});

// --- Mobile sidebar toggle ---

function toggleSidebar() {
    document.querySelector('.sidebar').classList.toggle('open');
    document.querySelector('.sidebar-overlay').classList.toggle('active');
}

function closeSidebar() {
    document.querySelector('.sidebar').classList.remove('open');
    document.querySelector('.sidebar-overlay').classList.remove('active');
}

// Close sidebar when a nav link is clicked (mobile)
document.addEventListener('click', function(e) {
    var link = e.target.closest('.sidebar .nav-item');
    if (link && window.innerWidth <= 1024) closeSidebar();
});

// --- Rate color using CSS custom properties ---

function getRateColor(queryRate) {
    const q = (queryRate && queryRate.queries) || 0;
    if (q >= 10000) return 'var(--color-error)';
    if (q >= 1000) return 'var(--color-warning)';
    return 'var(--color-success)';
}

// --- WebAuthn (passkey) helpers ---
// webauthn-rs speaks base64url; the browser WebAuthn API wants ArrayBuffers.
// These convert between the two for the create/get ceremonies.

function b64urlToBuf(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const bin = atob(b64 + pad);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
}

function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function webauthnSupported() {
    return typeof window.PublicKeyCredential !== 'undefined';
}

// Registration: transform the server challenge, call navigator.credentials.create,
// and shape the attestation back into webauthn-rs's RegisterPublicKeyCredential.
async function webauthnCreate(challenge) {
    const pk = challenge.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.user.id = b64urlToBuf(pk.user.id);
    if (pk.excludeCredentials) {
        pk.excludeCredentials = pk.excludeCredentials.map(c => ({ ...c, id: b64urlToBuf(c.id) }));
    }
    const cred = await navigator.credentials.create({ publicKey: pk });
    return {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        response: {
            attestationObject: bufToB64url(cred.response.attestationObject),
            clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        },
        extensions: cred.getClientExtensionResults(),
    };
}

// Authentication: transform the server challenge, call navigator.credentials.get,
// and shape the assertion back into webauthn-rs's PublicKeyCredential.
async function webauthnGet(challenge) {
    const pk = challenge.publicKey;
    pk.challenge = b64urlToBuf(pk.challenge);
    if (pk.allowCredentials) {
        pk.allowCredentials = pk.allowCredentials.map(c => ({ ...c, id: b64urlToBuf(c.id) }));
    }
    const cred = await navigator.credentials.get({ publicKey: pk });
    return {
        id: cred.id,
        rawId: bufToB64url(cred.rawId),
        type: cred.type,
        response: {
            authenticatorData: bufToB64url(cred.response.authenticatorData),
            clientDataJSON: bufToB64url(cred.response.clientDataJSON),
            signature: bufToB64url(cred.response.signature),
            userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
        },
        extensions: cred.getClientExtensionResults(),
    };
}
