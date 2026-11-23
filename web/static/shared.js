// API base URL — injected at runtime via /ferrous-config.js; the same in every mode.
// The fallback must match FERROUS_API_BASE in crates/cli/src/server/web.rs (a test checks it).
const API_BASE = window.FERROUS_API_BASE || '/ferrous/api/v1';

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

function showRestartBanner() {
    if (document.getElementById('global-restart-banner')) return;
    const main = document.querySelector('main');
    if (!main) return;
    const banner = document.createElement('div');
    banner.id = 'global-restart-banner';
    banner.className = 'notice notice-warning page-banner';
    banner.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg><p>Configuration saved. Restart the server to apply changes.</p>';
    main.insertBefore(banner, main.children[1] || null);
}

// --- Global certificate-expiry banner ---

// The same lead time as the FerrousDnsCertificateExpiring alert rule.
const CERTIFICATE_WARNING_DAYS = 21;

// Inside the warning window: the same `< 21 days` the alert rule uses.
function certificateExpiresSoon(expiresAtMs) {
    return expiresAtMs - Date.now() < CERTIFICATE_WARNING_DAYS * 86400000;
}

// Calendar days from today to the local day `expiresAtMs` falls on, so the
// count agrees with the date shown beside it; negative once that day is past.
function daysUntil(expiresAtMs) {
    const day = ms => {
        const d = new Date(ms);
        return Date.UTC(d.getFullYear(), d.getMonth(), d.getDate());
    };
    return Math.round((day(expiresAtMs) - day(Date.now())) / 86400000);
}

// `expiresAt` is the served web certificate's notAfter, in Unix seconds.
function showCertificateBanner(expiresAt) {
    const expiresAtMs = expiresAt * 1000;
    if (!certificateExpiresSoon(expiresAtMs) || document.getElementById('global-certificate-banner')) return;
    const main = document.querySelector('main');
    if (!main) return;
    const expired = expiresAtMs <= Date.now();
    const days = daysUntil(expiresAtMs);
    const banner = document.createElement('div');
    banner.id = 'global-certificate-banner';
    banner.className = `notice ${expired ? 'notice-error' : 'notice-warning'} page-banner`;
    banner.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg><p></p>';
    const date = new Date(expiresAtMs).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    const when = expired ? `expired on ${date}`
        : days === 0 ? `expires today, ${date}`
        : days === 1 ? `expires tomorrow, ${date}`
        : `expires in ${days} days, on ${date}`;
    const message = banner.querySelector('p');
    message.append(`This server's web TLS certificate ${when}. Replace it under `);
    const link = document.createElement('a');
    link.href = '/settings.html#security';
    link.textContent = 'Settings → Security';
    link.addEventListener('click', event => {
        // Already on Settings, where the hash may not change: tell the page anyway.
        if (document.body.dataset.page !== 'settings') return;
        event.preventDefault();
        history.replaceState(null, '', '#security');
        window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    message.append(link, ', restart the server, and update any copy of it a reverse proxy or Prometheus checks against.');
    // A page can place it in a slot of its own; otherwise it goes on top, like the restart banner.
    const slot = document.getElementById('certificate-banner-slot');
    if (slot) slot.append(banner);
    else main.insertBefore(banner, main.children[1] || null);
}

// --- Toasts: an action's outcome, bottom right. Errors stay a little longer;
// a click dismisses one at once. `kind` is success, error, warning or info. ---

function showToast(message, kind = 'success') {
    let stack = document.getElementById('toast-stack');
    if (!stack) {
        stack = document.createElement('div');
        stack.id = 'toast-stack';
        stack.className = 'toast-stack';
        stack.setAttribute('role', 'status');
        stack.setAttribute('aria-live', 'polite');
        document.body.appendChild(stack);
    }
    const toast = document.createElement('div');
    toast.className = `toast toast-${kind}`;
    toast.textContent = message;
    const dismiss = () => {
        toast.classList.add('toast-leaving');
        setTimeout(() => toast.remove(), 200);
    };
    toast.addEventListener('click', dismiss);
    stack.appendChild(toast);
    setTimeout(dismiss, kind === 'error' ? 6000 : 3500);
}

// --- Server version label (sidebar footer), linked to its release notes ---

function showServerVersion() {
    const el = document.getElementById('server-version');
    if (!el || !window.FERROUS_VERSION) return;
    el.textContent = 'v' + window.FERROUS_VERSION;
    el.href = `https://github.com/ferrous-networking/ferrous-dns/releases/tag/v${window.FERROUS_VERSION}`;
}

// --- UI that follows the server config: the DNSSEC and DoH UI and the restart and certificate banners ---

async function applyServerConfigUi() {
    try {
        const res = await apiFetch(`${API_BASE}/config`);
        if (!res.ok) return;
        const config = await res.json();
        hideDnssecUiWhenDisabled(config.dns || {});
        hideDohUiWhenDisabled(config.server || {});
        // The server clears `restart_required` by restarting; Settings renders its own banner.
        if (config.restart_required && document.body.dataset.page !== 'settings') showRestartBanner();
        if (typeof config.web_certificate_expires_at === 'number') showCertificateBanner(config.web_certificate_expires_at);
    } catch (e) {
        // fail-open: keep the DNSSEC and DoH UI visible and the banners hidden on any error
    }
}

// Hide DNSSEC UI (sidebar item + dashboard "DNSSEC Bogus" card) when DNSSEC is disabled (mode = Off).
function hideDnssecUiWhenDisabled(dns) {
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
}

// Hide the DoH IDs sidebar item when DoH is disabled. Fail-open: only hide on a definite false.
function hideDohUiWhenDisabled(server) {
    const encryptedDns = server.encrypted_dns || {};
    if (encryptedDns.doh_enabled !== false) return;
    document.querySelectorAll('a[href="/doh-ids.html"]')
        .forEach(el => { el.style.display = 'none'; });
}

document.addEventListener('DOMContentLoaded', function() {
    showServerVersion();
    applyServerConfigUi();
});

// --- Managed domain expiry, stored as UTC `YYYY-MM-DD HH:MM:SS` ---

// The time alone when it falls today, with the date when it does not.
function formatExpiry(expiresAt) {
    const at = new Date(expiresAt.replace(' ', 'T') + 'Z');
    return at.toDateString() === new Date().toDateString()
        ? at.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})
        : at.toLocaleString([], {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'});
}

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

// A tab tapped while partly off a scrolling tab bar slides fully into view. It waits a
// frame for the tab's panel to render: a taller page adds a scrollbar that narrows the bar.
document.addEventListener('click', function(e) {
    var tab = e.target.closest('.tab-bar .tab-btn');
    if (tab && window.innerWidth <= 1024) requestAnimationFrame(function() {
        tab.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'smooth' });
    });
});

// --- Rate color using CSS custom properties ---

function getRateColor(queryRate) {
    const q = (queryRate && queryRate.queries) || 0;
    if (q >= 10000) return 'var(--color-error)';
    if (q >= 1000) return 'var(--color-warning)';
    return 'var(--color-success)';
}

// --- Upstream pools (Settings and Dashboard) ---
// `/upstream/health/detail` returns one row per server; the cards show them
// under their pool.

function groupUpstreamsByPool(upstreams) {
    const pools = new Map();
    for (const group of upstreams) {
        const key = group.pool_name || 'default';
        if (!pools.has(key)) {
            pools.set(key, { pool_name: key, strategy: group.strategy || 'Parallel', servers: [] });
        }
        pools.get(key).servers.push(group);
    }
    return Array.from(pools.values());
}

// The badge colour of an upstream pool's strategy.
function upstreamStrategyBadge(strategy) {
    if (strategy === 'Parallel') return 'badge-purple';
    if (strategy === 'Failover') return 'badge-info';
    if (strategy === 'Balanced') return 'badge-success';
    return 'badge-neutral';
}

// The badge colour of an upstream's health status.
function upstreamStatusBadge(status) {
    if (status === 'Healthy') return 'badge-success';
    if (status === 'Unhealthy') return 'badge-danger';
    if (status === 'Partial') return 'badge-warning';
    return 'badge-neutral';
}

function upstreamStatusColor(status) {
    if (status === 'Healthy')   return 'var(--color-success)';
    if (status === 'Unhealthy') return 'var(--color-error)';
    if (status === 'Partial')   return 'var(--color-warning)';
    return 'var(--text-tertiary)';
}

// An address this host has no route to (a container without IPv6) is never
// dialed and leaves its server's status alone, so it reads "No route".
function upstreamEndpointStatus(ep) {
    return ep.no_route ? 'No route' : ep.status;
}

// The card's notice when some upstream addresses have no route from this host.
function upstreamNoRouteNotice(upstreams) {
    const skipped = { ipv4: new Set(), ipv6: new Set() };
    for (const group of upstreams) {
        for (const ep of group.resolved || []) {
            if (ep.no_route && skipped[ep.family]) skipped[ep.family].add(ep.address);
        }
    }
    const v4 = skipped.ipv4.size;
    const v6 = skipped.ipv6.size;
    const count = (n, family) => `${n} ${family} upstream address${n === 1 ? ' is' : 'es are'} skipped`;
    if (v6 && !v4) return `No IPv6 route on this host: ${count(v6, 'IPv6')}. IPv4 is used.`;
    if (v4 && !v6) return `No IPv4 route on this host: ${count(v4, 'IPv4')}. IPv6 is used.`;
    if (v4 && v6) return `No route on this host to ${v4 + v6} upstream addresses: they are skipped.`;
    return '';
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
