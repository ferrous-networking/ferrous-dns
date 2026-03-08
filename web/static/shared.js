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

// --- Rate color using CSS custom properties ---

function getRateColor(queryRate) {
    const q = (queryRate && queryRate.queries) || 0;
    if (q >= 10000) return 'var(--color-error)';
    if (q >= 1000) return 'var(--color-warning)';
    return 'var(--color-success)';
}
