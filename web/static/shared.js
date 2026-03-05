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
        const res = await fetch('/api/stats/rate?unit=second', {signal: _rateAbort.signal});
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

// --- Rate color using CSS custom properties ---

function getRateColor(queryRate) {
    const q = (queryRate && queryRate.queries) || 0;
    if (q >= 10000) return 'var(--color-error)';
    if (q >= 1000) return 'var(--color-warning)';
    return 'var(--color-success)';
}
