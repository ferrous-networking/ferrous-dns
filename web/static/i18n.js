// UI-only localization. DNS configuration, API enums and user data stay unchanged.
// Locale preference belongs to this browser; there is no server-wide setting.
(function () {
    'use strict';

    const STORAGE_KEY = 'ferrous_locale';
    const SUPPORTED = ['en', 'fr'];

    function browserLanguages() {
        return navigator.languages || [navigator.language || 'en'];
    }

    function detectLocale() {
        try {
            const saved = localStorage.getItem(STORAGE_KEY);
            if (SUPPORTED.includes(saved)) return saved;
        } catch (_) {
            // Storage may be unavailable in a restricted browsing context.
        }
        for (const language of browserLanguages()) {
            const code = language.toLowerCase().split('-')[0];
            if (SUPPORTED.includes(code)) return code;
        }
        return 'en';
    }

    // Read once per page load: switching language reloads the page, so a cached value
    // keeps static labels and re-rendered bindings in the same language.
    const current = detectLocale();

    // Formatting keeps the browser's regional conventions within the chosen language,
    // so an en-GB browser keeps its dates and a fr-CA browser its own conventions.
    const regional = browserLanguages().find(l => l.toLowerCase().split('-')[0] === current);
    const formatting = regional || (current === 'en' ? undefined : current);

    function locale() {
        return current;
    }

    function formatLocale() {
        return formatting;
    }

    function translate(message, parameters = {}) {
        const source = String(message ?? '');
        const key = Object.hasOwn(FERROUS_I18N_FR, source)
            ? source : source.replace(/\s+/g, ' ').trim();
        const translated = current === 'fr' && Object.hasOwn(FERROUS_I18N_FR, key)
            ? FERROUS_I18N_FR[key] : source;
        return translated.replace(/\{([a-zA-Z0-9_]+)\}/g, (token, name) =>
            Object.hasOwn(parameters, name) ? String(parameters[name]) : token);
    }

    function setLocale(language) {
        if (!SUPPORTED.includes(language)) return false;
        try {
            localStorage.setItem(STORAGE_KEY, language);
        } catch (_) {
            return false;
        }
        // Reload also updates charts, validation messages and native dialogs.
        window.location.reload();
        return true;
    }

    window.FerrousI18n = Object.freeze({
        locale,
        formatLocale,
        setLocale,
        t: translate,
        number: (value, options) => Number(value).toLocaleString(formatting, options),
        // Replaces toFixed(), which never followed the browser region.
        decimal: (value, places = 1) => Number(value).toLocaleString(current, {
            minimumFractionDigits: places, maximumFractionDigits: places, useGrouping: false,
        }),
        date: (value, options) => new Date(value).toLocaleString(formatting, options),
    });

    // Another tab switched language: reload so this one does not stay half translated.
    if (typeof window.addEventListener === 'function') {
        window.addEventListener('storage', event => {
            if (event.key === STORAGE_KEY && detectLocale() !== current) window.location.reload();
        });
    }

    document.documentElement.lang = current;
    document.addEventListener('DOMContentLoaded', () => {
        const title = document.querySelector('title[data-i18n-title]');
        if (title) document.title = translate(title.dataset.i18nTitle);
    });
})();

// Alpine expressions and page factories share the same stateless translation helper.
function t(message, parameters) {
    return window.FerrousI18n.t(message, parameters);
}

function tn(singular, plural, count) {
    const form = new Intl.PluralRules(window.FerrousI18n.locale()).select(count);
    return t(form === 'one' ? singular : plural, {count: window.FerrousI18n.number(count)});
}
