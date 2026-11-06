// Dependency-free UI checks: node --test scripts/tests/web-i18n.test.cjs
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const assets = path.join(root, 'web/static');
const catalogSource = fs.readFileSync(path.join(assets, 'i18n-fr.js'), 'utf8');
const runtimeSource = fs.readFileSync(path.join(assets, 'i18n.js'), 'utf8');

function browser({saved, languages = ['en-US'], storageBlocked = false} = {}) {
    const storage = new Map(saved ? [['ferrous_locale', saved]] : []);
    const listeners = {};
    let reloads = 0;
    const context = vm.createContext({
        navigator: {languages, language: languages[0]},
        localStorage: {
            getItem: key => {
                if (storageBlocked) throw new Error('Storage denied');
                return storage.get(key) ?? null;
            },
            setItem: (key, value) => {
                if (storageBlocked) throw new Error('Storage denied');
                storage.set(key, value);
            },
        },
        document: {
            documentElement: {},
            addEventListener: (name, handler) => { listeners[name] = handler; },
            querySelector: () => ({dataset: {i18nTitle: 'Ferrous DNS - Login'}}),
        },
        location: {reload: () => reloads++},
    });
    context.window = context;
    vm.runInContext(catalogSource + '\n' + runtimeSource, context);
    return {context, storage, listeners, reloads: () => reloads};
}

test('French browser language selects French before login', () => {
    const {context} = browser({languages: ['fr-CA', 'en']});
    assert.equal(context.FerrousI18n.locale(), 'fr');
    assert.equal(context.document.documentElement.lang, 'fr');
    assert.equal(context.t('Sign In'), 'Se connecter');
});

test('saved language overrides the browser and survives page navigation', () => {
    const {context} = browser({saved: 'en', languages: ['fr-FR']});
    assert.equal(context.t('Settings'), 'Settings');
    const french = browser({saved: 'fr', languages: ['en-US']});
    assert.equal(french.context.t('Settings'), 'Paramètres');
});

test('unsupported preferences and browser languages fall back to English', () => {
    const {context} = browser({saved: 'invalid', languages: ['de-DE']});
    assert.equal(context.FerrousI18n.locale(), 'en');
    assert.equal(context.t('Query Log'), 'Query Log');
});

test('changing language stores the preference and reloads once', () => {
    const b = browser();
    assert.equal(b.context.FerrousI18n.setLocale('fr'), true);
    assert.equal(b.storage.get('ferrous_locale'), 'fr');
    assert.equal(b.reloads(), 1);
    assert.equal(b.context.FerrousI18n.setLocale('xx'), false);
    assert.equal(b.reloads(), 1);
});

test('blocked browser storage does not break login or trigger a reload loop', () => {
    const b = browser({storageBlocked: true, languages: ['fr-FR']});
    assert.equal(b.context.t('Sign In'), 'Se connecter');
    assert.equal(b.context.FerrousI18n.setLocale('en'), false);
    assert.equal(b.reloads(), 0);
});

test('unknown technical diagnostics and user data are preserved', () => {
    const {context} = browser({saved: 'fr'});
    for (const value of ['my-custom-group', 'example.test', 'SERVFAIL: upstream disconnected']) {
        assert.equal(context.t(value), value);
    }
});

test('placeholders preserve literal replacement syntax and never evaluate data', () => {
    const {context} = browser({saved: 'fr'});
    const hostile = '<img src=x onerror=alert(1)>$&{1}';
    assert.equal(context.t('Group {0}', {0: hostile}), 'Groupe ' + hostile);
    assert.equal(context.t('Group {0}'), 'Groupe {0}');
    assert.equal(context.t('__proto__'), '__proto__');
});

test('French and English plurals use their respective zero and one rules', () => {
    const fr = browser({saved: 'fr'}).context;
    const en = browser({saved: 'en'}).context;
    assert.equal(fr.tn('{count} group', '{count} groups', 0), '0 groupe');
    assert.equal(fr.tn('{count} group', '{count} groups', 1), '1 groupe');
    assert.equal(fr.tn('{count} group', '{count} groups', 2), '2 groupes');
    assert.equal(en.tn('{count} group', '{count} groups', 0), '0 groups');
    assert.equal(en.tn('{count} group', '{count} groups', 1), '1 group');
});

test('number formatting follows the selected interface language', () => {
    const {context} = browser({saved: 'fr', languages: ['en-US']});
    assert.equal(context.FerrousI18n.number(1234.5), (1234.5).toLocaleString('fr'));
});

test('page titles are localized without putting translated HTML into the DOM', () => {
    const b = browser({saved: 'fr'});
    b.listeners.DOMContentLoaded();
    assert.equal(b.context.document.title, 'Ferrous DNS - Connexion');
});

const dictionary = vm.runInNewContext(catalogSource + '\nFERROUS_I18N_FR');
test('every French catalog entry retains its placeholders and contains plain text', () => {
    const placeholders = value => [...value.matchAll(/\{([a-zA-Z0-9_]+)\}/g)].map(m => m[1]).sort();
    for (const [source, translated] of Object.entries(dictionary)) {
        assert.ok(translated.length > 0, source);
        assert.deepEqual(placeholders(translated), placeholders(source), source);
        assert.doesNotMatch(translated, /<\/?[a-z][^>]*>/i, source);
    }
    assert.ok(Object.isFrozen(dictionary));
});

function decodeHtml(value) {
    return value.replace(/&quot;/g, '"').replace(/&#x27;|&#39;|&apos;/g, "'")
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

test('every literal translation lookup in admin HTML and JavaScript has a French entry', () => {
    const literal = String.raw`("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`;
    const lookup = new RegExp(String.raw`\bt\(\s*` + literal, 'g');
    const plural = new RegExp(String.raw`\btn\(\s*` + literal + String.raw`\s*,\s*` + literal, 'g');
    let checked = 0;
    for (const file of fs.readdirSync(assets).filter(f => /\.(html|js)$/.test(f) && !f.startsWith('i18n'))) {
        const source = decodeHtml(fs.readFileSync(path.join(assets, file), 'utf8'));
        for (const match of source.matchAll(lookup)) {
            const key = vm.runInNewContext(match[1]);
            assert.ok(Object.hasOwn(dictionary, key), `${file}: ${key}`);
            checked++;
        }
        for (const match of source.matchAll(plural)) {
            for (const literal of [match[1], match[2]]) {
                const key = vm.runInNewContext(literal);
                assert.ok(Object.hasOwn(dictionary, key), `${file}: ${key}`);
                checked++;
            }
        }
    }
    assert.ok(checked > 900, `Only checked ${checked} lookups`);
});

test('all admin pages load local catalogs before page code, and offer a language control', () => {
    for (const file of fs.readdirSync(assets).filter(f => f.endsWith('.html') && !['api-docs.html', 'index.html'].includes(f))) {
        const source = fs.readFileSync(path.join(assets, file), 'utf8');
        assert.ok(source.indexOf('/static/i18n-fr.js') < source.indexOf('/static/i18n.js'), file);
        assert.ok(source.indexOf('/static/i18n.js') < source.indexOf('/static/shared.js'), file);
        assert.match(source, /FerrousI18n\.setLocale/, file);
        assert.match(source, /value="en"/, file);
        assert.match(source, /value="fr"/, file);
    }
    const routes = fs.readFileSync(path.join(root, 'crates/cli/src/server/web.rs'), 'utf8');
    assert.match(routes, /"\/static\/i18n\.js" => \("i18n\.js", JS\)/);
    assert.match(routes, /"\/static\/i18n-fr\.js" => \("i18n-fr\.js", JS\)/);
});

test('switching language leaves DNS, security and filtering form payloads unchanged', () => {
    const cases = {
        'settings.js': ['config', 'settings', 'newUser'],
        'block-services.js': ['customForm', 'slotForm'],
        'dns-filter.js': ['form', 'mForm', 'rgForm'],
    };
    for (const [file, fields] of Object.entries(cases)) {
        const state = language => {
            const {context} = browser({saved: language});
            vm.runInContext(fs.readFileSync(path.join(assets, file), 'utf8'), context);
            const app = vm.runInContext('app()', context);
            return JSON.stringify(Object.fromEntries(fields.map(field => [field, app[field]])));
        };
        assert.equal(state('fr'), state('en'), file);
    }
});

test('pool strategy and health machine values remain available for styles and logic', () => {
    const {context} = browser({saved: 'fr'});
    vm.runInContext(fs.readFileSync(path.join(assets, 'shared.js'), 'utf8'), context);
    const strategy = vm.runInContext("groupUpstreamsByPool([{pool_name:'demo', servers:[]}])[0].strategy", context);
    assert.equal(strategy, 'Parallel');
    assert.equal(context.t(strategy), 'Parallèle');
    assert.equal(context.upstreamStatusColor('Healthy'), 'var(--color-success)');
});

test('an unknown blocked source still displays a blocked label in either language', () => {
    for (const [language, expected] of [['en', 'Blocked'], ['fr', 'Bloquées']]) {
        const {context} = browser({saved: language});
        vm.runInContext(fs.readFileSync(path.join(assets, 'queries.js'), 'utf8'), context);
        const label = vm.runInContext("app().formatSource({blocked:true,block_source:'future-kind'})", context);
        assert.equal(label, expected);
    }
});
