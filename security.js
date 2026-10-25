// E&C usage page – Security section.
// Reads security_log, which the audit functions (functions/index.js) write: sign-in activity,
// accounts, database changes and alerts. The database rules let only the admin read it. This page
// writes acks/{alertId} (an alert marked as seen), notify (which alerts send a phone notification),
// push_test (the test button) and, in the Android app, push_tokens (index.html, setupPush).
// Uses $, esc, fmt, tile, rankList, columnChart, db, TS, ecPush and ADMIN_EMAIL from index.html,
// and EC_ALERT_TYPES from functions/alert-types.js.

(function () {
    const LOG = 'security_log';
    const ROW_LIMIT = 5000;        // most entries read per list, newest first
    const SHOW_STEP = 200;         // rows shown at a time in the tables
    const AUTO_REFRESH = 2 * 60 * 1000;

    const TYPES = {
        signin:          { label: 'Signed in',          tone: 'ok' },
        signin_failed:   { label: 'Failed sign-in',     tone: 'bad' },
        signin_refused:  { label: 'Refused',            tone: 'bad' },
        signup:          { label: 'Sign-up',            tone: 'info' },
        user_created:    { label: 'Account created',    tone: 'info' },
        user_deleted:    { label: 'Account deleted',    tone: 'warn' },
        account_changed: { label: 'Account changed',    tone: 'warn' },
        email_sent:      { label: 'Email sent',         tone: 'muted' },
        sms_sent:        { label: 'SMS code sent',      tone: 'muted' },
        // PlutoScan (sent by plutoscan-audit/ through auditIngest)
        purchase:         { label: 'Purchase',               tone: 'ok' },
        purchase_removed: { label: 'Paid access removed',    tone: 'warn' },
        course_denied:    { label: 'Turned away from course', tone: 'bad' },
        checkout:         { label: 'Checkout',               tone: 'info' },
        visit:            { label: 'Visit',                  tone: 'muted' }
    };

    let hours = 24;
    const AT = window.EC_ALERT_TYPES;
    const EMPTY = () => ({ events: [], changes: [], alerts: [], acks: {}, census: {}, devices: {}, stats: {}, pluto: {}, notify: null, phones: {}, cut: {} });
    let data = EMPTY();
    let shown = { events: SHOW_STEP, changes: SHOW_STEP, accounts: SHOW_STEP };
    let started = false;
    let timer = null;
    const charts = {};

    // ===== HELPERS =====
    // The smallest push id made at time t: push ids start with 8 characters of time, so a range
    // of the log can be read by key with no index.
    const PUSH_CHARS = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz';
    function pushIdAt(t) {
        let out = '';
        for (let i = 0; i < 8; i++) { out = PUSH_CHARS.charAt(t % 64) + out; t = Math.floor(t / 64); }
        return out;
    }
    function when(at) {
        if (!at) return '';
        const d = new Date(at);
        const today = new Date().toDateString() === d.toDateString();
        return (today ? '' : d.toLocaleDateString('en-CA', { month: 'short', day: 'numeric' }) + ' ') +
            d.toLocaleTimeString('en-CA', { hour: 'numeric', minute: '2-digit', second: '2-digit' });
    }
    // Entries forwarded from another app (PlutoScan) are stamped with when they arrived here;
    // their own time is kept in sentAt. Show it when they arrived late, e.g. resent after an outage.
    function whenOf(x) {
        const late = Number.isFinite(x.sentAt) && Math.abs(x.at - x.sentAt) > 120000;
        return when(x.at) + (late ? ' (happened ' + when(x.sentAt) + ')' : '');
    }
    function ago(at) {
        const s = Math.round((Date.now() - at) / 1000);
        if (s < 90) return 'just now';
        if (s < 5400) return Math.round(s / 60) + ' min ago';
        if (s < 129600) return Math.round(s / 3600) + ' h ago';
        return Math.round(s / 86400) + ' days ago';
    }
    function deviceName(ua) {
        const s = String(ua || '');
        if (!s) return '';
        const browser = /Edg\//.test(s) ? 'Edge' : /OPR\//.test(s) ? 'Opera' : /SamsungBrowser/.test(s) ? 'Samsung Internet'
            : /CriOS|Chrome\//.test(s) ? 'Chrome' : /FxiOS|Firefox\//.test(s) ? 'Firefox' : /Safari\//.test(s) ? 'Safari'
            : /okhttp|Dalvik/.test(s) ? 'Android app' : /node|curl|python|Go-http|axios|Postman|wget/i.test(s) ? 'Script' : 'Browser';
        const os = /Android/.test(s) ? 'Android' : /iPhone|iPad|iPod/.test(s) ? 'iPhone/iPad' : /Windows/.test(s) ? 'Windows'
            : /Mac OS X|Macintosh/.test(s) ? 'Mac' : /CrOS/.test(s) ? 'Chromebook' : /Linux/.test(s) ? 'Linux' : '';
        return os ? browser + ' on ' + os : browser;
    }
    function list(obj) {
        return Object.keys(obj || {}).map(k => Object.assign({ id: k }, obj[k])).sort((a, b) => (b.at || 0) - (a.at || 0));
    }
    function typeLabel(t) { return TYPES[t] ? TYPES[t].label : t; }
    function pill(text, tone) { return '<span class="pill ' + esc(tone || 'muted') + '">' + esc(text) + '</span>'; }
    function who(by) {
        if (!by) return '';
        if (by.type === 'admin') return 'Server or console';
        if (by.type === 'unauthenticated') return 'Not signed in';
        return by.email || (by.uid ? 'uid ' + by.uid : 'Unknown');
    }
    const WRITERS = { app_user: 'a signed-in account', admin: 'server code or the Firebase console',
        unauthenticated: 'someone not signed in', unknown: 'Firebase did not say who' };
    function short(v) {
        if (v == null) return '—';
        const s = typeof v === 'string' ? v : JSON.stringify(v);
        return s.length > 80 ? s.slice(0, 80) + '…' : s;
    }
    function count(arr, keyFn) {
        const m = {};
        arr.forEach(x => { const k = keyFn(x); if (k) m[k] = (m[k] || 0) + 1; });
        return Object.keys(m).map(k => [k, m[k]]).sort((a, b) => b[1] - a[1]);
    }
    function status(msg, isError) {
        const el = $('sec-status');
        el.textContent = msg || '';
        el.classList.toggle('error', !!isError);
    }

    // ===== LOAD =====
    async function readRange(name, since) {
        const snap = await db.ref(LOG + '/' + name).orderByKey().startAt(pushIdAt(since)).limitToLast(ROW_LIMIT).once('value');
        data.cut[name] = snap.numChildren() >= ROW_LIMIT;
        return list(snap.val());
    }

    // auto: a timed refresh, which keeps how many rows are shown and skips while a change is open
    async function load(auto) {
        if (auto === true && document.querySelector('#sec-changes .change-detail:not([hidden])')) return;
        const since = Date.now() - hours * 3600 * 1000;
        if (auto !== true) status('Loading the last ' + rangeLabel() + '…');
        try {
            const [events, changes, alerts, acks, census, devices, stats, pluto, notify, phones] = await Promise.all([
                readRange('events', since),
                readRange('changes', since),
                readRange('alerts', Date.now() - Math.max(hours, 24 * 30) * 3600 * 1000),
                db.ref(LOG + '/acks').once('value'),
                db.ref(LOG + '/census').once('value'),
                db.ref(LOG + '/devices').once('value'),
                db.ref(LOG + '/stats').orderByKey().limitToLast(31).once('value'),
                db.ref(LOG + '/ext/plutoscan/census').once('value'),
                db.ref(LOG + '/notify').once('value'),
                db.ref(LOG + '/push_tokens').once('value')
            ]);
            data = Object.assign(data, { events, changes, alerts, acks: acks.val() || {}, census: census.val() || {},
                devices: devices.val() || {}, stats: stats.val() || {}, pluto: pluto.val() || {},
                notify: notify.val(), phones: phones.val() || {} });
            if (auto !== true) shown = { events: SHOW_STEP, changes: SHOW_STEP, accounts: SHOW_STEP };
            fillFilters();
            render();
            status('Updated ' + new Date().toLocaleTimeString('en-CA', { hour: 'numeric', minute: '2-digit' }) +
                (data.cut.events || data.cut.changes ? '. Only the newest ' + fmt(ROW_LIMIT) + ' entries of each list are shown; pick a shorter range to see the rest.' : ''));
        } catch (err) {
            console.error(err);
            status(err && err.code === 'PERMISSION_DENIED'
                ? 'The database refused the read. The security_log read rule must allow ' + ADMIN_EMAIL + ' (see the README).'
                : 'Could not load the security log: ' + (err && err.message ? err.message : err), true);
        }
    }
    function rangeLabel() { return hours === 24 ? '24 hours' : (hours / 24) + ' days'; }

    // ===== RENDER =====
    function render() {
        renderHealth();
        renderSummary();
        renderTiles();
        renderAlerts();
        renderCharts();
        renderTop();
        renderEvents();
        renderChanges();
        renderAccounts();
    }

    function renderHealth() {
        const last = Math.max(data.events[0] ? data.events[0].at : 0, data.changes[0] ? data.changes[0].at : 0);
        const days = Object.keys(data.stats).sort();
        const today = days.length ? data.stats[days[days.length - 1]] : null;
        if (!days.length && !last) {
            $('sec-health').innerHTML = '<div class="warnbox"><strong>Nothing has been logged yet.</strong> ' +
                'The security functions write this log once they are deployed (see the README in this repo). Until then, this section stays empty.</div>';
            return;
        }
        const runs = today ? Object.keys(today).reduce((s, k) => s + (Number(today[k]) || 0), 0) : 0;
        $('sec-health').innerHTML = '<p class="status" style="margin:-4px 0 12px">Last entry ' + (last ? esc(ago(last)) : 'not in this range') +
            ' · watchers ran ' + fmt(runs) + ' times on ' + esc(days[days.length - 1] || 'the last day') + ' (UTC)</p>';
    }

    function renderTiles() {
        const e = data.events;
        const n = t => e.filter(x => x.type === t).length;
        const open = data.alerts.filter(a => !data.acks[a.id]);
        const openHigh = open.filter(a => a.level === 'high').length;
        const deletes = data.changes.filter(c => c.action === 'deleted').length;
        $('sec-tab-count').textContent = open.length > 999 ? '999+' : String(open.length);
        $('sec-tab-count').hidden = !open.length;
        $('sec-tiles').innerHTML =
            tile(open.length, openHigh ? 'Alerts not seen (' + openHigh + ' high)' : 'Alerts not seen', openHigh ? 'bad' : open.length ? 'warn' : '') +
            tile(n('signin'), 'Sign-ins') +
            tile(n('signin_failed'), 'Failed sign-ins', n('signin_failed') ? 'warn' : '') +
            tile(n('signin_refused'), 'Refused accounts', n('signin_refused') ? 'warn' : '') +
            tile(n('user_created') + n('signup'), 'New accounts') +
            tile(data.changes.length, 'Database changes' + (deletes ? ' (' + fmt(deletes) + ' deletes)' : '')) +
            (Object.keys(data.pluto).length || n('purchase') || n('course_denied')
                ? tile(n('purchase'), 'PlutoScan purchases') +
                  tile(Object.values(data.pluto).filter(a => a && a.paid).length, 'PlutoScan paid (of ' + fmt(Object.keys(data.pluto).length) + ')')
                : '');
    }

    function renderAlerts() {
        const showSeen = $('sec-show-seen').checked;
        const rows = data.alerts.filter(a => showSeen || !data.acks[a.id]);
        $('sec-ack-all').disabled = !data.alerts.some(a => !data.acks[a.id]);
        if (!rows.length) {
            $('sec-alerts').innerHTML = '<div class="empty">' + (data.alerts.length ? 'Every alert has been marked as seen.' : 'No alerts in the last 30 days.') + '</div>';
            return;
        }
        const tone = { high: 'bad', medium: 'warn', low: 'info' };
        $('sec-alerts').innerHTML = rows.slice(0, 300).map(a =>
            '<div class="alert' + (data.acks[a.id] ? ' seen' : '') + '">' +
                '<div class="alert-body">' + pill(a.level || 'low', tone[a.level] || 'info') + '<strong>' + esc(a.title) + '</strong><span>' + esc(a.detail) + '</span>' +
                '<small>' + esc(whenOf(a)) + ' · ' + esc(AT.TYPES[AT.typeOf(a)].label) + (AT.wantsPush(a, data.notify) ? '' : ' · no notification') + '</small></div>' +
                (data.acks[a.id] ? '<span class="seen-mark">Seen</span>'
                    : '<button class="btn-ghost small" type="button" data-ack="' + esc(a.id) + '">Seen</button>') +
            '</div>').join('') +
            (rows.length > 300 ? '<div class="empty">' + fmt(rows.length - 300) + ' older alerts not shown.</div>' : '');
    }

    function ack(ids) {
        const updates = {};
        ids.forEach(id => { updates[id] = true; data.acks[id] = true; });
        renderAlerts();
        renderTiles();
        db.ref(LOG + '/acks').update(updates).catch(err => {
            console.error(err);
            ids.forEach(id => { delete data.acks[id]; });
            renderAlerts();
            renderTiles();
            status('Could not mark alerts as seen: ' + (err && err.message ? err.message : err), true);
        });
    }

    function renderCharts() {
        // Sign-ins: buckets of an hour for 24 hours, a day otherwise. Two series: worked, and failed or refused.
        const step = hours <= 24 ? 3600 * 1000 : 24 * 3600 * 1000;
        const end = Date.now();
        const start = end - hours * 3600 * 1000;
        const slots = Math.ceil((end - start) / step);
        const labels = [];
        for (let i = 0; i < slots; i++) {
            const d = new Date(start + (i + 1) * step);
            labels.push(step < 86400000 ? d.toLocaleTimeString('en-CA', { hour: 'numeric' }) : d.toLocaleDateString('en-CA', { month: 'short', day: 'numeric' }));
        }
        const okN = new Array(slots).fill(0), badN = new Array(slots).fill(0);
        data.events.forEach(e => {
            const into = e.type === 'signin' ? okN : e.type === 'signin_failed' || e.type === 'signin_refused' ? badN : null;
            if (into) into[Math.min(slots - 1, Math.max(0, Math.floor((e.at - start) / step)))]++;
        });
        columnChart('sec-signins-chart', labels, [
            { label: 'Signed in', data: okN, color: '#3DDC97' },
            { label: 'Failed or refused', data: badN, color: '#FF6B5B' }
        ], charts);

        // Changes by area, most changed first
        const areas = count(data.changes, c => c.area);
        $('sec-areas').innerHTML = rankList(areas.map(([area, n]) => {
            const of = data.changes.filter(c => c.area === area);
            const by = act => of.filter(c => c.action === act).length;
            const parts = [['created', by('created')], ['updated', by('updated')], ['deleted', by('deleted')]].filter(p => p[1]);
            return { name: area, value: n, sub: parts.map(p => (p[0] === 'deleted' ? '<span class="e">' : '<span>') + fmt(p[1]) + ' ' + p[0] + '</span>').join(' · ') };
        }), 'No database changes in this range.', 12);
    }

    function renderTop() {
        const failed = data.events.filter(e => e.type === 'signin_failed' || e.type === 'signin_refused');
        const ranks = (rows, bad) => rows.map(r => ({ name: r[0], value: r[1], bad }));
        $('sec-top-email').innerHTML = rankList(ranks(count(failed, e => e.email || '(no email)'), true), 'None in this range.', 10);
        $('sec-top-ip').innerHTML = rankList(ranks(count(failed, e => e.ip), true), 'None in this range.', 10);
        $('sec-top-writers').innerHTML = rankList(ranks(count(data.changes, c => who(c.by)), false), 'None in this range.', 10);
    }

    // ----- sign-in activity -----
    function fillFilters() {
        const apps = Array.from(new Set(data.events.map(e => e.app).filter(Boolean))).sort();
        fillSelect('sec-ev-app', apps.map(a => [a, a]), 'All apps');
        const areas = Array.from(new Set(data.changes.map(c => c.area).filter(Boolean))).sort();
        fillSelect('sec-ch-area', areas.map(a => [a, a]), 'All areas');
    }
    function fillSelect(id, options, allLabel) {
        const sel = $(id);
        const keep = sel.value;
        sel.innerHTML = '<option value="all">' + esc(allLabel) + '</option>' +
            options.map(o => '<option value="' + esc(o[0]) + '">' + esc(o[1]) + '</option>').join('');
        sel.value = options.some(o => o[0] === keep) ? keep : 'all';
    }
    function matches(text, q) { return !q || String(text || '').toLowerCase().includes(q); }

    function renderEvents() {
        const type = $('sec-ev-type').value, app = $('sec-ev-app').value;
        const q = $('sec-ev-q').value.trim().toLowerCase();
        const rows = data.events.filter(e =>
            // Visits are many and rarely interesting, so only their own filter shows them.
            (type === 'all' ? e.type !== 'visit' : type === 'problems' ? !e.ok : e.type === type) &&
            (app === 'all' || e.app === app) &&
            (!q || [e.email, e.claimedEmail, e.ip, e.uid, e.phone, e.code, e.reason, e.ua].some(v => matches(v, q))));
        if (!rows.length) { $('sec-events').innerHTML = '<div class="empty">No sign-in activity matches.</div>'; return; }
        const detail = e => {
            const bits = [];
            if (e.code) bits.push(e.code);
            if (e.reason) bits.push(e.reason);
            if (e.action) bits.push('while: ' + e.action);
            if (e.method) bits.push('with: ' + e.method);
            if (e.provider) bits.push(e.provider);
            if (e.emailType) bits.push(e.emailType);
            if (e.smsType) bits.push(e.smsType);
            if (e.changes) bits.push(e.changes.map(c => c.label + ': ' + short(c.b) + ' → ' + short(c.a)).join('; '));
            if (e.type === 'signin_refused') bits.push(e.verified ? 'token checked' : 'not verified' + (e.tokenError ? ' (' + e.tokenError + ')' : ''));
            if (e.step) bits.push('step: ' + e.step);
            if (e.type === 'visit' || e.type === 'course_denied') bits.push(e.page || '');
            if (e.referrer) bits.push('from: ' + e.referrer);
            if (e.type === 'course_denied' || (e.type === 'checkout' && e.step === 'started')) bits.push(e.verified ? 'token checked' : 'not signed in or not verified');
            if (e.claimedEmail) bits.push('page said ' + e.claimedEmail);
            if (e.type === 'signup' && e.ok === false) bits.push('blocked');
            return bits.join(' · ');
        };
        const tone = e => ((e.type === 'signup' || e.type === 'checkout' || e.type === 'purchase') && e.ok === false ? 'bad' : TYPES[e.type] ? TYPES[e.type].tone : 'muted');
        $('sec-events').innerHTML = '<ul class="items">' +
            rows.slice(0, shown.events).map(e => {
                const meta = [e.app, e.ip, deviceName(e.ua)].filter(Boolean).join(' · ');
                const d = detail(e);
                return '<li class="item">' +
                    '<div class="item-top">' + pill(e.type === 'signup' && e.ok === false ? 'Sign-up blocked' : typeLabel(e.type), tone(e)) +
                        '<span class="time">' + esc(whenOf(e)) + '</span></div>' +
                    '<div class="item-main">' + esc(e.email || e.phone || (e.uid ? 'uid ' + e.uid : 'No account')) + (e.staff ? ' <span class="tag">staff</span>' : '') + '</div>' +
                    (meta ? '<div class="item-meta">' + esc(meta) + '</div>' : '') +
                    (d ? '<div class="item-detail">' + esc(d) + '</div>' : '') + '</li>';
            }).join('') + '</ul>' + more('events', rows.length);
    }

    function more(name, total) {
        return total > shown[name]
            ? '<div class="more"><button class="btn-ghost" type="button" data-more="' + name + '">Show more (' + fmt(total - shown[name]) + ' left)</button></div>'
            : '';
    }

    // ----- database changes -----
    function renderChanges() {
        const area = $('sec-ch-area').value, action = $('sec-ch-action').value, by = $('sec-ch-by').value;
        const q = $('sec-ch-q').value.trim().toLowerCase();
        const rows = data.changes.filter(c =>
            (area === 'all' || c.area === area) && (action === 'all' || c.action === action) &&
            (by === 'all' || (c.by && c.by.type === by)) &&
            (!q || matches(c.path, q) || matches(who(c.by), q) || matches(c.by && c.by.uid, q) ||
                (c.fields || []).some(f => matches(f.f, q) || matches(f.b, q) || matches(f.a, q))));
        if (!rows.length) { $('sec-changes').innerHTML = '<div class="empty">No database changes match.</div>'; return; }
        const tone = { created: 'ok', updated: 'info', deleted: 'bad' };
        $('sec-changes').innerHTML = '<ul class="items">' +
            rows.slice(0, shown.changes).map(c => {
                const fields = c.fields || [];
                const summary = c.action === 'deleted' ? fmt(c.n || 0) + ' values removed'
                    : fields.slice(0, 3).map(f => f.f + ': ' + short(f.b) + ' → ' + short(f.a)).join('; ') + (fields.length > 3 ? '; +' + (fields.length - 3) + ' more' : '');
                return '<li class="item">' +
                    '<div class="item-top"><span>' + pill(c.action, tone[c.action]) + ' <strong>' + esc(c.area) + '</strong></span><span class="time">' + esc(whenOf(c)) + '</span></div>' +
                    '<div class="item-main">' + esc(who(c.by)) + (c.by && c.by.type === 'unauthenticated' ? ' ' + pill('not signed in', 'bad') : '') + '</div>' +
                    '<div class="item-meta mono">' + esc(c.path) + '</div>' +
                    (summary ? '<div class="item-detail">' + esc(summary) + '</div>' : '') +
                    '<div class="item-foot"><button class="btn-ghost small" type="button" data-change="' + esc(c.id) + '" aria-expanded="false">Details</button></div>' +
                    '<div class="change-detail" id="chd-' + esc(c.id) + '" hidden></div></li>';
            }).join('') + '</ul>' + more('changes', rows.length);
    }

    function showChange(id, btn) {
        const box = document.getElementById('chd-' + id);
        if (!box) return;
        if (!box.hidden) { box.hidden = true; btn.setAttribute('aria-expanded', 'false'); btn.textContent = 'Details'; return; }
        const c = data.changes.find(x => x.id === id);
        const fields = c.fields || [];
        const json = v => (v == null ? '(nothing)' : v._cut ? v.json + '… (cut short)' : JSON.stringify(v, null, 2));
        const val = v => (v == null ? '—' : typeof v === 'string' ? v : JSON.stringify(v));
        box.innerHTML =
            '<p>By ' + esc(who(c.by)) + (c.by && c.by.uid ? ' (uid ' + esc(c.by.uid) + ')' : '') + ': ' + esc(c.by ? WRITERS[c.by.type] || c.by.type : '') + '</p>' +
            (fields.length ? '<h3>Changed fields</h3><dl class="fields">' +
                fields.map(f => '<div><dt>' + esc(f.f) + '</dt><dd>' + (f.b == null ? '' : '<span class="was">' + esc(val(f.b)) + '</span> → ') + esc(val(f.a)) + '</dd></div>').join('') +
                '</dl>' + (fields.length >= 40 ? '<p class="sub">Only the first 40 changed fields are listed.</p>' : '') : '') +
            '<h3>Before</h3><pre>' + esc(json(c.before)) + '</pre><h3>After</h3><pre>' + esc(json(c.after)) + '</pre>';
        box.hidden = false;
        btn.setAttribute('aria-expanded', 'true');
        btn.textContent = 'Hide details';
    }

    // ----- accounts -----
    function renderAccounts() {
        const q = $('sec-acc-q').value.trim().toLowerCase();
        const kind = $('sec-acc-kind').value;
        if (kind === 'pluto' || kind === 'pluto_paid' || kind === 'pluto_unpaid') { renderPlutoAccounts(kind, q); return; }
        const uids = Object.keys(data.census);
        if (!uids.length) {
            $('sec-accounts').innerHTML = '<div class="empty">The account list fills in within 30 minutes of the functions being deployed.</div>';
            return;
        }
        const rows = uids.map(uid => Object.assign({ uid }, data.census[uid]))
            .filter(a => {
                const staff = /@ec\.com$/.test(a.email || '');
                return (kind === 'all' || (kind === 'staff' && staff) || (kind === 'customers' && !staff) || (kind === 'disabled' && a.disabled)) &&
                    (!q || [a.email, a.phone, a.uid, a.providers].some(v => matches(v, q)));
            })
            .sort((a, b) => (Date.parse(b.lastSignIn) || 0) - (Date.parse(a.lastSignIn) || 0));
        const date = s => (s && Date.parse(s) ? when(Date.parse(s)) : '');
        $('sec-accounts').innerHTML = '<p class="status" style="margin:0 0 8px">' + fmt(rows.length) + ' accounts. Latest sign-in first.</p><ul class="items">' +
            rows.slice(0, shown.accounts).map(a => {
                const devices = Object.values(data.devices[a.uid] || {});
                const notes = [];
                if (a.disabled) notes.push(pill('disabled', 'warn'));
                if (a.claims) notes.push(pill('custom claims: ' + a.claims, 'bad'));
                if (a.email && !a.verified && /@/.test(a.email)) notes.push(pill('email not verified', 'muted'));
                return '<li class="item">' +
                    '<div class="item-top"><span class="item-main" style="margin:0">' + esc(a.email || a.phone || a.uid) +
                        (/@ec\.com$/.test(a.email || '') ? ' <span class="tag">staff</span>' : '') + '</span>' +
                        '<span class="time">' + esc(date(a.lastSignIn) || 'never signed in') + '</span></div>' +
                    '<div class="item-meta">' + esc([a.providers, a.created ? 'created ' + date(a.created) : ''].filter(Boolean).join(' · ')) + '</div>' +
                    (devices.length ? '<div class="item-detail">' + esc(devices.map(d => d.name || deviceName(d.ua)).join(', ')) + '</div>' : '') +
                    (notes.length ? '<div class="item-detail">' + notes.join(' ') + '</div>' : '') +
                    '<div class="item-meta mono">' + esc(a.uid) + '</div></li>';
            }).join('') + '</ul>' + more('accounts', rows.length);
    }

    // PlutoScan accounts (its own Firebase project), from auditPlutoCensus every 30 minutes
    function renderPlutoAccounts(kind, q) {
        const uids = Object.keys(data.pluto);
        if (!uids.length) {
            $('sec-accounts').innerHTML = '<div class="empty">The PlutoScan account list fills in within 30 minutes of its functions being deployed (see plutoscan-audit/README.md).</div>';
            return;
        }
        const rows = uids.map(uid => Object.assign({ uid }, data.pluto[uid]))
            .filter(a => (kind === 'pluto' || (kind === 'pluto_paid') === !!a.paid) &&
                (!q || [a.email, a.uid, a.providers].some(v => matches(v, q))))
            .sort((a, b) => (Date.parse(b.created) || 0) - (Date.parse(a.created) || 0));
        const date = s => (s && Date.parse(s) ? when(Date.parse(s)) : '');
        const paid = uids.filter(u => data.pluto[u] && data.pluto[u].paid).length;
        $('sec-accounts').innerHTML = '<p class="status" style="margin:0 0 8px">' + fmt(uids.length) + ' PlutoScan accounts, ' + fmt(paid) + ' paid. Newest first.</p><ul class="items">' +
            rows.slice(0, shown.accounts).map(a => {
                const notes = [];
                if (a.disabled) notes.push(pill('disabled', 'warn'));
                if (a.claims) notes.push(pill('custom claims: ' + a.claims, 'bad'));
                if (a.email && !a.verified) notes.push(pill('email not verified', 'muted'));
                return '<li class="item">' +
                    '<div class="item-top"><span class="item-main" style="margin:0">' + esc(a.email || a.uid) + '</span>' +
                        (a.paid ? pill('paid', 'ok') : pill('not paid', 'muted')) + '</div>' +
                    '<div class="item-meta">' + esc([a.providers, a.created ? 'created ' + date(a.created) : '', a.lastSignIn ? 'last sign-in ' + date(a.lastSignIn) : ''].filter(Boolean).join(' · ')) + '</div>' +
                    (notes.length ? '<div class="item-detail">' + notes.join(' ') + '</div>' : '') +
                    '<div class="item-meta mono">' + esc(a.uid) + '</div></li>';
            }).join('') + '</ul>' + more('accounts', rows.length);
    }

    // ===== ALERTS SETTINGS (which alerts send a phone notification) =====
    // Saved in security_log/notify as { on, types: { type: bool } }; auditAlertPush reads it for every new alert.
    function settings() {
        const n = data.notify || {};
        const types = {};
        Object.keys(AT.TYPES).forEach(t => { types[t] = AT.wantsPush({ type: t }, { on: true, types: n.types }); });
        return { on: n.on !== false, types };
    }
    function renderSummary() {
        const s = settings();
        const on = Object.values(s.types).filter(Boolean).length;
        $('sec-alert-summary').textContent = s.on ? on + ' of ' + Object.keys(s.types).length + ' on' : 'notifications off';
    }
    function phoneText() {
        const phones = Object.values(data.phones || {});
        const list = phones.length ? phones.length + (phones.length === 1 ? ' phone gets' : ' phones get') + ' notifications (' +
            phones.map(p => p.device || 'Android phone').join(', ') + ').' : '';
        if (ecPush.native) {
            const here = { on: 'This phone is set up for notifications.', off: 'Setting up notifications on this phone…',
                blocked: 'Notifications are turned off for this app. Turn them on in the phone’s Settings > Apps > E&C Usage > Notifications.',
                error: 'This phone could not sign up for notifications. Close the app and open it again.' }[ecPush.state] || '';
            return { text: here + (list && ecPush.state === 'on' ? ' ' + list : ''), bad: ecPush.state === 'blocked' || ecPush.state === 'error' };
        }
        return { text: (list || 'No phone gets notifications yet.') + ' Notifications go to the E&C Usage Android app: install it and sign in to add a phone.', bad: !phones.length };
    }
    function renderSettings() {
        const s = settings();
        $('alert-sheet').classList.toggle('off', !s.on);
        $('notify-on').checked = s.on;
        $('notify-on-text').textContent = s.on ? 'On for the alerts ticked below' : 'Off: no alert sends a notification';
        const ph = phoneText();
        $('notify-phones').textContent = ph.text;
        $('notify-phones').classList.toggle('bad', ph.bad);
        $('notify-test').disabled = !Object.keys(data.phones || {}).length;
        const tone = { high: 'bad', medium: 'warn', low: 'info' };
        $('notify-types').innerHTML = Object.keys(AT.GROUPS).map(g =>
            '<fieldset><legend>' + esc(AT.GROUPS[g]) + '</legend>' +
            Object.keys(AT.TYPES).filter(t => AT.TYPES[t].group === g).map(t => {
                const T = AT.TYPES[t];
                return '<label class="check-row"><input type="checkbox" data-type="' + esc(t) + '"' + (s.types[t] ? ' checked' : '') + (s.on ? '' : ' disabled') + '>' +
                    '<span class="txt">' + esc(T.label) + (T.help ? '<small>' + esc(T.help) + '</small>' : '') + '</span>' +
                    pill(T.level, tone[T.level]) + '</label>';
            }).join('') + '</fieldset>').join('');
        renderSummary();
    }
    function saveSettings(next) {
        const was = data.notify;
        data.notify = next;
        renderSettings();
        renderAlerts();
        $('notify-saved').classList.remove('error');
        $('notify-saved').textContent = 'Saving…';
        db.ref(LOG + '/notify').set(next).then(() => {
            $('notify-saved').textContent = 'Saved. New alerts follow these settings right away.';
        }).catch(err => {
            console.error(err);
            data.notify = was;
            renderSettings();
            renderAlerts();
            $('notify-saved').classList.add('error');
            $('notify-saved').textContent = err && err.code === 'PERMISSION_DENIED'
                ? 'The database refused the change. The security_log rules need the notify part (see security_log.rules.json).'
                : 'Could not save: ' + (err && err.message ? err.message : err);
        });
    }
    async function openSettings() {
        $('notify-saved').textContent = '';
        $('notify-test-msg').textContent = '';
        renderSettings();
        $('alert-sheet').showModal();
        try {
            // Fresh copies: a phone may have been added since the last load
            const [notify, phones] = await Promise.all([db.ref(LOG + '/notify').once('value'), db.ref(LOG + '/push_tokens').once('value')]);
            data.notify = notify.val();
            data.phones = phones.val() || {};
            renderSettings();
        } catch (e) { /* the copies from the last load stay */ }
    }
    function sendTest() {
        const btn = $('notify-test'), msg = $('notify-test-msg');
        const asked = Date.now() - 60 * 1000; // allows for the phone's clock being a little off
        btn.disabled = true;
        msg.textContent = 'Sending…';
        const ref = db.ref(LOG + '/push_result');
        let done = false;
        const finish = text => { if (done) return; done = true; ref.off('value', onResult); clearTimeout(t); msg.textContent = text; btn.disabled = false; };
        const onResult = snap => {
            const r = snap.val();
            if (r && r.at > asked) finish(r.sent ? 'Sent to ' + r.sent + (r.sent === 1 ? ' phone.' : ' phones.') : 'No phone took it. Open the app on the phone and sign in again.');
        };
        const t = setTimeout(() => finish('No answer from the server. Check that the functions are deployed (README).'), 25000);
        db.ref(LOG + '/push_test').set(TS).then(() => ref.on('value', onResult)).catch(err => finish('Could not send: ' + (err && err.message ? err.message : err)));
    }
    function wireSettings() {
        $('sec-alert-settings').addEventListener('click', openSettings);
        $('alert-sheet-close').addEventListener('click', () => $('alert-sheet').close());
        $('notify-on').addEventListener('change', e => saveSettings(Object.assign(settings(), { on: e.target.checked })));
        $('notify-types').addEventListener('change', e => {
            const box = e.target.closest('[data-type]'); if (!box) return;
            const s = settings();
            s.types[box.dataset.type] = box.checked;
            saveSettings(s);
        });
        document.querySelector('#alert-sheet .quick').addEventListener('click', e => {
            const b = e.target.closest('[data-preset]'); if (!b) return;
            const p = b.dataset.preset;
            const types = {};
            Object.keys(AT.TYPES).forEach(t => {
                types[t] = p === 'all' ? true : p === 'none' ? false : p === 'high' ? AT.TYPES[t].level === 'high' : AT.TYPES[t].on;
            });
            saveSettings({ on: true, types });
        });
        $('notify-test').addEventListener('click', sendTest);
    }

    // ===== CONTROLS =====
    function wire() {
        $('sec-range').addEventListener('click', e => {
            const b = e.target.closest('button'); if (!b) return;
            hours = Number(b.dataset.hours);
            document.querySelectorAll('#sec-range button').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
            load();
        });
        $('sec-refresh').addEventListener('click', () => load());
        $('sec-show-seen').addEventListener('change', renderAlerts);
        $('sec-ack-all').addEventListener('click', () => ack(data.alerts.filter(a => !data.acks[a.id]).map(a => a.id)));
        $('sec-alerts').addEventListener('click', e => { const b = e.target.closest('[data-ack]'); if (b) ack([b.dataset.ack]); });
        ['sec-ev-type', 'sec-ev-app'].forEach(id => $(id).addEventListener('change', () => { shown.events = SHOW_STEP; renderEvents(); }));
        $('sec-ev-q').addEventListener('input', () => { shown.events = SHOW_STEP; renderEvents(); });
        ['sec-ch-area', 'sec-ch-action', 'sec-ch-by'].forEach(id => $(id).addEventListener('change', () => { shown.changes = SHOW_STEP; renderChanges(); }));
        $('sec-ch-q').addEventListener('input', () => { shown.changes = SHOW_STEP; renderChanges(); });
        $('sec-acc-kind').addEventListener('change', () => { shown.accounts = SHOW_STEP; renderAccounts(); });
        $('sec-acc-q').addEventListener('input', () => { shown.accounts = SHOW_STEP; renderAccounts(); });
        $('sec-changes').addEventListener('click', e => { const b = e.target.closest('[data-change]'); if (b) showChange(b.dataset.change, b); });
        wireSettings();
        $('view-security').addEventListener('click', e => {
            const b = e.target.closest('[data-more]'); if (!b) return;
            shown[b.dataset.more] += SHOW_STEP;
            ({ events: renderEvents, changes: renderChanges, accounts: renderAccounts })[b.dataset.more]();
        });
    }

    // Called by index.html when the Security tab is shown or hidden, and on sign-out.
    window.ecSecurity = {
        show() {
            if (!started) { started = true; wire(); }
            load();
            clearInterval(timer);
            timer = setInterval(() => { if (!document.hidden) load(true); }, AUTO_REFRESH);
        },
        hide() { clearInterval(timer); timer = null; },
        refreshSettings() { if ($('alert-sheet').open) renderSettings(); },
        refreshIfShown() { if (started && !$('view-security').hidden) load(true); },
        reset() {
            clearInterval(timer); timer = null;
            data = EMPTY();
            if ($('alert-sheet').open) $('alert-sheet').close();
        }
    };
})();
