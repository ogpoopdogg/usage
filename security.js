// E&C usage page – Security section.
// Reads security_log, which the audit functions (functions/index.js) write: sign-in activity,
// accounts, database changes and alerts. The database rules let only the admin read it, and the
// only thing this page writes is acks/{alertId} (an alert marked as seen).
// Uses $, esc, fmt, db and ADMIN_EMAIL from index.html.

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
        visit:            { label: 'Visit',                  tone: 'muted' },
        stripe_paid:      { label: 'Stripe payment',         tone: 'ok' },
        payment_failed:   { label: 'Payment failed',         tone: 'bad' },
        checkout_expired: { label: 'Checkout abandoned',     tone: 'warn' },
        refund:           { label: 'Refund',                 tone: 'warn' },
        dispute:          { label: 'Chargeback',             tone: 'bad' },
        dispute_closed:   { label: 'Chargeback closed',      tone: 'info' },
        fraud_warning:    { label: 'Fraud warning',          tone: 'bad' }
    };

    let hours = 24;
    let data = { events: [], changes: [], alerts: [], acks: {}, census: {}, devices: {}, stats: {}, pluto: {}, cut: {} };
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
        if (auto === true && document.querySelector('#sec-changes tr.detail:not([hidden])')) return;
        const since = Date.now() - hours * 3600 * 1000;
        if (auto !== true) status('Loading the last ' + rangeLabel() + '…');
        try {
            const [events, changes, alerts, acks, census, devices, stats, pluto] = await Promise.all([
                readRange('events', since),
                readRange('changes', since),
                readRange('alerts', Date.now() - Math.max(hours, 24 * 30) * 3600 * 1000),
                db.ref(LOG + '/acks').once('value'),
                db.ref(LOG + '/census').once('value'),
                db.ref(LOG + '/devices').once('value'),
                db.ref(LOG + '/stats').orderByKey().limitToLast(31).once('value'),
                db.ref(LOG + '/ext/plutoscan/census').once('value')
            ]);
            data = Object.assign(data, { events, changes, alerts, acks: acks.val() || {}, census: census.val() || {},
                devices: devices.val() || {}, stats: stats.val() || {}, pluto: pluto.val() || {} });
            if (auto !== true) shown = { events: SHOW_STEP, changes: SHOW_STEP, accounts: SHOW_STEP };
            fillFilters();
            render();
            status('Updated at ' + new Date().toLocaleTimeString('en-CA', { hour: 'numeric', minute: '2-digit' }) +
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
        $('sec-health').innerHTML = '<p class="status">Last entry ' + (last ? esc(ago(last)) + ' (' + esc(when(last)) + ')' : 'not in this range') +
            '. Watchers ran ' + fmt(runs) + ' times on ' + esc(days[days.length - 1] || 'the last day') + ' (UTC).</p>';
    }

    function renderTiles() {
        const e = data.events;
        const n = t => e.filter(x => x.type === t).length;
        const open = data.alerts.filter(a => !data.acks[a.id]);
        const openHigh = open.filter(a => a.level === 'high').length;
        const deletes = data.changes.filter(c => c.action === 'deleted').length;
        $('sec-tab-count').textContent = open.length > 999 ? '999+' : String(open.length);
        $('sec-tab-count').hidden = !open.length;
        const tile = (v, label, tone) => '<div' + (tone ? ' class="' + tone + '"' : '') + '><strong>' + fmt(v) + '</strong>' + esc(label) + '</div>';
        $('sec-tiles').innerHTML =
            tile(open.length, 'Alerts not seen' + (openHigh ? ' (' + openHigh + ' high)' : ''), openHigh ? 'bad' : '') +
            tile(n('signin'), 'Sign-ins') +
            tile(n('signin_failed'), 'Failed sign-ins', n('signin_failed') ? 'warn' : '') +
            tile(n('signin_refused'), 'Refused accounts', n('signin_refused') ? 'warn' : '') +
            tile(n('user_created') + n('signup'), 'New accounts') +
            tile(data.changes.length, 'Database changes') +
            tile(deletes, 'Deletes') +
            (Object.keys(data.pluto).length || n('purchase') || n('course_denied')
                ? tile(n('purchase'), 'PlutoScan purchases') +
                  tile(n('course_denied'), 'Turned away from the course', n('course_denied') ? 'warn' : '') +
                  tile(Object.values(data.pluto).filter(a => a && a.paid).length, 'PlutoScan paid accounts (of ' + fmt(Object.keys(data.pluto).length) + ')')
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
                pill(a.level || 'low', tone[a.level] || 'info') +
                '<div class="alert-body"><strong>' + esc(a.title) + '</strong><span>' + esc(a.detail) + '</span>' +
                '<small>' + esc(when(a.at)) + ' · ' + esc(a.src || '') + '</small></div>' +
                (data.acks[a.id] ? '<span class="seen-mark">Seen</span>'
                    : '<button class="btn-ghost" type="button" data-ack="' + esc(a.id) + '">Mark seen</button>') +
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
        // Sign-in activity: buckets of an hour for 24 hours, a day otherwise
        const step = hours <= 24 ? 3600 * 1000 : 24 * 3600 * 1000;
        const end = Date.now();
        const start = end - hours * 3600 * 1000;
        const slots = Math.ceil((end - start) / step);
        const labels = [];
        for (let i = 0; i < slots; i++) {
            const d = new Date(start + (i + 1) * step);
            labels.push(step < 86400000 ? d.toLocaleTimeString('en-CA', { hour: 'numeric' }) : d.toLocaleDateString('en-CA', { month: 'short', day: 'numeric' }));
        }
        const series = { signin: 'Signed in', signin_failed: 'Failed', signin_refused: 'Refused' };
        const colors = { signin: '#3DDC97', signin_failed: '#FF6B5B', signin_refused: '#FF8A3D' };
        const counts = {};
        Object.keys(series).forEach(t => { counts[t] = new Array(slots).fill(0); });
        data.events.forEach(e => {
            if (!counts[e.type]) return;
            const i = Math.min(slots - 1, Math.max(0, Math.floor((e.at - start) / step)));
            counts[e.type][i]++;
        });
        drawChart('sec-signins-chart', labels, Object.keys(series).map(t => ({
            label: series[t], data: counts[t], backgroundColor: colors[t], borderWidth: 0, borderRadius: 2, maxBarThickness: 40
        })), false);

        // Changes by area, split by action
        const areas = count(data.changes, c => c.area).map(x => x[0]);
        const actions = { created: '#3DDC97', updated: '#4FA3FF', deleted: '#FF6B5B' };
        $('sec-areas-box').style.height = Math.max(160, areas.length * 32 + 90) + 'px';
        drawChart('sec-areas-chart', areas, Object.keys(actions).map(a => ({
            label: a[0].toUpperCase() + a.slice(1), backgroundColor: actions[a], borderWidth: 0, borderRadius: 2, maxBarThickness: 26,
            data: areas.map(ar => data.changes.filter(c => c.area === ar && c.action === a).length)
        })), true);
    }
    function drawChart(id, labels, datasets, horizontal) {
        if (charts[id]) charts[id].destroy();
        const options = baseOptions(horizontal);
        charts[id] = new Chart($(id), { type: 'bar', data: { labels, datasets }, options });
    }

    function renderTop() {
        const failed = data.events.filter(e => e.type === 'signin_failed' || e.type === 'signin_refused');
        const table = (rows, head) => rows.length
            ? '<table><thead><tr><th scope="col">' + esc(head) + '</th><th scope="col">Count</th></tr></thead><tbody>' +
                rows.slice(0, 10).map(r => '<tr><td>' + esc(r[0]) + '</td><td>' + fmt(r[1]) + '</td></tr>').join('') + '</tbody></table>'
            : '<div class="empty" style="padding:14px">None in this range.</div>';
        $('sec-top-email').innerHTML = table(count(failed, e => e.email || '(no email)'), 'Email');
        $('sec-top-ip').innerHTML = table(count(failed, e => e.ip), 'IP address');
        $('sec-top-writers').innerHTML = table(count(data.changes, c => who(c.by)), 'Changed by');
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
        if (!rows.length) { $('sec-events').innerHTML = '<div class="empty" style="padding:20px">No sign-in activity matches.</div>'; return; }
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
            if (e.amount) bits.push(e.amount);
            if (e.stripeEvent && e.livemode === false) bits.push('Stripe test mode');
            if (e.type === 'visit' || e.type === 'course_denied') bits.push(e.page || '');
            if (e.referrer) bits.push('from: ' + e.referrer);
            if (e.type === 'course_denied' || (e.type === 'checkout' && e.step === 'started')) bits.push(e.verified ? 'token checked' : 'not signed in or not verified');
            if (e.claimedEmail) bits.push('page said ' + e.claimedEmail);
            if (e.type === 'signup' && e.ok === false) bits.push('blocked');
            return bits.join(' · ');
        };
        const tone = e => ((e.type === 'signup' || e.type === 'checkout' || e.type === 'purchase') && e.ok === false ? 'bad' : TYPES[e.type] ? TYPES[e.type].tone : 'muted');
        $('sec-events').innerHTML = '<table class="log"><thead><tr><th scope="col">Time</th><th scope="col">What</th><th scope="col">Account</th>' +
            '<th scope="col">App</th><th scope="col">IP address</th><th scope="col">Device</th><th scope="col">Details</th></tr></thead><tbody>' +
            rows.slice(0, shown.events).map(e => '<tr>' +
                '<td>' + esc(when(e.at)) + '</td>' +
                '<td>' + pill(e.type === 'signup' && e.ok === false ? 'Sign-up blocked' : typeLabel(e.type), tone(e)) + '</td>' +
                '<td>' + esc(e.email || e.phone || (e.uid ? 'uid ' + e.uid : '')) + (e.staff ? ' <span class="tag">staff</span>' : '') + '</td>' +
                '<td>' + esc(e.app || '') + '</td>' +
                '<td>' + esc(e.ip || '') + '</td>' +
                '<td title="' + esc(e.ua || '') + '">' + esc(deviceName(e.ua)) + '</td>' +
                '<td class="wrap">' + esc(detail(e)) + '</td></tr>').join('') +
            '</tbody></table>' + more('events', rows.length);
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
        if (!rows.length) { $('sec-changes').innerHTML = '<div class="empty" style="padding:20px">No database changes match.</div>'; return; }
        const tone = { created: 'ok', updated: 'info', deleted: 'bad' };
        $('sec-changes').innerHTML = '<table class="log"><thead><tr><th scope="col">Time</th><th scope="col">Area</th><th scope="col">Action</th>' +
            '<th scope="col">Record</th><th scope="col">Changed by</th><th scope="col">What changed</th><th scope="col"></th></tr></thead><tbody>' +
            rows.slice(0, shown.changes).map(c => {
                const fields = c.fields || [];
                const summary = c.action === 'deleted' ? fmt(c.n || 0) + ' values removed'
                    : fields.slice(0, 3).map(f => f.f + ': ' + short(f.b) + ' → ' + short(f.a)).join('; ') + (fields.length > 3 ? '; +' + (fields.length - 3) + ' more' : '');
                return '<tr>' +
                    '<td>' + esc(when(c.at)) + '</td>' +
                    '<td>' + esc(c.area) + '</td>' +
                    '<td>' + pill(c.action, tone[c.action]) + '</td>' +
                    '<td class="mono">' + esc(c.path) + '</td>' +
                    '<td>' + esc(who(c.by)) + (c.by && c.by.type === 'unauthenticated' ? ' ' + pill('!', 'bad') : '') + '</td>' +
                    '<td class="wrap">' + esc(summary) + '</td>' +
                    '<td><button class="btn-ghost small" type="button" data-change="' + esc(c.id) + '">Details</button></td></tr>' +
                    '<tr class="detail" id="chd-' + esc(c.id) + '" hidden><td colspan="7"></td></tr>';
            }).join('') + '</tbody></table>' + more('changes', rows.length);
    }

    function showChange(id) {
        const row = document.getElementById('chd-' + id);
        if (!row) return;
        if (!row.hidden) { row.hidden = true; return; }
        const c = data.changes.find(x => x.id === id);
        const fields = c.fields || [];
        const json = v => (v == null ? '(nothing)' : v._cut ? v.json + '… (cut short)' : JSON.stringify(v, null, 2));
        row.firstChild.innerHTML =
            '<div class="change-detail">' +
            '<p><strong>' + esc(c.area) + '</strong> · ' + esc(c.path) + ' · ' + esc(c.action) + ' ' + esc(when(c.at)) + '<br>' +
            'By ' + esc(who(c.by)) + (c.by && c.by.uid ? ' (uid ' + esc(c.by.uid) + ')' : '') + ': ' + esc(c.by ? WRITERS[c.by.type] || c.by.type : '') + '</p>' +
            (fields.length ? '<table><thead><tr><th scope="col">Field</th><th scope="col">Before</th><th scope="col">After</th></tr></thead><tbody>' +
                fields.map(f => '<tr><td class="mono">' + esc(f.f) + '</td><td class="wrap">' + esc(f.b == null ? '—' : typeof f.b === 'string' ? f.b : JSON.stringify(f.b)) +
                    '</td><td class="wrap">' + esc(f.a == null ? '—' : typeof f.a === 'string' ? f.a : JSON.stringify(f.a)) + '</td></tr>').join('') +
                '</tbody></table>' + (fields.length >= 40 ? '<p class="sub">Only the first 40 changed fields are listed.</p>' : '') : '') +
            '<div class="grid2"><div><h3>Before</h3><pre>' + esc(json(c.before)) + '</pre></div><div><h3>After</h3><pre>' + esc(json(c.after)) + '</pre></div></div>' +
            '</div>';
        row.hidden = false;
    }

    // ----- accounts -----
    function renderAccounts() {
        const q = $('sec-acc-q').value.trim().toLowerCase();
        const kind = $('sec-acc-kind').value;
        if (kind === 'pluto' || kind === 'pluto_paid' || kind === 'pluto_unpaid') { renderPlutoAccounts(kind, q); return; }
        const uids = Object.keys(data.census);
        if (!uids.length) {
            $('sec-accounts').innerHTML = '<div class="empty" style="padding:20px">The account list fills in within 30 minutes of the functions being deployed.</div>';
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
        $('sec-accounts').innerHTML = '<table class="log"><thead><tr><th scope="col">Account</th><th scope="col">Sign-in methods</th>' +
            '<th scope="col">Created</th><th scope="col">Last sign-in</th><th scope="col">Devices</th><th scope="col">Notes</th></tr></thead><tbody>' +
            rows.slice(0, shown.accounts).map(a => {
                const devices = Object.values(data.devices[a.uid] || {});
                const notes = [];
                if (a.disabled) notes.push(pill('disabled', 'warn'));
                if (a.claims) notes.push(pill('custom claims: ' + a.claims, 'bad'));
                if (a.email && !a.verified && /@/.test(a.email)) notes.push(pill('email not verified', 'muted'));
                return '<tr>' +
                    '<td>' + esc(a.email || a.phone || a.uid) + (/@ec\.com$/.test(a.email || '') ? ' <span class="tag">staff</span>' : '') +
                        '<small class="mono">' + esc(a.uid) + '</small></td>' +
                    '<td>' + esc(a.providers || '') + '</td>' +
                    '<td>' + esc(date(a.created)) + '</td>' +
                    '<td>' + esc(date(a.lastSignIn)) + '</td>' +
                    '<td class="wrap">' + esc(devices.map(d => d.name || deviceName(d.ua)).join(', ')) + '</td>' +
                    '<td>' + notes.join(' ') + '</td></tr>';
            }).join('') + '</tbody></table>' + more('accounts', rows.length);
    }

    // PlutoScan accounts (its own Firebase project), from auditPlutoCensus every 30 minutes
    function renderPlutoAccounts(kind, q) {
        const uids = Object.keys(data.pluto);
        if (!uids.length) {
            $('sec-accounts').innerHTML = '<div class="empty" style="padding:20px">The PlutoScan account list fills in within 30 minutes of its functions being deployed (see plutoscan-audit/README.md).</div>';
            return;
        }
        const rows = uids.map(uid => Object.assign({ uid }, data.pluto[uid]))
            .filter(a => (kind === 'pluto' || (kind === 'pluto_paid') === !!a.paid) &&
                (!q || [a.email, a.uid, a.providers].some(v => matches(v, q))))
            .sort((a, b) => (Date.parse(b.created) || 0) - (Date.parse(a.created) || 0));
        const date = s => (s && Date.parse(s) ? when(Date.parse(s)) : '');
        const paid = uids.filter(u => data.pluto[u] && data.pluto[u].paid).length;
        $('sec-accounts').innerHTML = '<p class="status" style="padding:0 0 8px">' + fmt(uids.length) + ' PlutoScan accounts, ' + fmt(paid) + ' paid. Newest first.</p>' +
            '<table class="log"><thead><tr><th scope="col">Account</th><th scope="col">Paid</th><th scope="col">Sign-in methods</th>' +
            '<th scope="col">Created</th><th scope="col">Last sign-in</th><th scope="col">Notes</th></tr></thead><tbody>' +
            rows.slice(0, shown.accounts).map(a => {
                const notes = [];
                if (a.disabled) notes.push(pill('disabled', 'warn'));
                if (a.claims) notes.push(pill('custom claims: ' + a.claims, 'bad'));
                if (a.email && !a.verified) notes.push(pill('email not verified', 'muted'));
                return '<tr>' +
                    '<td>' + esc(a.email || a.uid) + '<small class="mono">' + esc(a.uid) + '</small></td>' +
                    '<td>' + (a.paid ? pill('paid', 'ok') : pill('not paid', 'muted')) + '</td>' +
                    '<td>' + esc(a.providers || '') + '</td>' +
                    '<td>' + esc(date(a.created)) + '</td>' +
                    '<td>' + esc(date(a.lastSignIn)) + '</td>' +
                    '<td>' + notes.join(' ') + '</td></tr>';
            }).join('') + '</tbody></table>' + more('accounts', rows.length);
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
        $('sec-changes').addEventListener('click', e => { const b = e.target.closest('[data-change]'); if (b) showChange(b.dataset.change); });
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
        reset() {
            clearInterval(timer); timer = null;
            data = { events: [], changes: [], alerts: [], acks: {}, census: {}, devices: {}, stats: {}, pluto: {}, cut: {} };
        }
    };
})();
