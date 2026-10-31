/* E&C security log – the parts that don't need Firebase, so they can be tested with `node --test`.

   Layout of security_log (server code writes it; the database rules let nobody else write, and
   only the admin read):
     events/{id}      sign-in activity: { at, type, ok, app, email, uid, ip, ua, ... }
                        type: signin | signin_failed | signin_refused | signup | user_created |
                              user_deleted | account_changed | email_sent | sms_sent
     changes/{id}     database changes: { at, area, path, action, by, before, after, fields, n }
     alerts/{id}      things worth looking at now: { at, type, level, title, detail, src }
                        type: a key of alert-types.js; level: high | medium | low
     acks/{alertId}   true once the admin marked an alert as seen
     notify           which kinds of alert send a phone notification: { on, types: { type: bool } }
     push_tokens/{key}  the admin's phones (the Android app): { token, platform, updated_at }
     push_result      { at, sent }: how many phones the last test reached (server code writes it)
     push_test        written by the page's "Send a test notification" button; the function clears it
                      (notify, push_tokens and push_test are the parts the admin writes, besides acks)
     counters/...     short-lived counts used to spot bursts (failed sign-ins, deletes, reports)
     devices/{uid}/{hash}  devices each account has signed in from: { first, last, ua, ip }
     census/{uid}     the last look at each account, to spot changes made outside the apps
     stats/{day}/{name}    how many times each watcher ran, to keep an eye on cost
     ext/{app}/census/{uid}  accounts of another Firebase project (PlutoScan), sent by its own
                        audit functions to auditIngest; its events, changes and alerts go into the
                        lists above with app set to that project
   Ids are push ids, which sort by time, so the page reads a time range by key with no index. */
'use strict';

const crypto = require('crypto');
const AT = require('./alert-types');

const ADMIN_EMAILS = ['justin@ec.com', 'desirae@ec.com', 'celeste@ec.com'];
const TEXT_MAX = 300;
const VALUE_MAX = 4000;      // longest before/after JSON kept for one change
const FIELDS_MAX = 40;       // changed fields listed for one change
const REPORT_MAX = 8000;     // largest report body the apps may send

function clip(v, max) {
  if (v == null || v === '') return null;
  return String(v).slice(0, max || TEXT_MAX);
}
function normEmail(email) { return String(email || '').trim().toLowerCase(); }
/** A database key for any text (IPs, emails): no . # $ [ ] / */
function safeKey(v) { return String(v || 'none').toLowerCase().replace(/[.#$[\]/]/g, ',').slice(0, 200) || 'none'; }
function hash(v) { return crypto.createHash('sha256').update(String(v)).digest('hex').slice(0, 16); }
function dayKey(at) { return new Date(at).toISOString().slice(0, 10); }
function bucket(at, ms) { return String(Math.floor(at / ms)); }

/** The client IP of an HTTP request (the first address Google's front end saw). */
function requestIp(req) {
  const fwd = String((req.headers && req.headers['x-forwarded-for']) || '').split(',')[0].trim();
  return clip(fwd || req.ip || (req.socket && req.socket.remoteAddress) || null, 64);
}

const PUSH_CHARS = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz';
/** The smallest push id made at time t: the first 8 characters of a push id are its time. */
function pushIdAt(t) {
  let out = '';
  for (let i = 0; i < 8; i++) { out = PUSH_CHARS.charAt(t % 64) + out; t = Math.floor(t / 64); }
  return out;
}

// ---------------------------------------------------------------- reports from the apps

const APPS = /^[a-z0-9_-]{1,30}$/;
const KINDS = new Set(['failed', 'refused', 'signedin']);

/** A failed or refused sign-in report sent by an app (see reportFailedSignIn in each app), or a
 * 'signedin' report naming the app a sign-in came from, or null. */
function parseReport(text) {
  if (typeof text !== 'string' || !text || text.length > REPORT_MAX) return null;
  let r;
  try { r = JSON.parse(text); } catch (e) { return null; }
  if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
  if (!KINDS.has(r.kind)) return null;
  const app = String(r.app || '').toLowerCase();
  return {
    kind: r.kind,
    app: APPS.test(app) ? app : 'unknown',
    email: clip(normEmail(r.email), 200),
    code: clip(r.code, 80),
    reason: clip(r.reason, 200),
    action: clip(r.action, 20),
    method: clip(r.method, 20),
    page: clip(r.page, 200),
    clientAt: Number.isFinite(r.at) ? r.at : null,
    idToken: typeof r.idToken === 'string' && r.idToken.length < 4096 ? r.idToken : null
  };
}

/** The security log entry for a report. token: the verified ID token (or null). */
function reportEntry(r, { at, ip, ua, origin, token, tokenError }) {
  const e = {
    at,
    type: r.kind === 'failed' ? 'signin_failed' : 'signin_refused',
    ok: false,
    app: r.app,
    email: r.email,
    code: r.code,
    reason: r.reason,
    action: r.action,
    method: r.method,
    page: r.page,
    ip: clip(ip, 64),
    ua: clip(ua),
    origin: clip(origin, 120),
    verified: !!token
  };
  if (token) {
    e.uid = clip(token.uid, 128);
    const tokenEmail = normEmail(token.email);
    if (tokenEmail && tokenEmail !== r.email) { e.claimedEmail = r.email; e.email = tokenEmail; }
  } else if (r.idToken) {
    e.tokenError = clip(tokenError || 'invalid', 80);
  }
  return e;
}

const SIGNIN_MATCH = 3 * 60 * 1000;  // how far a sign-in row may be from the token's sign-in time

/** The key of the sign-in row a 'signedin' report belongs to: the account's own row with no app yet,
 * closest to the token's sign-in time (authTime, ms). Firebase can't tell the sign-in function which
 * app is signing in, so the app says so afterwards. events: { key: entry }. */
function signInRowFor(events, uid, authTime) {
  let best = null;
  let bestGap = Infinity;
  for (const [key, e] of Object.entries(events || {})) {
    if (!e || e.type !== 'signin' || e.uid !== uid || e.app) continue;
    const gap = Math.abs((e.at || 0) - authTime);
    if (gap <= SIGNIN_MATCH && gap < bestGap) { best = key; bestGap = gap; }
  }
  return best;
}

// ---------------------------------------------------------------- sign-ins (blocking functions)

function providerOf(event) {
  const info = (event && event.additionalUserInfo) || {};
  const cred = (event && event.credential) || {};
  const u = (event && event.data) || {};
  const providers = (u.providerData || []).map((p) => p && p.providerId).filter(Boolean);
  return clip(info.providerId || cred.signInMethod || providers[0] || null, 40);
}

/** The security log entry for a beforeUserSignedIn / beforeEmailSent / beforeSmsSent event. */
function authEventEntry(type, event, at) {
  const u = (event && event.data) || {};
  const info = (event && event.additionalUserInfo) || {};
  return {
    at,
    type,
    ok: true,
    email: clip(normEmail(u.email || info.email) || null, 200),
    phone: clip(u.phoneNumber || info.phoneNumber || null, 32),
    uid: clip(u.uid || null, 128),
    provider: providerOf(event),
    emailType: clip(event && event.emailType, 30),
    smsType: clip(event && event.smsType, 40),
    ip: clip(event && event.ipAddress, 64),
    ua: clip(event && event.userAgent),
    staff: /@ec\.com$/.test(normEmail(u.email))
  };
}

/** A short description of a browser for people: "Chrome on Android". */
function deviceName(ua) {
  const s = String(ua || '');
  if (!s) return 'Unknown device';
  const browser = /Edg\//.test(s) ? 'Edge' : /OPR\//.test(s) ? 'Opera' : /SamsungBrowser/.test(s) ? 'Samsung Internet'
    : /CriOS|Chrome\//.test(s) ? 'Chrome' : /FxiOS|Firefox\//.test(s) ? 'Firefox' : /Safari\//.test(s) ? 'Safari'
    : /okhttp|Dalvik/.test(s) ? 'Android app' : /node|curl|python|Go-http|axios|Postman|wget/i.test(s) ? 'Script' : 'Browser';
  const os = /Android/.test(s) ? 'Android' : /iPhone|iPad|iPod/.test(s) ? 'iPhone/iPad' : /Windows/.test(s) ? 'Windows'
    : /Mac OS X|Macintosh/.test(s) ? 'Mac' : /CrOS/.test(s) ? 'Chromebook' : /Linux/.test(s) ? 'Linux' : '';
  return os ? browser + ' on ' + os : browser;
}
/** The key a device is remembered by: the browser and system, not the version or IP (those change often). */
function deviceKey(ua) { return hash(deviceName(ua)); }

// ---------------------------------------------------------------- database changes

/**
 * What the watchers look at. path: the trigger path; area: the name the page shows; level: the alert
 * any change raises (null = none); staffOnly: only staff accounts should ever write here.
 * Busy data that changes many times a minute is left out on purpose (see README): live driver
 * positions (developer/dispatch_dashboard/drivers, poll_state), API counters
 * (developer/api_usage), the request counter, and the apps' own logs (timeclock/audit, garage/history).
 */
const WATCHES = [
  { name: 'addressLookup', path: 'address_lookup/{id}', area: 'Address lookup', staffOnly: true },
  { name: 'staff', path: 'staff/{uid}', area: 'Staff list', level: 'high' },
  { name: 'roles', path: 'roles/{user}', area: 'Roles', level: 'high' },
  { name: 'jobs', path: 'jobs/{id}', area: 'Jobs', staffOnly: true },
  { name: 'requests', path: 'requests/{id}', area: 'Pickup requests' },
  { name: 'companies', path: 'companies/{cid}', area: 'Companies' },
  { name: 'joinCodes', path: 'join_codes/{code}', area: 'Join codes' },
  { name: 'users', path: 'users/{uid}', area: 'Customer profiles' },
  { name: 'pushTokens', path: 'push_tokens/{uid}', area: 'Dispatch phones' },
  { name: 'allowedUsers', path: 'developer/dispatch_dashboard/allowed_users', area: 'RouteWatcher allowed users', level: 'high', staffOnly: true },
  { name: 'masterConfig', path: 'developer/dispatch_dashboard/master_config', area: 'RouteWatcher settings', level: 'medium', staffOnly: true },
  { name: 'nicknames', path: 'developer/dispatch_dashboard/driver_nicknames/{gpsId}', area: 'Driver nicknames' },
  { name: 'sessions', path: 'developer/dispatch_dashboard/active_sessions/{uid}', area: 'RouteWatcher sign-in locks', staffOnly: true, quiet: true },
  { name: 'routePlanner', path: 'developer/route_planner/{section}/{id}', area: 'Route planner', staffOnly: true, skip: ['ui_prefs', 'notification_reads'] },
  { name: 'tcEmployees', path: 'timeclock/employees/{ek}', area: 'Time clock employees', level: 'high' },
  { name: 'tcSettings', path: 'timeclock/settings', area: 'Time clock settings', level: 'medium' },
  { name: 'tcShifts', path: 'timeclock/shifts/{ek}/{shiftId}', area: 'Time clock punches' },
  { name: 'tcRequests', path: 'timeclock/requests/{ek}/{id}', area: 'Punch fix requests' },
  { name: 'tcVanReports', path: 'timeclock/van_reports/{id}', area: 'Van problem reports' },
  { name: 'tcVans', path: 'timeclock/vans/{id}', area: 'Vans' },
  { name: 'tcOilPlan', path: 'timeclock/oil_plan', area: 'Oil check schedule' },
  { name: 'tcVehicleClaims', path: 'timeclock/vehicle_claims/{gpsId}', area: 'Van picks' },
  { name: 'garage', path: 'garage/{section}/{id}', area: 'Garage', skip: ['history'] },
  { name: 'dispatchContacts', path: 'dispatch_contacts/{section}/{id}', area: 'Dispatch drivers list', staffOnly: true },
  { name: 'dispatchSettings', path: 'dispatch_settings/{section}', area: 'Dispatch settings', level: 'medium', staffOnly: true }
];

function actionOf(before, after) {
  if (before == null && after != null) return 'created';
  if (before != null && after == null) return 'deleted';
  return 'updated';
}

function isObj(v) { return v !== null && typeof v === 'object'; }

/** The leaf fields that differ between two values: [{ f, b, a }], at most `limit`. */
function diffFields(before, after, limit) {
  const out = [];
  const max = limit || FIELDS_MAX;
  (function walk(b, a, p) {
    if (out.length >= max) return;
    if (isObj(b) || isObj(a)) {
      const keys = new Set([...(isObj(b) ? Object.keys(b) : []), ...(isObj(a) ? Object.keys(a) : [])]);
      if (!isObj(b) && b != null) { out.push({ f: p || '(value)', b: short(b), a: '(object)' }); return; }
      if (!isObj(a) && a != null) { out.push({ f: p || '(value)', b: '(object)', a: short(a) }); return; }
      for (const k of [...keys].sort()) walk(isObj(b) ? b[k] : undefined, isObj(a) ? a[k] : undefined, p ? p + '/' + k : k);
      return;
    }
    if (b === a) return;
    out.push({ f: p || '(value)', b: b === undefined ? null : short(b), a: a === undefined ? null : short(a) });
  })(before, after, '');
  return out;
}
function short(v) { return typeof v === 'string' ? v.slice(0, 200) : v; }

/** Number of leaf values in a value (how much a delete removed). */
function countLeaves(v) {
  if (!isObj(v)) return v == null ? 0 : 1;
  return Object.values(v).reduce((n, x) => n + countLeaves(x), 0);
}

/** A value small enough to keep in the log: the value itself, or its JSON cut short. */
function keepValue(v) {
  if (v == null) return null;
  const json = JSON.stringify(v);
  if (json.length <= VALUE_MAX) return v;
  return { _cut: true, json: json.slice(0, VALUE_MAX) };
}

/** Who made a change, from the database event. */
function whoOf(authType, authId) {
  return { type: clip(authType || 'unknown', 20), uid: clip(authId || null, 128) };
}

/** The log entry for a database change. */
function changeEntry({ watch, path, before, after, authType, authId, email, at }) {
  const action = actionOf(before, after);
  const fields = diffFields(before, after);
  return {
    at,
    area: watch.area,
    watch: watch.name,
    path: clip(path, 300),
    action,
    by: Object.assign(whoOf(authType, authId), email ? { email: clip(email, 200) } : {}),
    fields,
    n: action === 'deleted' ? countLeaves(before) : fields.length,
    before: keepValue(before),
    after: keepValue(after)
  };
}

/** Alerts a single database change raises (the burst checks are separate). staff: whether the writer is staff. */
function changeAlerts(entry, watch, { staff, adminEmail }) {
  const out = [];
  const who = entry.by.email || entry.by.uid ||
    (entry.by.type === 'admin' ? 'Server code or the console' : entry.by.type === 'unknown' ? 'Someone (Firebase did not say who)' : entry.by.type);
  if (entry.by.type === 'unauthenticated') {
    out.push({ type: 'no_signin_change', level: 'high', title: 'Change with no sign-in', detail: entry.area + ': ' + entry.path + ' was ' + entry.action + ' by someone not signed in. The database rules should never allow this.' });
  } else if (watch.staffOnly && entry.by.type === 'app_user' && staff === false && !adminEmail) {
    out.push({ type: 'nonstaff_change', level: 'high', title: 'Non-staff account changed staff data', detail: who + ' ' + entry.action + ' ' + entry.path + ' without being on the staff list.' });
  }
  if (watch.level && !watch.quiet) {
    out.push({ type: watch.level === 'high' ? 'access_change' : 'settings_change', level: watch.level, title: entry.area + ' ' + entry.action, detail: who + ' ' + entry.action + ' ' + entry.path + (entry.fields.length ? ' (' + entry.fields.slice(0, 5).map((f) => f.f).join(', ') + ')' : '') });
  }
  if (entry.action === 'deleted' && entry.n >= 20) {
    out.push({ type: 'large_delete', level: 'high', title: 'Large delete', detail: who + ' deleted ' + entry.path + ' (' + entry.n + ' values).' });
  }
  return out;
}

// ---------------------------------------------------------------- accounts (census)

/** What the census remembers about an account. */
function censusOf(u) {
  return {
    email: clip(normEmail(u.email) || null, 200),
    phone: clip(u.phoneNumber || null, 32),
    disabled: !!u.disabled,
    providers: (u.providerData || []).map((p) => p.providerId).filter(Boolean).sort().join(',') || null,
    claims: u.customClaims && Object.keys(u.customClaims).length ? JSON.stringify(u.customClaims).slice(0, 500) : null,
    tokensValidAfter: clip(u.tokensValidAfterTime || null, 40),
    created: clip(u.metadata && u.metadata.creationTime, 40),
    lastSignIn: clip(u.metadata && u.metadata.lastSignInTime, 40),
    verified: !!u.emailVerified
  };
}

const CENSUS_FIELDS = {
  email: 'email address', phone: 'phone number', disabled: 'disabled', providers: 'sign-in methods',
  claims: 'custom claims', tokensValidAfter: 'password or sessions reset', verified: 'email verified'
};

/** The differences that matter between two census records: [{ f, b, a, label }] */
function censusDiff(before, after) {
  return Object.keys(CENSUS_FIELDS)
    .filter((f) => (before[f] == null ? null : before[f]) !== (after[f] == null ? null : after[f]))
    .map((f) => ({ f, b: before[f] == null ? null : before[f], a: after[f] == null ? null : after[f], label: CENSUS_FIELDS[f] }));
}

function censusAlertLevel(diff, email) {
  if (diff.some((d) => d.f === 'claims' || d.f === 'email')) return 'high';
  if (/@ec\.com$/.test(email || '') || ADMIN_EMAILS.includes(email)) return 'medium';
  return null;
}

// ---------------------------------------------------------------- other projects (auditIngest)

/** Firebase projects whose own audit functions forward here. The key is the app name the page shows. */
const INGEST_APPS = { plutoscan: { label: 'PlutoScan', alertPrefix: 'pluto_' } };
const INGEST_MAX = 16000;     // largest body another project may send
const LEVELS = new Set(['high', 'medium', 'low']);
const UID = /^[A-Za-z0-9_-]{1,128}$/;

/** Plain JSON only, cut to a size the log can hold. */
function plain(v, depth) {
  if (v == null) return null;
  if (typeof v === 'string') return v.slice(0, VALUE_MAX);
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'boolean') return v;
  if (typeof v !== 'object' || (depth || 0) > 6) return null;
  const out = Array.isArray(v) ? [] : {};
  let n = 0;
  for (const [k, x] of Object.entries(v)) {
    if (++n > 200) break;
    const key = Array.isArray(v) ? k : (String(k).replace(/[.#$[\]/]/g, ',').slice(0, 100) || '_');
    const val = plain(x, (depth || 0) + 1);
    if (val != null) { if (Array.isArray(out)) out.push(val); else out[key] = val; }
  }
  return out;
}

/**
 * Checks what another project's audit functions sent to auditIngest. Returns
 * { kind: 'events' | 'changes' | 'alerts', entry } or { kind: 'census', set: { uid: record | null } },
 * or null if it isn't one of those. The app name is always set here, never taken from the body.
 */
function ingestEntry(text, app, at) {
  if (!INGEST_APPS[app] || typeof text !== 'string' || !text || text.length > INGEST_MAX) return null;
  let body;
  try { body = JSON.parse(text); } catch (e) { return null; }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const label = INGEST_APPS[app].label;
  if (body.kind === 'census') {
    if (!body.set || typeof body.set !== 'object' || Array.isArray(body.set)) return null;
    const set = {};
    for (const [uid, rec] of Object.entries(body.set).slice(0, 500)) {
      if (!UID.test(uid)) continue;
      set[uid] = rec && typeof rec === 'object' && !Array.isArray(rec) ? plain(rec) : null;
    }
    return { kind: 'census', set };
  }
  const e = body.entry;
  if (!e || typeof e !== 'object' || Array.isArray(e)) return null;
  const entry = plain(e);
  // Their clock is kept for reference; the log is ordered by when it arrived here.
  if (Number.isFinite(e.at)) entry.sentAt = e.at;
  entry.at = at;
  entry.app = app;
  if (body.kind === 'events') {
    if (!/^[a-z_]{1,30}$/.test(String(e.type || ''))) return null;
    entry.staff = false;
    return { kind: 'events', entry };
  }
  if (body.kind === 'changes') {
    entry.area = label + ': ' + clip(e.area || 'database', 80);
    return { kind: 'changes', entry };
  }
  if (body.kind === 'alerts') {
    entry.level = LEVELS.has(e.level) ? e.level : 'medium';
    // Their kinds of alert get the app's prefix (failed_signins -> pluto_failed_signins); unknown ones are 'other'.
    const prefix = INGEST_APPS[app].alertPrefix;
    entry.type = AT.TYPES[prefix + e.type] ? prefix + e.type : prefix + 'other';
    entry.title = clip(label + ': ' + (e.title || 'alert'), 200);
    entry.detail = clip(e.detail, 600);
    entry.src = clip(app + (e.src ? '/' + e.src : ''), 60);
    return { kind: 'alerts', entry };
  }
  return null;
}

module.exports = {
  ADMIN_EMAILS, WATCHES, REPORT_MAX, INGEST_APPS,
  ingestEntry,
  clip, normEmail, safeKey, hash, dayKey, bucket, requestIp, pushIdAt,
  parseReport, reportEntry, signInRowFor, SIGNIN_MATCH, authEventEntry, deviceName, deviceKey,
  actionOf, diffFields, countLeaves, keepValue, changeEntry, changeAlerts,
  censusOf, censusDiff, censusAlertLevel
};
