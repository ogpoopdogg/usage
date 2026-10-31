/* E&C security log – server code for the Security section of the usage page.

   Everything here only writes to security_log (layout in lib.js). Nothing is ever refused or
   changed: a fault in this code must never stop anyone signing in or saving their work.

   Sign-ins
   - auditSignInReport: the apps send failed and refused sign-ins here (wrong password, not on
     the staff list, ...). Firebase runs no server code on a wrong password, so this is the only
     way to see them; a determined attacker can skip it, which is why the README also turns on
     Identity Platform's own logging.
   - auditBeforeSignIn: every successful sign-in, with its IP address and browser, and the
     devices each account has used. A new device for a staff account raises a low alert.
   - auditBeforeEmail / auditBeforeSms: password reset and sign-in emails, and SMS codes.
   - auditUserCreated / auditUserDeleted: every account made or removed, including ones made in
     the Firebase console or with admin tools (the blocking functions don't see those).
   - auditUserCensus (every 30 minutes): compares every account with the last look, to catch
     changes made outside the apps (email changed, disabled, custom claims, password reset).

   Database changes
   - One watcher per entry in lib.js WATCHES, e.g. auditAddressLookup. Each change is logged
     with who made it, what it was before and after, and the fields that changed. Alerts for
     changes with no sign-in, non-staff accounts changing staff data, large deletes, and bursts
     of deletes by one account.

   Other projects
   - auditIngest: PlutoScan (its own Firebase project) runs its own audit functions and sends
     what they log here, with a secret key, so it shows in the same Security tab. Its code is
     in ../plutoscan-audit.

   Phone notifications
   - auditAlertPush: every new alert whose kind is ticked in the Security tab's Alerts settings
     (security_log/notify, kinds in alert-types.js) goes to the admin's phones through Firebase
     Cloud Messaging. The phones are the E&C Usage Android app (see ../android and the README).
   - auditTestPush: the "Send a test notification" button.

   Upkeep
   - auditPrune (daily): drops events and changes after 90 days, alerts after a year.
   - auditBackup (daily): a copy of the whole database and its rules in the backup bucket
     (see backup.js), because Firebase's own automated backups got stuck. A failure raises a
     high alert.

   This is its own Firebase "codebase" (see ../firebase.json), so deploying it never touches
   the time clock's or the dispatch app's functions in the same project. */
'use strict';

const { onValueWritten, onValueCreated } = require('firebase-functions/v2/database');
const { onRequest } = require('firebase-functions/v2/https');
const { onSchedule } = require('firebase-functions/v2/scheduler');
const { onMessagePublished } = require('firebase-functions/v2/pubsub');
const { defineSecret } = require('firebase-functions/params');
const { beforeUserSignedIn, beforeEmailSent, beforeSmsSent } = require('firebase-functions/v2/identity');
const functionsV1 = require('firebase-functions/v1');
const logger = require('firebase-functions/logger');
const admin = require('firebase-admin');
const { ServerValue } = require('firebase-admin/database');
const { applicationDefault } = require('firebase-admin/app');
const { getStorage } = require('firebase-admin/storage');
const crypto = require('crypto');
const L = require('./lib');
const AT = require('./alert-types');
const BK = require('./backup');
const W = require('./watch');

admin.initializeApp();

// The default Realtime Database lives in us-central1; database triggers must run in the same region.
const REGION = 'us-central1';
const MEMORY = '256MiB';
const LOG = 'security_log';

const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;
const FAIL_WINDOW = 15 * MIN;        // failed sign-ins are counted in 15 minute windows
const FAIL_ALERT = 5;                // ... and this many from one email or IP raises an alert
const FAIL_ALERT_IP = 20;            // ... and this many from one IP raises a high alert
const REPORT_WINDOW = 10 * MIN;
const REPORT_LIMIT = 60;             // reports kept per IP per window (stops someone filling the log)
const DELETE_WINDOW = 5 * MIN;
const DELETE_ALERT = 10;             // deletes by one account in one window that raise an alert
const KEEP_EVENTS = 90 * DAY;
const KEEP_ALERTS = 365 * DAY;
const KEEP_COUNTERS = 2 * DAY;
const BLOCKING_BUDGET = 3000;        // ms; blocking functions must answer within 7 seconds

function db() { return admin.database(); }
function log(path) { return db().ref(LOG + '/' + path); }

/** Like Promise.race with a timer, so a slow database never holds up a sign-in. */
function within(ms, promise) {
  let timer;
  const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve('timeout'), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Writes an alert. src: what raised it (a watcher name, 'signin', 'census', ...). */
function raise(alert, src, at) {
  return log('alerts').push(Object.assign({ at: at || Date.now(), src }, alert, {
    title: L.clip(alert.title, 200), detail: L.clip(alert.detail, 600)
  }));
}

/** Adds one to a counter and returns the new count. */
async function count(path) {
  const res = await log('counters/' + path).transaction((n) => (n || 0) + 1);
  return res.snapshot.val() || 0;
}

/** How many times each function ran today, so the page can show what the watching costs, and
 * when it last ran (security_log/last), so auditHeartbeat can tell if one stopped. */
function tally(name, at) {
  return Promise.all([
    log('stats/' + L.dayKey(at) + '/' + name).set(ServerValue.increment(1)),
    log('last/' + name).set(at)
  ]);
}

// ---------------------------------------------------------------- failed and refused sign-ins

/** Counts a failed sign-in per email and per IP, and raises an alert once a count gets high. */
async function countFailure(entry) {
  const b = L.bucket(entry.at, FAIL_WINDOW);
  const jobs = [];
  if (entry.email) {
    jobs.push(count('failed_email/' + b + '/' + L.safeKey(entry.email)).then((n) => {
      if (n === FAIL_ALERT) {
        return raise({ type: 'failed_signins', level: L.ADMIN_EMAILS.includes(entry.email) || /@ec\.com$/.test(entry.email) ? 'high' : 'medium',
          title: 'Repeated failed sign-ins', detail: n + ' failed sign-ins for ' + entry.email + ' in 15 minutes (latest from ' + (entry.ip || 'unknown IP') + ', ' + entry.app + ').' }, 'signin', entry.at);
      }
    }));
  }
  if (entry.ip) {
    jobs.push(count('failed_ip/' + b + '/' + L.safeKey(entry.ip)).then((n) => {
      if (n === FAIL_ALERT || n === FAIL_ALERT_IP) {
        return raise({ type: 'failed_signins', level: n >= FAIL_ALERT_IP ? 'high' : 'medium', title: 'Many failed sign-ins from one place',
          detail: n + ' failed sign-ins from IP ' + entry.ip + ' in 15 minutes (latest for ' + (entry.email || 'no email') + ').' }, 'signin', entry.at);
      }
    }));
  }
  await Promise.all(jobs);
}

/** Adds the app to the sign-in row the token's sign-in made (see L.signInRowFor). */
async function nameSignInApp(token, report, at) {
  const authTime = (token.auth_time || 0) * 1000;
  if (!authTime || at - authTime > 15 * MIN) return;  // an old token: not a fresh sign-in
  const from = L.pushIdAt(Math.max(0, authTime - L.SIGNIN_MATCH));
  const snap = await log('events').orderByKey().startAt(from).endAt(L.pushIdAt(authTime + L.SIGNIN_MATCH) + '\uf8ff').once('value');
  const key = L.signInRowFor(snap.val(), token.uid, authTime);
  if (key) await log('events/' + key).update({ app: report.app, page: report.page });
}

exports.auditSignInReport = onRequest(
  { region: REGION, memory: MEMORY, invoker: 'public', cors: true, maxInstances: 5, concurrency: 40 },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).end(); return; }
    const at = Date.now();
    try {
      const raw = Buffer.isBuffer(req.rawBody) ? req.rawBody.toString('utf8') : typeof req.body === 'string' ? req.body : '';
      const report = L.parseReport(raw);
      if (!report) { res.status(400).end(); return; }
      const ip = L.requestIp(req);
      const n = await count('reports/' + L.bucket(at, REPORT_WINDOW) + '/' + L.safeKey(ip));
      if (n > REPORT_LIMIT) {
        if (n === REPORT_LIMIT + 1) {
          await raise({ type: 'report_flood', level: 'medium', title: 'Too many sign-in reports', detail: 'IP ' + ip + ' sent more than ' + REPORT_LIMIT + ' reports in 10 minutes; the rest are not logged.' }, 'signin', at);
        }
        res.status(204).end();
        return;
      }
      let token = null;
      let tokenError = null;
      if (report.idToken) {
        try { token = await admin.auth().verifyIdToken(report.idToken); } catch (e) { tokenError = e.code || 'invalid'; }
      }
      if (report.kind === 'signedin') {
        // Only a real token can name an app; the row stays as it was otherwise.
        if (token) await nameSignInApp(token, report, at);
        await tally('auditSignInReport', at);
        res.status(204).end();
        return;
      }
      const entry = L.reportEntry(report, { at, ip, ua: req.get('user-agent'), origin: req.get('origin'), token, tokenError });
      await log('events').push(entry);
      if (entry.type === 'signin_failed') await countFailure(entry);
      else if (entry.verified) {
        await raise({ type: 'refused', level: 'medium', title: 'Account refused by ' + entry.app,
          detail: (entry.email || entry.uid) + ' signed in to ' + entry.app + ' but was refused: ' + (entry.reason || entry.code || 'no reason given') + '.' }, 'signin', at);
      }
      await tally('auditSignInReport', at);
      res.status(204).end();
    } catch (e) {
      logger.error('Sign-in report not logged', e);
      res.status(500).end();
    }
  }
);

// ---------------------------------------------------------------- sign-ins that worked

async function logSignIn(event) {
  const at = Date.now();
  const entry = L.authEventEntry('signin', event, at);
  const jobs = [log('events').push(entry), tally('auditBeforeSignIn', at)];
  if (entry.uid) {
    const key = L.deviceKey(entry.ua);
    const devices = log('devices/' + entry.uid);
    jobs.push(devices.once('value').then((snap) => {
      const known = snap.child(key).exists();
      const write = devices.child(key).update({ first: known ? snap.child(key + '/first').val() : at, last: at,
        name: L.deviceName(entry.ua), ua: entry.ua, ip: entry.ip });
      // An account's first device isn't news; another one for a staff account might be.
      if (!known && snap.exists() && entry.staff) {
        return Promise.all([write, raise({ type: 'new_device', level: 'low', title: 'New device for ' + entry.email,
          detail: entry.email + ' signed in from ' + L.deviceName(entry.ua) + ' for the first time (IP ' + (entry.ip || 'unknown') + ').' }, 'signin', at)]);
      }
      return write;
    }));
    if (entry.staff && entry.ip) {
      const net = W.networkOf(entry.ip);
      const netKey = net ? L.safeKey(net) : null;
      const networks = log('networks/' + entry.uid);
      jobs.push(networks.once('value').then((snap) => {
        const odd = W.signInOddities(entry, snap.val(), netKey);
        return Promise.all([netKey ? networks.child(netKey).set(at) : null, ...odd.map((a) => raise(a, 'signin', at))]);
      }));
    }
  }
  await Promise.all(jobs);
}

exports.auditBeforeSignIn = beforeUserSignedIn({ region: REGION, memory: MEMORY }, async (event) => {
  try {
    if (await within(BLOCKING_BUDGET, logSignIn(event)) === 'timeout') logger.warn('Sign-in log slow; sign-in let through');
  } catch (e) {
    logger.error('Sign-in not logged; sign-in let through', e);
  }
});

async function logAuthMessage(type, event) {
  const at = Date.now();
  await Promise.all([log('events').push(L.authEventEntry(type, event, at)), tally(type, at)]);
}

exports.auditBeforeEmail = beforeEmailSent({ region: REGION, memory: MEMORY }, async (event) => {
  try { await within(BLOCKING_BUDGET, logAuthMessage('email_sent', event)); } catch (e) { logger.error('Email not logged', e); }
});

exports.auditBeforeSms = beforeSmsSent({ region: REGION, memory: MEMORY }, async (event) => {
  try { await within(BLOCKING_BUDGET, logAuthMessage('sms_sent', event)); } catch (e) { logger.error('SMS not logged', e); }
});

// ---------------------------------------------------------------- accounts made and removed

function userSummary(u) {
  return {
    email: L.clip(L.normEmail(u.email) || null, 200),
    phone: L.clip(u.phoneNumber || null, 32),
    uid: L.clip(u.uid, 128),
    provider: L.clip((u.providerData || []).map((p) => p.providerId).filter(Boolean).join(',') || null, 80)
  };
}

exports.auditUserCreated = functionsV1.region(REGION).runWith({ memory: '256MB' }).auth.user().onCreate(async (u) => {
  const at = Date.now();
  const s = userSummary(u);
  const staff = /@ec\.com$/.test(s.email || '');
  await Promise.all([
    log('events').push(Object.assign({ at, type: 'user_created', ok: true, staff }, s)),
    log('census/' + u.uid).set(L.censusOf(u)),
    staff ? raise({ type: 'new_staff', level: 'medium', title: 'New staff account', detail: s.email + ' was created (' + (s.provider || 'no sign-in method') + ').' }, 'accounts', at)
      : raise({ type: 'new_account', level: 'medium', title: 'New account: ' + (s.email || s.phone || s.uid), detail: (s.email || s.phone || s.uid) + ' made an account (' + (s.provider || 'no sign-in method') + '). Every account so far is @ec.com, so check who this is.' }, 'accounts', at),
    tally('auditUserCreated', at)
  ]);
});

exports.auditUserDeleted = functionsV1.region(REGION).runWith({ memory: '256MB' }).auth.user().onDelete(async (u) => {
  const at = Date.now();
  const s = userSummary(u);
  const staff = /@ec\.com$/.test(s.email || '');
  await Promise.all([
    log('events').push(Object.assign({ at, type: 'user_deleted', ok: true, staff }, s)),
    log('census/' + u.uid).remove(),
    log('devices/' + u.uid).remove(),
    log('networks/' + u.uid).remove(),
    raise({ type: 'account_deleted', level: staff ? 'high' : 'low', title: 'Account deleted', detail: (s.email || s.phone || s.uid) + ' was deleted.' }, 'accounts', at),
    tally('auditUserDeleted', at)
  ]);
});

/** Every account, compared with the last look. Catches changes no app made (console, admin tools, the REST API). */
exports.auditUserCensus = onSchedule({ schedule: 'every 30 minutes', region: REGION, memory: MEMORY, timeoutSeconds: 300 }, async () => {
  const at = Date.now();
  const before = (await log('census').once('value')).val() || {};
  const seen = new Set();
  const updates = {};
  const jobs = [];
  let pageToken;
  do {
    const page = await admin.auth().listUsers(1000, pageToken);
    for (const u of page.users) {
      seen.add(u.uid);
      const now = L.censusOf(u);
      const was = before[u.uid];
      updates[u.uid] = now;
      if (!was) continue;  // new accounts are logged by auditUserCreated
      const diff = L.censusDiff(was, now);
      if (!diff.length) continue;
      jobs.push(log('events').push({ at, type: 'account_changed', ok: true, uid: u.uid, email: now.email || was.email,
        changes: diff, staff: /@ec\.com$/.test(now.email || was.email || '') }));
      const level = L.censusAlertLevel(diff, now.email || was.email);
      if (level) {
        jobs.push(raise({ type: 'account_changed', level, title: 'Account changed: ' + (now.email || was.email || u.uid),
          detail: diff.map((d) => d.label + ': ' + (d.b == null ? 'none' : d.b) + ' → ' + (d.a == null ? 'none' : d.a)).join('; ') }, 'census', at));
      }
    }
    pageToken = page.pageToken;
  } while (pageToken);
  // Accounts gone since the last look, without auditUserDeleted having seen them
  for (const uid of Object.keys(before)) {
    if (seen.has(uid)) continue;
    updates[uid] = null;
    jobs.push(log('events').push({ at, type: 'user_deleted', ok: true, uid, email: before[uid].email || null, via: 'census' }));
  }
  await Promise.all(jobs);
  await log('census').update(updates);
  await tally('auditUserCensus', at);
  logger.info('Account census done', { accounts: seen.size, changes: jobs.length });
});

// ---------------------------------------------------------------- database changes

// Per-instance caches: who a uid is, and whether they're staff. Short-lived so a change shows up soon.
const CACHE_MS = 10 * MIN;
const people = new Map();

async function personOf(uid) {
  const hit = people.get(uid);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit;
  const [email, staff] = await Promise.all([
    admin.auth().getUser(uid).then((u) => L.normEmail(u.email) || null, () => null),
    db().ref('staff/' + uid).once('value').then((s) => s.val() === true, () => null)
  ]);
  const p = { at: Date.now(), email, staff };
  people.set(uid, p);
  return p;
}

function watcher(watch) {
  return onValueWritten({ ref: '/' + watch.path, region: REGION, memory: MEMORY, maxInstances: 10 }, async (event) => {
    const params = event.params || {};
    if (watch.skip && watch.skip.includes(params.section)) return;
    const at = Date.now();
    const person = event.authType === 'app_user' && event.authId ? await personOf(event.authId) : null;
    const entry = L.changeEntry({
      watch,
      path: watch.path.replace(/\{(\w+)\}/g, (m, k) => params[k]),
      before: event.data.before.val(),
      after: event.data.after.val(),
      authType: event.authType,
      authId: event.authId,
      email: person && person.email,
      at
    });
    if (entry.action === 'updated' && !entry.fields.length) return;  // written with the same value
    const jobs = [log('changes').push(entry), tally(watch.name, at)];
    const alerts = L.changeAlerts(entry, watch, { staff: person ? person.staff : null, adminEmail: !!(person && L.ADMIN_EMAILS.includes(person.email)) });
    const who = entry.by.email || entry.by.uid || (entry.by.type === 'admin' ? 'Server code or the console' : 'An unknown writer');
    const odd = W.suspiciousValues(event.data.before.val(), event.data.after.val());
    if (odd.length) {
      alerts.push({ type: 'injection', level: 'high', title: 'Possible code hidden in ' + watch.area,
        detail: who + ' saved ' + entry.path + ' with ' + odd.map((o) => o.why + ' in ' + o.f + (o.sample ? ': ' + JSON.stringify(o.sample) : '')).join('; ') });
    }
    if (watch.name === 'tcShifts') {
      alerts.push(...W.shiftAlerts({ before: event.data.before.val(), after: event.data.after.val(), path: entry.path, who,
        admin: entry.by.type === 'admin' || !!(person && L.ADMIN_EMAILS.includes(person.email)) }));
    }
    for (const a of alerts) jobs.push(raise(a, watch.name, at));
    if (entry.action === 'deleted') {
      // Per account; changes with no account (server code, the console) are counted together
      jobs.push(count('deletes/' + L.bucket(at, DELETE_WINDOW) + '/' + L.safeKey(entry.by.uid || entry.by.type)).then((n) => {
        if (n === DELETE_ALERT) {
          return raise({ type: 'many_deletes', level: 'high', title: 'Many deletes in a few minutes',
            detail: (entry.by.email || entry.by.uid || (entry.by.type === 'admin' ? 'Server code or the console' : 'An unknown writer')) + ' deleted ' + n + ' records within 5 minutes (latest: ' + entry.path + ').' }, watch.name, at);
        }
      }));
    }
    await Promise.all(jobs);
  });
}

for (const w of L.WATCHES) exports['audit' + w.name[0].toUpperCase() + w.name.slice(1)] = watcher(w);

// ---------------------------------------------------------------- other projects

// The same random value is stored as a secret in each project that sends here (see the README).
const PLUTOSCAN_AUDIT_KEY = defineSecret('PLUTOSCAN_AUDIT_KEY');
const INGEST_KEYS = { plutoscan: PLUTOSCAN_AUDIT_KEY };

// Trimmed because a key file made with `openssl rand -hex 32 > file` ends in a line break that
// the secret keeps but the sender's HTTP header drops.
function sameKey(given, expected) {
  const a = Buffer.from(String(given || '').trim());
  const b = Buffer.from(String(expected || '').trim());
  return a.length > 0 && b.length >= 32 && a.length === b.length && crypto.timingSafeEqual(a, b);
}

exports.auditIngest = onRequest(
  { region: REGION, memory: MEMORY, invoker: 'public', maxInstances: 5, concurrency: 40, secrets: [PLUTOSCAN_AUDIT_KEY] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).end(); return; }
    const at = Date.now();
    const app = String(req.get('x-audit-app') || '');
    const key = INGEST_KEYS[app];
    if (!key || !sameKey(req.get('x-audit-key'), key.value())) {
      // Someone guessing at the key: count it once per IP per window, and say so once.
      const ip = L.requestIp(req);
      const n = await count('ingest_refused/' + L.bucket(at, REPORT_WINDOW) + '/' + L.safeKey(ip)).catch(() => 0);
      if (n === 5) {
        await raise({ type: 'ingest_key', level: 'high', title: 'Wrong key sent to auditIngest', detail: 'IP ' + ip + ' sent ' + n + ' requests with a wrong or missing key in 10 minutes (app: ' + L.clip(app || 'none', 30) + ').' }, 'ingest', at).catch(() => {});
      }
      res.status(403).end();
      return;
    }
    try {
      const raw = Buffer.isBuffer(req.rawBody) ? req.rawBody.toString('utf8') : typeof req.body === 'string' ? req.body : JSON.stringify(req.body || null);
      const got = L.ingestEntry(raw, app, at);
      if (!got) { res.status(400).end(); return; }
      if (got.kind === 'census') await log('ext/' + app + '/census').update(got.set);
      else await log(got.kind).push(got.entry);
      await tally('auditIngest', at);
      res.status(204).end();
    } catch (e) {
      logger.error('Forwarded entry not logged', e);
      res.status(500).end();
    }
  }
);

// ---------------------------------------------------------------- phone notifications

// Must match ALERT_CHANNEL in index.html (the app makes the channel when it starts)
const PUSH_CHANNEL = 'security_alerts';
// Tokens FCM reports as gone for good (app uninstalled, data cleared, token replaced)
const DEAD_TOKEN_CODES = new Set(['messaging/registration-token-not-registered', 'messaging/invalid-registration-token']);
const LEVEL_NAMES = { high: 'High', medium: 'Medium', low: 'Low' };

/** Sends one notification to every phone in security_log/push_tokens. Returns how many got it. */
async function pushToPhones({ title, body, tag, data }) {
  const snap = await log('push_tokens').once('value');
  const phones = [];
  snap.forEach((c) => { const token = c.child('token').val(); if (typeof token === 'string' && token) phones.push({ key: c.key, token }); });
  if (!phones.length) { logger.info('No phones registered for security alerts'); return 0; }
  const res = await admin.messaging().sendEachForMulticast({
    tokens: phones.map((p) => p.token),
    notification: { title: L.clip(title, 120), body: L.clip(body, 400) },
    data,
    android: {
      priority: 'high',  // shown right away, even when the phone is dozing
      notification: { channelId: PUSH_CHANNEL, icon: 'ic_stat_usage', color: '#E8E400', tag, defaultSound: true }
    }
  });
  const dead = {};
  res.responses.forEach((r, i) => {
    if (r.success) return;
    const code = r.error && r.error.code;
    if (DEAD_TOKEN_CODES.has(code)) dead[phones[i].key] = null;
    else logger.warn('Push failed', { code, message: r.error && r.error.message });
  });
  if (Object.keys(dead).length) await log('push_tokens').update(dead);
  return res.successCount;
}

exports.auditAlertPush = onValueCreated({ ref: '/' + LOG + '/alerts/{id}', region: REGION, memory: MEMORY, maxInstances: 5 }, async (event) => {
  const alert = event.data.val() || {};
  const notify = (await log('notify').once('value')).val();
  if (!AT.wantsPush(alert, notify)) return;
  const at = Date.now();
  await pushToPhones({
    title: (LEVEL_NAMES[alert.level] ? LEVEL_NAMES[alert.level] + ': ' : '') + (alert.title || 'Security alert'),
    body: alert.detail || '',
    tag: 'alert-' + event.params.id,
    data: { alertId: String(event.params.id), type: AT.typeOf(alert) }
  });
  await tally('auditAlertPush', at);
});

// "Send a test notification" in the Alerts settings writes push_test
exports.auditTestPush = onValueWritten({ ref: '/' + LOG + '/push_test', region: REGION, memory: MEMORY, maxInstances: 2 }, async (event) => {
  if (!event.data.after.exists()) return;
  const at = Date.now();
  const sent = await pushToPhones({ title: 'Test notification', body: 'Security alerts will show up like this.', tag: 'test', data: { type: 'test' } });
  await Promise.all([log('push_test').set(null), log('push_result').set({ at, sent }), tally('auditTestPush', at)]);
});

// ---------------------------------------------------------------- upkeep

/** Deletes children of a push-id list older than `age`. Push ids sort by time, so this reads only the old ones. */
async function dropOlder(path, age, now) {
  const cutoff = L.pushIdAt(now - age);
  let total = 0;
  for (;;) {
    const snap = await log(path).orderByKey().endAt(cutoff).limitToFirst(500).once('value');
    if (!snap.exists()) return total;
    const updates = {};
    snap.forEach((c) => { updates[c.key] = null; });
    await log(path).update(updates);
    total += snap.numChildren();
    if (snap.numChildren() < 500) return total;
  }
}

exports.auditPrune = onSchedule({ schedule: 'every day 03:30', timeZone: 'America/Chicago', region: REGION, memory: MEMORY, timeoutSeconds: 540 }, async () => {
  const now = Date.now();
  const removed = {
    events: await dropOlder('events', KEEP_EVENTS, now),
    changes: await dropOlder('changes', KEEP_EVENTS, now),
    alerts: await dropOlder('alerts', KEEP_ALERTS, now)
  };
  // Acks for alerts that are gone
  const acks = (await log('acks').orderByKey().endAt(L.pushIdAt(now - KEEP_ALERTS)).once('value')).val() || {};
  if (Object.keys(acks).length) await log('acks').update(Object.fromEntries(Object.keys(acks).map((k) => [k, null])));
  // Counters are kept in time buckets (bucket = time / window); drop old buckets
  const counters = (await log('counters').once('value')).val() || {};
  const windows = { failed_email: FAIL_WINDOW, failed_ip: FAIL_WINDOW, reports: REPORT_WINDOW, deletes: DELETE_WINDOW, ingest_refused: REPORT_WINDOW, github_refused: REPORT_WINDOW, cloud: REPORT_WINDOW };
  const updates = {};
  for (const [kind, buckets] of Object.entries(counters)) {
    const ms = windows[kind];
    if (!ms) continue;
    for (const b of Object.keys(buckets || {})) if (Number(b) * ms < now - KEEP_COUNTERS) updates[kind + '/' + b] = null;
  }
  if (Object.keys(updates).length) await log('counters').update(updates);
  // Stats for a year
  const stats = (await log('stats').orderByKey().endAt(L.dayKey(now - 365 * DAY)).once('value')).val() || {};
  if (Object.keys(stats).length) await log('stats').update(Object.fromEntries(Object.keys(stats).map((k) => [k, null])));
  await tally('auditPrune', now);
  logger.info('Security log pruned', removed);
});

// ---------------------------------------------------------------- daily backup

// 7:00 PM in Brandon, after the working day. The function's service account needs
// Storage Object Creator on the bucket (README, "Daily backup").
exports.auditBackup = onSchedule({ schedule: 'every day 19:00', timeZone: 'America/Winnipeg', region: REGION, memory: MEMORY, timeoutSeconds: 300 }, async () => {
  const at = Date.now();
  const dbUrl = db().ref().toString().replace(/\/$/, '');
  try {
    const res = await BK.makeBackup({
      readData: async () => (await db().ref().once('value')).val(),
      readRules: async () => {
        const { access_token: token } = await applicationDefault().getAccessToken();
        const r = await fetch(dbUrl + '/.settings/rules.json', { headers: { Authorization: 'Bearer ' + token } });
        if (!r.ok) throw new Error('rules download: HTTP ' + r.status);
        return r.text();
      },
      save: (name, buf) => getStorage().bucket(BK.BUCKET).file(name).save(buf, { resumable: false, contentType: 'application/gzip' })
    }, at);
    await tally('auditBackup', at);
    logger.info('Database backed up', res);
  } catch (err) {
    logger.error('Database backup failed', { message: err && err.message });
    await raise({ type: 'backup_failed', level: 'high', title: 'Daily database backup failed', detail: String((err && err.message) || err) }, 'backup', at);
    throw err;
  }
});

// ---------------------------------------------------------------- extra watches (see watch.js)

function projectId() {
  try { return JSON.parse(process.env.FIREBASE_CONFIG || '{}').projectId || process.env.GCLOUD_PROJECT; } catch (e) { return process.env.GCLOUD_PROJECT; }
}
let projectNumberCache = null;
/** The project's number, from the metadata server (names the Google-managed deploy accounts). */
async function projectNumber() {
  if (projectNumberCache) return projectNumberCache;
  try {
    const r = await fetch('http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id', { headers: { 'Metadata-Flavor': 'Google' } });
    if (r.ok) projectNumberCache = (await r.text()).trim();
  } catch (e) { logger.warn('Project number unknown', { message: e.message }); }
  return projectNumberCache || '';
}
async function googleToken() { return (await applicationDefault().getAccessToken()).access_token; }

/** The live database rules, as text. */
async function readRules() {
  const dbUrl = db().ref().toString().replace(/\/$/, '');
  const r = await fetch(dbUrl + '/.settings/rules.json', { headers: { Authorization: 'Bearer ' + await googleToken() } });
  if (!r.ok) throw new Error('rules download: HTTP ' + r.status);
  return r.text();
}

// Every hour: the rules compared with the last copy (security_log/rules_watch). The rules live only
// in the Firebase console, so this is the only way to know they were changed, by whom is in the
// Google Cloud alerts if the log sink is set up.
exports.auditRulesCheck = onSchedule({ schedule: 'every 60 minutes', region: REGION, memory: MEMORY, timeoutSeconds: 120 }, async () => {
  const at = Date.now();
  const text = await readRules();
  const h = L.hash(text);
  const ref = log('rules_watch');
  const was = (await ref.once('value')).val();
  if (was && was.hash !== h) {
    const diff = W.rulesDiff(was.text, text);
    const opened = W.rulesLoosened(diff.changes);
    const list = diff.changes.slice(0, 8).map((c) => c.path + (c.a == null ? ' (removed)' : c.b == null ? ' (added)' : '')).join(', ');
    await Promise.all([
      raise({ type: 'rules_changed', level: opened.length || !diff.parsed ? 'high' : 'medium',
        title: opened.length ? 'Database rules opened up' : 'Database rules changed',
        detail: (diff.parsed ? diff.changes.length + (diff.changes.length >= 15 ? '+' : '') + ' rule(s) changed: ' + list : 'The rules text changed (could not compare it rule by rule).') +
          (opened.length ? ' Opened: ' + opened.map((c) => c.path + ' = ' + (c.a == null ? 'removed' : c.a)).join(', ') + '.' : '') +
          ' The old copy is in security_log/rules_watch/previous.' }, 'rules', at),
      log('changes').push({ at, area: 'Database rules', watch: 'rules', path: '.settings/rules', action: 'updated',
        by: { type: 'console', uid: null }, fields: diff.changes.slice(0, 40).map((c) => ({ f: c.path, b: c.b, a: c.a })), n: diff.changes.length, before: null, after: null })
    ]);
  }
  if (!was || was.hash !== h) {
    await ref.set({ hash: h, at, text, size: text.length, previous: was ? { hash: was.hash, at: was.at, text: was.text } : null });
  }
  await tally('auditRulesCheck', at);
});

// Every hour: how much was downloaded from the database in the last full hour (Cloud Monitoring,
// firebasedatabase.googleapis.com/network/sent_bytes_count), compared with the hours before
// (security_log/usage, kept 8 days). The functions' service account needs Monitoring Viewer (README).
exports.auditUsageCheck = onSchedule({ schedule: 'every 60 minutes', region: REGION, memory: MEMORY, timeoutSeconds: 120 }, async () => {
  const at = Date.now();
  const end = Math.floor((at - 10 * MIN) / W.HOUR) * W.HOUR;  // the last full hour, after the metric's delay
  const start = end - W.HOUR;
  const q = new URLSearchParams({
    filter: 'metric.type="firebasedatabase.googleapis.com/network/sent_bytes_count"',
    'interval.startTime': new Date(start).toISOString(),
    'interval.endTime': new Date(end).toISOString(),
    'aggregation.alignmentPeriod': '3600s',
    'aggregation.perSeriesAligner': 'ALIGN_SUM',
    'aggregation.crossSeriesReducer': 'REDUCE_SUM'
  });
  const r = await fetch('https://monitoring.googleapis.com/v3/projects/' + projectId() + '/timeSeries?' + q, { headers: { Authorization: 'Bearer ' + await googleToken() } });
  if (!r.ok) throw new Error('Cloud Monitoring: HTTP ' + r.status + ' ' + (await r.text()).slice(0, 200));
  const body = await r.json();
  let bytes = 0;
  for (const ts of body.timeSeries || []) for (const p of ts.points || []) bytes += Number(p.value && (p.value.int64Value || p.value.doubleValue)) || 0;
  const key = String(start);
  const usage = log('usage');
  const past = (await usage.orderByKey().startAt(String(start - 8 * W.DAY)).once('value')).val() || {};
  delete past[key];
  const spike = (await log('usage_alerted/' + key).once('value')).exists() ? null : W.usageSpike(bytes, Object.values(past));
  const old = Object.keys(past).filter((k) => Number(k) < start - 8 * W.DAY);
  await Promise.all([
    usage.child(key).set(bytes),
    old.length ? usage.update(Object.fromEntries(old.map((k) => [k, null]))) : null,
    spike ? raise(spike, 'usage', at) : null,
    spike ? log('usage_alerted/' + key).set(true) : null
  ]);
  await tally('auditUsageCheck', at);
});

// Google Cloud Admin Activity audit logs, sent by the log sink "security-cloud-log" to this topic
// (README, "Google Cloud alerts"). Firebase's own deploy accounts are routine, one level lower.
const CLOUD_TOPIC = 'security-cloud-log';
exports.auditCloudLog = onMessagePublished({ topic: CLOUD_TOPIC, region: REGION, memory: MEMORY, maxInstances: 3 }, async (event) => {
  const at = Date.now();
  const entry = event.data && event.data.message && event.data.message.json;
  const pn = await projectNumber();
  const routine = [pn && pn + '-compute@developer.gserviceaccount.com', pn && 'service-' + pn + '@gcf-admin-robot.iam.gserviceaccount.com',
    pn && pn + '@cloudbuild.gserviceaccount.com', pn && pn + '@cloudservices.gserviceaccount.com'].filter(Boolean);
  const found = W.cloudLogAlert(entry, routine);
  if (found) {
    const { who, method, resource, ...alert } = found;
    // Every one is listed under Changes; a deploy makes dozens, so one alert per kind per account per 10 minutes.
    const jobs = [log('changes').push({ at, area: 'Google Cloud', watch: 'cloud', path: L.clip(resource || method, 300), action: 'updated',
      by: { type: 'google', uid: null, email: who }, fields: [{ f: 'method', b: null, a: method }], n: 1, before: null, after: null })];
    const n = await count('cloud/' + L.bucket(at, REPORT_WINDOW) + '/' + L.safeKey(alert.type + '_' + alert.level + '_' + who));
    if (n === 1) jobs.push(raise(Object.assign(alert, { detail: alert.detail + ' Further changes like this by the same account in the next 10 minutes are listed under Changes only.' }), 'cloud', at));
    await Promise.all(jobs);
  }
  await tally('auditCloudLog', at);
});

// Budget notifications from Billing → Budgets & alerts, sent to this topic (README, "Spending budget").
const BUDGET_TOPIC = 'security-budget';
exports.auditBudget = onMessagePublished({ topic: BUDGET_TOPIC, region: REGION, memory: MEMORY, maxInstances: 2 }, async (event) => {
  const at = Date.now();
  const msg = event.data && event.data.message && event.data.message.json;
  if (!msg) return;
  const month = L.safeKey(String(msg.costIntervalStart || L.dayKey(at).slice(0, 7)).slice(0, 10));
  const ref = log('budget/' + L.safeKey((event.data.message.attributes || {}).budgetId || 'budget') + '/' + month);
  let got = null;
  await ref.transaction((last) => {
    got = W.budgetAlert(msg, last);
    return got ? got.step : undefined;  // undefined: leave it as it is
  });
  if (got) await raise(got.alert, 'budget', at);
  await tally('auditBudget', at);
});

// GitHub webhooks from each repository (README, "GitHub alerts"), signed with this secret.
const GITHUB_WEBHOOK_SECRET = defineSecret('GITHUB_WEBHOOK_SECRET');
exports.auditGitHub = onRequest(
  { region: REGION, memory: MEMORY, invoker: 'public', maxInstances: 3, concurrency: 20, secrets: [GITHUB_WEBHOOK_SECRET] },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).end(); return; }
    const at = Date.now();
    const raw = Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.from('');
    const sig = String(req.get('x-hub-signature-256') || '');
    const want = 'sha256=' + crypto.createHmac('sha256', String(GITHUB_WEBHOOK_SECRET.value() || '').trim()).update(raw).digest('hex');
    if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) {
      const ip = L.requestIp(req);
      const n = await count('github_refused/' + L.bucket(at, REPORT_WINDOW) + '/' + L.safeKey(ip)).catch(() => 0);
      if (n === 5) {
        await raise({ type: 'ingest_key', level: 'high', title: 'Fake GitHub messages', detail: 'IP ' + ip + ' sent ' + n + ' unsigned or wrongly signed GitHub messages in 10 minutes.' }, 'github', at).catch(() => {});
      }
      res.status(403).end();
      return;
    }
    try {
      const event = String(req.get('x-github-event') || '');
      if (event === 'ping') { await tally('auditGitHub', at); res.status(204).end(); return; }
      const alert = W.githubAlert(event, JSON.parse(raw.toString('utf8')));
      if (alert) await raise(alert, 'github', at);
      await tally('auditGitHub', at);
      res.status(204).end();
    } catch (e) {
      logger.error('GitHub message not logged', e);
      res.status(500).end();
    }
  }
);

// Every morning at 8: checks every scheduled watcher ran when it should have. All fine sends the
// "all OK" notification (alert kind heartbeat in the Alerts settings); a stopped one raises a high alert.
exports.auditHeartbeat = onSchedule({ schedule: 'every day 08:00', timeZone: 'America/Winnipeg', region: REGION, memory: MEMORY, timeoutSeconds: 120 }, async () => {
  const at = Date.now();
  const [last, notify, alerts] = await Promise.all([
    log('last').once('value').then((s) => s.val() || {}),
    log('notify').once('value').then((s) => s.val()),
    log('alerts').orderByKey().startAt(L.pushIdAt(at - W.DAY)).once('value').then((s) => s.val() || {})
  ]);
  const problems = W.heartbeatProblems(last, at);
  const open = Object.values(alerts).filter((a) => a && a.level === 'high').length;
  await log('heartbeat').set({ at, ok: !problems.length, problems, highAlerts24h: open });
  if (problems.length) {
    await raise({ type: 'watch_stopped', level: 'high', title: problems.length + ' watcher(s) stopped running',
      detail: problems.map((p) => p.name + ' (last ran ' + (p.last ? new Date(p.last).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : 'never') + ')').join(', ') + '. Check Functions → Logs in the Firebase console.' }, 'heartbeat', at);
  } else if (AT.wantsPush({ type: 'heartbeat' }, notify)) {
    await pushToPhones({ title: 'Security: all OK', body: 'Every watcher ran, and last night’s backup saved.' + (open ? ' ' + open + ' high alert(s) in the last 24 hours.' : ' No high alerts in the last 24 hours.'),
      tag: 'heartbeat', data: { type: 'heartbeat' } });
  }
  await tally('auditHeartbeat', at);
});
