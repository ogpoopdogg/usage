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

   Upkeep
   - auditPrune (daily): drops events and changes after 90 days, alerts after a year.

   This is its own Firebase "codebase" (see ../firebase.json), so deploying it never touches
   the time clock's or the dispatch app's functions in the same project. */
'use strict';

const { onValueWritten } = require('firebase-functions/v2/database');
const { onRequest } = require('firebase-functions/v2/https');
const { onSchedule } = require('firebase-functions/v2/scheduler');
const { defineSecret } = require('firebase-functions/params');
const { beforeUserSignedIn, beforeEmailSent, beforeSmsSent } = require('firebase-functions/v2/identity');
const functionsV1 = require('firebase-functions/v1');
const logger = require('firebase-functions/logger');
const admin = require('firebase-admin');
const { ServerValue } = require('firebase-admin/database');
const crypto = require('crypto');
const L = require('./lib');

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

/** How many times each function ran today, so the page can show what the watching costs. */
function tally(name, at) {
  return log('stats/' + L.dayKey(at) + '/' + name).set(ServerValue.increment(1));
}

// ---------------------------------------------------------------- failed and refused sign-ins

/** Counts a failed sign-in per email and per IP, and raises an alert once a count gets high. */
async function countFailure(entry) {
  const b = L.bucket(entry.at, FAIL_WINDOW);
  const jobs = [];
  if (entry.email) {
    jobs.push(count('failed_email/' + b + '/' + L.safeKey(entry.email)).then((n) => {
      if (n === FAIL_ALERT) {
        return raise({ level: L.ADMIN_EMAILS.includes(entry.email) || /@ec\.com$/.test(entry.email) ? 'high' : 'medium',
          title: 'Repeated failed sign-ins', detail: n + ' failed sign-ins for ' + entry.email + ' in 15 minutes (latest from ' + (entry.ip || 'unknown IP') + ', ' + entry.app + ').' }, 'signin', entry.at);
      }
    }));
  }
  if (entry.ip) {
    jobs.push(count('failed_ip/' + b + '/' + L.safeKey(entry.ip)).then((n) => {
      if (n === FAIL_ALERT || n === FAIL_ALERT_IP) {
        return raise({ level: n >= FAIL_ALERT_IP ? 'high' : 'medium', title: 'Many failed sign-ins from one place',
          detail: n + ' failed sign-ins from IP ' + entry.ip + ' in 15 minutes (latest for ' + (entry.email || 'no email') + ').' }, 'signin', entry.at);
      }
    }));
  }
  await Promise.all(jobs);
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
          await raise({ level: 'medium', title: 'Too many sign-in reports', detail: 'IP ' + ip + ' sent more than ' + REPORT_LIMIT + ' reports in 10 minutes; the rest are not logged.' }, 'signin', at);
        }
        res.status(204).end();
        return;
      }
      let token = null;
      let tokenError = null;
      if (report.idToken) {
        try { token = await admin.auth().verifyIdToken(report.idToken); } catch (e) { tokenError = e.code || 'invalid'; }
      }
      const entry = L.reportEntry(report, { at, ip, ua: req.get('user-agent'), origin: req.get('origin'), token, tokenError });
      await log('events').push(entry);
      if (entry.type === 'signin_failed') await countFailure(entry);
      else if (entry.verified) {
        await raise({ level: 'medium', title: 'Account refused by ' + entry.app,
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
        return Promise.all([write, raise({ level: 'low', title: 'New device for ' + entry.email,
          detail: entry.email + ' signed in from ' + L.deviceName(entry.ua) + ' for the first time (IP ' + (entry.ip || 'unknown') + ').' }, 'signin', at)]);
      }
      return write;
    }));
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
    staff ? raise({ level: 'medium', title: 'New staff account', detail: s.email + ' was created (' + (s.provider || 'no sign-in method') + ').' }, 'accounts', at) : null,
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
    raise({ level: staff ? 'high' : 'low', title: 'Account deleted', detail: (s.email || s.phone || s.uid) + ' was deleted.' }, 'accounts', at),
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
        jobs.push(raise({ level, title: 'Account changed: ' + (now.email || was.email || u.uid),
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
    for (const a of alerts) jobs.push(raise(a, watch.name, at));
    if (entry.action === 'deleted') {
      // Per account; changes with no account (server code, the console) are counted together
      jobs.push(count('deletes/' + L.bucket(at, DELETE_WINDOW) + '/' + L.safeKey(entry.by.uid || entry.by.type)).then((n) => {
        if (n === DELETE_ALERT) {
          return raise({ level: 'high', title: 'Many deletes in a few minutes',
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

function sameKey(given, expected) {
  const a = Buffer.from(String(given || ''));
  const b = Buffer.from(String(expected || ''));
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
        await raise({ level: 'high', title: 'Wrong key sent to auditIngest', detail: 'IP ' + ip + ' sent ' + n + ' requests with a wrong or missing key in 10 minutes (app: ' + L.clip(app || 'none', 30) + ').' }, 'ingest', at).catch(() => {});
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
  const windows = { failed_email: FAIL_WINDOW, failed_ip: FAIL_WINDOW, reports: REPORT_WINDOW, deletes: DELETE_WINDOW, ingest_refused: REPORT_WINDOW };
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
  logger.info('Security log pruned', removed);
});
