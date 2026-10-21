/* PlutoScan security log – runs in the `plutoscan` Firebase project and sends everything it logs
   to the Security tab of the E&C usage page (auditIngest in the eandccourier-36fcc project).

   Nothing here ever refuses or changes anything: a fault in this code must never stop anyone
   signing up, signing in, paying or using the course. Each entry is written to this project's
   own security_log first (the backup), then sent on.

   Accounts and sign-ins
   - auditPlutoSignUp: every new account, with its IP address, browser and sign-in method.
   - auditPlutoSignIn: every successful sign-in (email and password, or Google).
   - auditPlutoEmail: password reset emails.
   - auditPlutoUserCreated / auditPlutoUserDeleted: every account made or removed, including in
     the Firebase console (the blocking functions don't see those).
   - auditPlutoCensus (every 30 minutes): every account with its paid flag, compared with the
     last look; also sends again anything the E&C log didn't take.

   Purchases and account data
   - auditPlutoUsers: every write to users/{uid}. The paid flag turning on is a purchase. Alerts
     for paid set by anyone but server code, writes to someone else's account, writes with no
     sign-in, unexpected fields, and deletes.

   What the site reports (it sends these; Firebase runs no server code for them)
   - auditPlutoReport: failed sign-ins, the course page turning someone away (not signed in or not
     paid), the checkout steps, and page visits.

   Upkeep
   - auditPlutoPrune (daily): drops this project's copies after 90 days.

   This is its own codebase (`audit`, see ../firebase.json), so deploying it never touches
   createCheckoutSession, getModuleContent or stripeWebhook. */
'use strict';

const { onValueWritten } = require('firebase-functions/v2/database');
const { onRequest } = require('firebase-functions/v2/https');
const { onSchedule } = require('firebase-functions/v2/scheduler');
const { beforeUserCreated, beforeUserSignedIn, beforeEmailSent } = require('firebase-functions/v2/identity');
const { defineSecret } = require('firebase-functions/params');
const functionsV1 = require('firebase-functions/v1');
const logger = require('firebase-functions/logger');
const admin = require('firebase-admin');
const { ServerValue } = require('firebase-admin/database');
const L = require('./lib');

admin.initializeApp();

const REGION = 'us-central1';
const MEMORY = '256MiB';
const LOG = 'security_log';
// AUDIT_INGEST_URL is only for trying this out in the emulators.
const INGEST_URL = process.env.AUDIT_INGEST_URL || 'https://us-central1-eandccourier-36fcc.cloudfunctions.net/auditIngest';
// The same random value is stored as a secret in eandccourier-36fcc (see the README).
const KEY = defineSecret('PLUTOSCAN_AUDIT_KEY');
const SITE = ['https://plutoscan.com', 'https://www.plutoscan.com', 'https://pluto-scan.github.io'];

const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;
const FAIL_WINDOW = 15 * MIN;
const FAIL_ALERT = 5;                // failed sign-ins for one email, or from one IP, in 15 minutes
const FAIL_ALERT_IP = 20;
const DENIED_ALERT = 10;             // times one IP is turned away from the course in 15 minutes
const REPORT_WINDOW = 10 * MIN;
const REPORT_LIMIT = 60;             // reports kept per IP per window
const KEEP = 90 * DAY;
const KEEP_COUNTERS = 2 * DAY;
const BLOCKING_BUDGET = 3000;        // ms; blocking functions must answer within 7 seconds
const SEND_TIMEOUT = 2500;

function db() { return admin.database(); }
function log(path) { return db().ref(LOG + '/' + path); }

function within(ms, promise) {
  let timer;
  const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve('timeout'), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ---------------------------------------------------------------- sending to the E&C log

/** Posts one body to auditIngest. Resolves true if it was taken. */
async function post(body) {
  try {
    const res = await fetch(INGEST_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-audit-app': 'plutoscan', 'x-audit-key': KEY.value() },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(SEND_TIMEOUT)
    });
    if (res.status === 204) return true;
    logger.warn('auditIngest refused an entry', { status: res.status });
    return false;
  } catch (e) {
    logger.warn('auditIngest not reached', { error: String(e && e.message || e) });
    return false;
  }
}

/** Sends a body on, and keeps it in unsent/ to try again if the E&C log didn't take it. */
async function send(body) {
  if (!(await post(body))) await log('unsent').push({ at: Date.now(), body: JSON.stringify(body) });
}

/** Writes an entry to this project's log and sends it on. kind: events | changes | alerts */
async function record(kind, entry) {
  await log(kind).push(entry);
  await send({ kind, entry });
}

function raise(alert, src, at) {
  return record('alerts', Object.assign({ at: at || Date.now(), src }, alert, {
    title: L.clip(alert.title, 200), detail: L.clip(alert.detail, 600)
  }));
}

async function count(path) {
  const res = await log('counters/' + path).transaction((n) => (n || 0) + 1);
  return res.snapshot.val() || 0;
}

function tally(name, at) {
  return log('stats/' + L.dayKey(at) + '/' + name).set(ServerValue.increment(1));
}

// ---------------------------------------------------------------- accounts and sign-ins

async function logAuth(type, event, name) {
  const at = Date.now();
  await Promise.all([record('events', L.authEventEntry(type, event, at)), tally(name, at)]);
}

/** Runs a blocking function's logging within its time budget; never throws, never blocks. */
async function quietly(what, job) {
  try {
    if (await within(BLOCKING_BUDGET, job) === 'timeout') logger.warn(what + ' log slow; let through');
  } catch (e) {
    logger.error(what + ' not logged; let through', e);
  }
}

exports.auditPlutoSignUp = beforeUserCreated({ region: REGION, memory: MEMORY, secrets: [KEY] }, async (event) => {
  await quietly('Sign-up', logAuth('signup', event, 'auditPlutoSignUp'));
});

exports.auditPlutoSignIn = beforeUserSignedIn({ region: REGION, memory: MEMORY, secrets: [KEY] }, async (event) => {
  await quietly('Sign-in', logAuth('signin', event, 'auditPlutoSignIn'));
});

exports.auditPlutoEmail = beforeEmailSent({ region: REGION, memory: MEMORY, secrets: [KEY] }, async (event) => {
  await quietly('Email', logAuth('email_sent', event, 'auditPlutoEmail'));
});

function userSummary(u) {
  return {
    email: L.clip(L.normEmail(u.email) || null, 200),
    uid: L.clip(u.uid, 128),
    provider: L.clip((u.providerData || []).map((p) => p.providerId).filter(Boolean).join(',') || null, 80)
  };
}

exports.auditPlutoUserCreated = functionsV1.region(REGION).runWith({ memory: '256MB', secrets: ['PLUTOSCAN_AUDIT_KEY'] }).auth.user().onCreate(async (u) => {
  const at = Date.now();
  const rec = L.censusOf(u, false);
  await Promise.all([
    record('events', Object.assign({ at, type: 'user_created', ok: true }, userSummary(u))),
    log('census/' + u.uid).set(rec),
    send({ kind: 'census', set: { [u.uid]: rec } }),
    tally('auditPlutoUserCreated', at)
  ]);
});

exports.auditPlutoUserDeleted = functionsV1.region(REGION).runWith({ memory: '256MB', secrets: ['PLUTOSCAN_AUDIT_KEY'] }).auth.user().onDelete(async (u) => {
  const at = Date.now();
  const s = userSummary(u);
  await Promise.all([
    record('events', Object.assign({ at, type: 'user_deleted', ok: true }, s)),
    log('census/' + u.uid).remove(),
    send({ kind: 'census', set: { [u.uid]: null } }),
    raise({ level: 'low', title: 'Account deleted', detail: (s.email || s.uid) + ' was deleted.' }, 'accounts', at),
    tally('auditPlutoUserDeleted', at)
  ]);
});

/** Sends again what the E&C log didn't take, oldest first. */
async function resend() {
  const snap = await log('unsent').orderByKey().limitToFirst(200).once('value');
  let sent = 0;
  for (const [id, item] of Object.entries(snap.val() || {})) {
    let body = null;
    try { body = JSON.parse(item.body); } catch (e) { /* dropped below */ }
    if (body && !(await post(body))) break;  // still down; try next time
    await log('unsent/' + id).remove();
    sent++;
  }
  return sent;
}

exports.auditPlutoCensus = onSchedule({ schedule: 'every 30 minutes', region: REGION, memory: MEMORY, timeoutSeconds: 300, secrets: [KEY] }, async () => {
  const at = Date.now();
  const resent = await resend();
  const before = (await log('census').once('value')).val() || {};
  const seen = new Set();
  const updates = {};
  const forward = {};
  const jobs = [];
  let pageToken;
  do {
    const page = await admin.auth().listUsers(1000, pageToken);
    const paid = await Promise.all(page.users.map((u) => db().ref('users/' + u.uid + '/paid').once('value').then((s) => s.val(), () => null)));
    page.users.forEach((u, i) => {
      seen.add(u.uid);
      const now = L.censusOf(u, paid[i]);
      const was = before[u.uid];
      updates[u.uid] = now;
      if (L.censusChanged(was, now)) forward[u.uid] = now;
      if (!was) return;  // new accounts are logged by auditPlutoUserCreated
      const diff = L.censusDiff(was, now);
      if (!diff.length) return;
      jobs.push(record('events', { at, type: 'account_changed', ok: true, uid: u.uid, email: now.email || was.email, changes: diff }));
      const level = L.censusAlertLevel(diff);
      if (level) {
        jobs.push(raise({ level, title: 'Account changed: ' + (now.email || was.email || u.uid),
          detail: diff.map((d) => d.label + ': ' + (d.b == null ? 'none' : d.b) + ' → ' + (d.a == null ? 'none' : d.a)).join('; ') }, 'census', at));
      }
    });
    pageToken = page.pageToken;
  } while (pageToken);
  for (const uid of Object.keys(before)) {
    if (seen.has(uid)) continue;
    updates[uid] = null;
    forward[uid] = null;
    jobs.push(record('events', { at, type: 'user_deleted', ok: true, uid, email: before[uid].email || null, via: 'census' }));
  }
  await Promise.all(jobs);
  await log('census').update(updates);
  const uids = Object.keys(forward);
  for (let i = 0; i < uids.length; i += 200) {
    await send({ kind: 'census', set: Object.fromEntries(uids.slice(i, i + 200).map((k) => [k, forward[k]])) });
  }
  await tally('auditPlutoCensus', at);
  logger.info('PlutoScan account census done', { accounts: seen.size, sentOn: uids.length, resent });
});

// ---------------------------------------------------------------- users/{uid}

const CACHE_MS = 10 * MIN;
const emails = new Map();

async function emailOf(uid) {
  const hit = emails.get(uid);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.email;
  const email = await admin.auth().getUser(uid).then((u) => L.normEmail(u.email) || null, () => null);
  emails.set(uid, { at: Date.now(), email });
  return email;
}

exports.auditPlutoUsers = onValueWritten({ ref: '/users/{uid}', region: REGION, memory: MEMORY, maxInstances: 10, secrets: [KEY] }, async (event) => {
  const uid = event.params.uid;
  const at = Date.now();
  const who = { type: event.authType, uid: event.authId || null };
  if (who.type === 'app_user' && who.uid) who.email = await emailOf(who.uid);
  const got = L.userChange({ uid, before: event.data.before.val(), after: event.data.after.val(), who, at });
  if (got.entry.action === 'updated' && !got.entry.fields.length) return;
  const owner = await emailOf(uid);
  const jobs = [record('changes', got.entry), tally('auditPlutoUsers', at)];
  for (const e of got.events) jobs.push(record('events', Object.assign(e, { email: owner })));
  for (const a of got.alerts) jobs.push(raise(Object.assign(a, { detail: owner ? a.detail.split(uid).join(owner) : a.detail }), 'users', at));
  await Promise.all(jobs);
});

// ---------------------------------------------------------------- reports from the site

async function countReport(entry) {
  const b = L.bucket(entry.at, FAIL_WINDOW);
  const jobs = [];
  if (entry.type === 'signin_failed' && entry.email) {
    jobs.push(count('failed_email/' + b + '/' + L.safeKey(entry.email)).then((n) => n === FAIL_ALERT && raise({ level: 'medium',
      title: 'Repeated failed sign-ins', detail: n + ' failed sign-ins for ' + entry.email + ' in 15 minutes (latest from ' + (entry.ip || 'unknown IP') + ').' }, 'signin', entry.at)));
  }
  if (entry.type === 'signin_failed' && entry.ip) {
    jobs.push(count('failed_ip/' + b + '/' + L.safeKey(entry.ip)).then((n) => (n === FAIL_ALERT || n === FAIL_ALERT_IP) && raise({ level: n >= FAIL_ALERT_IP ? 'high' : 'medium',
      title: 'Many failed sign-ins from one place', detail: n + ' failed sign-ins from IP ' + entry.ip + ' in 15 minutes (latest for ' + (entry.email || 'no email') + ').' }, 'signin', entry.at)));
  }
  if (entry.type === 'course_denied' && entry.ip) {
    jobs.push(count('denied_ip/' + b + '/' + L.safeKey(entry.ip)).then((n) => n === DENIED_ALERT && raise({ level: 'medium',
      title: 'Repeated attempts to open the course', detail: 'IP ' + entry.ip + ' was turned away from the course ' + n + ' times in 15 minutes (latest: ' + (entry.reason || 'no reason') + ', ' + (entry.email || 'not signed in') + ').' }, 'course', entry.at)));
  }
  await Promise.all(jobs);
}

exports.auditPlutoReport = onRequest(
  { region: REGION, memory: MEMORY, invoker: 'public', cors: SITE, maxInstances: 5, concurrency: 40, secrets: [KEY] },
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
          await raise({ level: 'medium', title: 'Too many reports from one place', detail: 'IP ' + ip + ' sent more than ' + REPORT_LIMIT + ' reports in 10 minutes; the rest are not logged.' }, 'report', at);
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
      await record('events', entry);
      await countReport(entry);
      await tally('auditPlutoReport', at);
      res.status(204).end();
    } catch (e) {
      logger.error('Report not logged', e);
      res.status(500).end();
    }
  }
);

// ---------------------------------------------------------------- upkeep

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

exports.auditPlutoPrune = onSchedule({ schedule: 'every day 03:45', timeZone: 'America/Chicago', region: REGION, memory: MEMORY, timeoutSeconds: 540 }, async () => {
  const now = Date.now();
  const removed = {};
  for (const path of ['events', 'changes', 'alerts', 'unsent']) removed[path] = await dropOlder(path, KEEP, now);
  const counters = (await log('counters').once('value')).val() || {};
  const windows = { failed_email: FAIL_WINDOW, failed_ip: FAIL_WINDOW, denied_ip: FAIL_WINDOW, reports: REPORT_WINDOW };
  const updates = {};
  for (const [kind, buckets] of Object.entries(counters)) {
    const ms = windows[kind];
    if (!ms) continue;
    for (const b of Object.keys(buckets || {})) if (Number(b) * ms < now - KEEP_COUNTERS) updates[kind + '/' + b] = null;
  }
  if (Object.keys(updates).length) await log('counters').update(updates);
  const stats = (await log('stats').orderByKey().endAt(L.dayKey(now - 365 * DAY)).once('value')).val() || {};
  if (Object.keys(stats).length) await log('stats').update(Object.fromEntries(Object.keys(stats).map((k) => [k, null])));
  logger.info('PlutoScan security log pruned', removed);
});
