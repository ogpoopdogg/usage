/* PlutoScan security log – the parts that don't need Firebase, so they can be tested with `node --test`.

   Layout of security_log in the plutoscan database (server code only; the database rules give
   nobody access, and the admin SDK used here ignores rules):
     events/{id}      { at, type, ok, email, uid, ip, ua, ... }
                        type: signup | signin | signin_failed | user_created | user_deleted |
                              account_changed | email_sent | purchase | purchase_removed |
                              course_denied | checkout | visit |
                              stripe_paid | payment_failed | checkout_expired | refund |
                              dispute | dispute_closed | fraud_warning
     changes/{id}     changes to users/{uid}: { at, area, path, action, by, fields, n, before, after }
     alerts/{id}      { at, level, title, detail, src }
     census/{uid}     the last look at each account (with its paid flag)
     counters/...     short-lived counts used to spot bursts
     unsent/{id}      entries the E&C log didn't take; sent again by auditPlutoResend
   Every events/changes/alerts entry is also sent to auditIngest in the E&C project, so it shows
   in the Security tab of the usage page. The copy here is the backup. */
'use strict';

const crypto = require('crypto');

const TEXT_MAX = 300;
const VALUE_MAX = 4000;
const FIELDS_MAX = 40;
const REPORT_MAX = 4000;

function clip(v, max) {
  if (v == null || v === '') return null;
  return String(v).slice(0, max || TEXT_MAX);
}
function normEmail(email) { return String(email || '').trim().toLowerCase(); }
function safeKey(v) { return String(v || 'none').toLowerCase().replace(/[.#$[\]/]/g, ',').slice(0, 200) || 'none'; }
function dayKey(at) { return new Date(at).toISOString().slice(0, 10); }
function bucket(at, ms) { return String(Math.floor(at / ms)); }

function requestIp(req) {
  const fwd = String((req.headers && req.headers['x-forwarded-for']) || '').split(',')[0].trim();
  return clip(fwd || req.ip || (req.socket && req.socket.remoteAddress) || null, 64);
}

const PUSH_CHARS = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz';
function pushIdAt(t) {
  let out = '';
  for (let i = 0; i < 8; i++) { out = PUSH_CHARS.charAt(t % 64) + out; t = Math.floor(t / 64); }
  return out;
}

// ---------------------------------------------------------------- reports from the site

/**
 * What the site may report (see reportToAudit in plutoscan-auth.js):
 *   failed    a sign-in, sign-up or reset that Firebase turned down (wrong password, ...)
 *   denied    the course page sent someone away (not signed in, or not paid)
 *   checkout  the purchase flow: started, failed, returned (back from Stripe), pending
 *   visit     a page was opened
 */
const KINDS = { failed: 'signin_failed', denied: 'course_denied', checkout: 'checkout', visit: 'visit' };
const CHECKOUT_STEPS = new Set(['started', 'failed', 'returned', 'pending', 'cancelled']);

function parseReport(text) {
  if (typeof text !== 'string' || !text || text.length > REPORT_MAX) return null;
  let r;
  try { r = JSON.parse(text); } catch (e) { return null; }
  if (!r || typeof r !== 'object' || Array.isArray(r) || !KINDS[r.kind]) return null;
  return {
    kind: r.kind,
    email: clip(normEmail(r.email), 200),
    code: clip(r.code, 80),
    reason: clip(r.reason, 200),
    action: clip(r.action, 20),
    method: clip(r.method, 20),
    step: r.kind === 'checkout' && CHECKOUT_STEPS.has(r.step) ? r.step : null,
    page: clip(r.page, 200),
    referrer: clip(r.referrer, 200),
    clientAt: Number.isFinite(r.at) ? r.at : null,
    idToken: typeof r.idToken === 'string' && r.idToken.length < 4096 ? r.idToken : null
  };
}

/** The log entry for a report. token: the verified ID token, or null. */
function reportEntry(r, { at, ip, ua, origin, token, tokenError }) {
  const e = {
    at,
    type: KINDS[r.kind],
    ok: r.kind === 'visit' || (r.kind === 'checkout' && r.step !== 'failed'),
    email: r.email,
    code: r.code,
    reason: r.reason,
    action: r.action,
    method: r.method,
    step: r.step,
    page: r.page,
    referrer: r.referrer,
    ip: clip(ip, 64),
    ua: clip(ua),
    origin: clip(origin, 120),
    verified: !!token
  };
  if (token) {
    e.uid = clip(token.uid, 128);
    const tokenEmail = normEmail(token.email);
    if (tokenEmail && tokenEmail !== r.email) { if (r.email) e.claimedEmail = r.email; e.email = tokenEmail; }
  } else if (r.idToken) {
    e.tokenError = clip(tokenError || 'invalid', 80);
  }
  return e;
}

// ---------------------------------------------------------------- blocking functions

function providerOf(event) {
  const info = (event && event.additionalUserInfo) || {};
  const cred = (event && event.credential) || {};
  const u = (event && event.data) || {};
  const providers = (u.providerData || []).map((p) => p && p.providerId).filter(Boolean);
  return clip(info.providerId || cred.signInMethod || providers[0] || null, 40);
}

function authEventEntry(type, event, at) {
  const u = (event && event.data) || {};
  const info = (event && event.additionalUserInfo) || {};
  return {
    at,
    type,
    ok: true,
    email: clip(normEmail(u.email || info.email) || null, 200),
    uid: clip(u.uid || null, 128),
    provider: providerOf(event),
    emailType: clip(event && event.emailType, 30),
    ip: clip(event && event.ipAddress, 64),
    ua: clip(event && event.userAgent)
  };
}

// ---------------------------------------------------------------- users/{uid}

/**
 * What a client may write under users/{uid}, per the repo's README: progress and review. paid is
 * set only by stripeWebhook (server code). Anything else there is unexpected.
 */
const CLIENT_FIELDS = new Set(['progress', 'review']);
const SERVER_FIELDS = new Set(['paid']);

function actionOf(before, after) {
  if (before == null && after != null) return 'created';
  if (before != null && after == null) return 'deleted';
  return 'updated';
}
function isObj(v) { return v !== null && typeof v === 'object'; }
function short(v) { return typeof v === 'string' ? v.slice(0, 200) : v; }

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
function countLeaves(v) {
  if (!isObj(v)) return v == null ? 0 : 1;
  return Object.values(v).reduce((n, x) => n + countLeaves(x), 0);
}
function keepValue(v) {
  if (v == null) return null;
  const json = JSON.stringify(v);
  return json.length <= VALUE_MAX ? v : { _cut: true, json: json.slice(0, VALUE_MAX) };
}

/** The top-level fields of users/{uid} that changed. */
function topFields(before, after) {
  const b = isObj(before) ? before : {};
  const a = isObj(after) ? after : {};
  return [...new Set([...Object.keys(b), ...Object.keys(a)])].filter((k) => JSON.stringify(b[k]) !== JSON.stringify(a[k])).sort();
}

/**
 * Looks at one write to users/{uid}. Returns { entry, events, alerts }: the change entry for the
 * log, purchase events, and alerts. who: { type, uid, email } from the database event.
 */
function userChange({ uid, before, after, who, at }) {
  const action = actionOf(before, after);
  const top = topFields(before, after);
  const fields = diffFields(before, after);
  const progressOnly = top.length > 0 && top.every((k) => k === 'progress');
  const entry = {
    at,
    area: progressOnly ? 'Course progress' : 'Accounts',
    path: 'users/' + uid,
    action,
    by: Object.assign({ type: clip(who.type || 'unknown', 20), uid: clip(who.uid || null, 128) }, who.email ? { email: clip(who.email, 200) } : {}),
    fields,
    n: action === 'deleted' ? countLeaves(before) : fields.length,
    // Progress is a big object saved after every lesson step; the fields that changed are enough.
    before: progressOnly ? null : keepValue(before),
    after: progressOnly ? null : keepValue(after)
  };
  const events = [];
  const alerts = [];
  const name = (who.email && who.uid === uid ? who.email : null) || uid;
  const writer = who.email || who.uid || (who.type === 'admin' ? 'Server code or the console' : 'Someone (Firebase did not say who)');
  const paidBefore = isObj(before) && before.paid === true;
  const paidAfter = isObj(after) && after.paid === true;
  if (!paidBefore && paidAfter) {
    // Only server code (stripeWebhook, or the console) should ever set paid. If Firebase didn't
    // say who wrote it, it's still logged as a purchase, with a note.
    const byUser = who.type === 'app_user' || who.type === 'unauthenticated';
    events.push({ at, type: 'purchase', ok: !byUser, uid, by: entry.by.type });
    alerts.push(byUser
      ? { level: 'high', title: 'Paid flag set by a user', detail: writer + ' marked ' + uid + ' as paid without going through Stripe. The database rules should never allow this.' }
      : { level: 'low', title: 'New purchase', detail: 'Account ' + uid + ' was marked as paid' + (who.type === 'admin' ? ' (by the Stripe webhook or the console).' : ' (Firebase did not say who wrote it).') });
  } else if (paidBefore && !paidAfter) {
    events.push({ at, type: 'purchase_removed', ok: true, uid, by: entry.by.type });
    alerts.push({ level: 'medium', title: 'Paid access removed', detail: writer + ' removed paid access from ' + uid + '.' });
  }
  if (who.type === 'unauthenticated') {
    alerts.push({ level: 'high', title: 'Change with no sign-in', detail: 'users/' + uid + ' was ' + action + ' by someone not signed in. The database rules should never allow this.' });
  } else if (who.type === 'app_user' && who.uid && who.uid !== uid) {
    alerts.push({ level: 'high', title: "Changed someone else's account", detail: writer + ' ' + action + ' users/' + uid + ' (' + top.join(', ') + ').' });
  } else if (who.type === 'app_user') {
    const odd = top.filter((k) => !CLIENT_FIELDS.has(k) && !SERVER_FIELDS.has(k));
    if (odd.length) alerts.push({ level: 'medium', title: 'Unexpected data on an account', detail: name + ' wrote ' + odd.join(', ') + ' under users/' + uid + '; the site only writes progress and review.' });
  }
  if (action === 'deleted' && who.type !== 'admin') {
    alerts.push({ level: 'high', title: 'Account data deleted', detail: writer + ' deleted users/' + uid + ' (' + entry.n + ' values).' });
  }
  return { entry, events, alerts, progressOnly };
}

// ---------------------------------------------------------------- accounts (census)

function censusOf(u, paid) {
  return {
    email: clip(normEmail(u.email) || null, 200),
    disabled: !!u.disabled,
    providers: (u.providerData || []).map((p) => p.providerId).filter(Boolean).sort().join(',') || null,
    claims: u.customClaims && Object.keys(u.customClaims).length ? JSON.stringify(u.customClaims).slice(0, 500) : null,
    tokensValidAfter: clip(u.tokensValidAfterTime || null, 40),
    created: clip(u.metadata && u.metadata.creationTime, 40),
    lastSignIn: clip(u.metadata && u.metadata.lastSignInTime, 40),
    verified: !!u.emailVerified,
    paid: paid === true
  };
}

const CENSUS_FIELDS = {
  email: 'email address', disabled: 'disabled', providers: 'sign-in methods', claims: 'custom claims',
  tokensValidAfter: 'password or sessions reset', verified: 'email verified'
};

function censusDiff(before, after) {
  return Object.keys(CENSUS_FIELDS)
    .filter((f) => (before[f] == null ? null : before[f]) !== (after[f] == null ? null : after[f]))
    .map((f) => ({ f, b: before[f] == null ? null : before[f], a: after[f] == null ? null : after[f], label: CENSUS_FIELDS[f] }));
}

/** Whether the census record changed in a way the page shows (incl. paid and last sign-in). */
function censusChanged(before, after) {
  return !before || JSON.stringify(before) !== JSON.stringify(after);
}

function censusAlertLevel(diff) {
  if (diff.some((d) => d.f === 'claims' || d.f === 'email')) return 'high';
  if (diff.some((d) => d.f === 'disabled' || d.f === 'providers')) return 'medium';
  return null;
}

// ---------------------------------------------------------------- Stripe (auditPlutoStripe)

const STRIPE_TOLERANCE = 5 * 60;   // seconds a signed event may be old (Stripe's own default)

/**
 * Checks a Stripe-Signature header the way Stripe documents it: HMAC-SHA256 of "<t>.<raw body>"
 * with the endpoint's signing secret, compared with each v1 value, and t no more than 5 minutes old.
 * https://docs.stripe.com/webhooks#verify-manually
 */
function stripeSignatureOk(header, rawBody, secret, nowSec) {
  if (!header || !secret || typeof rawBody !== 'string') return false;
  const parts = String(header).split(',').map((p) => p.split('='));
  const t = Number((parts.find((p) => p[0] === 't') || [])[1]);
  const sigs = parts.filter((p) => p[0] === 'v1').map((p) => p[1] || '');
  if (!Number.isFinite(t) || !sigs.length || Math.abs(nowSec - t) > STRIPE_TOLERANCE) return false;
  const expected = Buffer.from(crypto.createHmac('sha256', secret).update(t + '.' + rawBody, 'utf8').digest('hex'));
  return sigs.some((s) => { const b = Buffer.from(s); return b.length === expected.length && crypto.timingSafeEqual(b, expected); });
}

function money(amount, currency) {
  if (!Number.isFinite(amount)) return null;
  return (amount / 100).toFixed(2) + ' ' + String(currency || '').toUpperCase();
}

/**
 * The log entry and alert for a Stripe event, or null for events not watched. Card numbers never
 * reach here; only the card brand, the country and Stripe's decline reason are kept.
 */
function stripeEntry(ev, at) {
  const o = (ev && ev.data && ev.data.object) || {};
  const base = { at, ok: true, stripeEvent: clip(ev.id, 80), livemode: !!ev.livemode, uid: clip(o.client_reference_id || (o.metadata && (o.metadata.uid || o.metadata.firebaseUid)) || null, 128) };
  const err = o.last_payment_error || {};
  const pm = err.payment_method || {};
  const card = pm.card || {};
  switch (ev && ev.type) {
    case 'checkout.session.completed':
      return { entry: Object.assign(base, { type: 'stripe_paid', email: clip(normEmail(o.customer_details && o.customer_details.email) || null, 200),
        amount: money(o.amount_total, o.currency), reason: clip(o.payment_status, 40) }) };
    case 'checkout.session.expired':
      return { entry: Object.assign(base, { type: 'checkout_expired', ok: false, email: clip(normEmail(o.customer_details && o.customer_details.email) || null, 200),
        amount: money(o.amount_total, o.currency), reason: 'checkout left unfinished' }) };
    case 'checkout.session.async_payment_failed':
      return { entry: Object.assign(base, { type: 'payment_failed', ok: false, email: clip(normEmail(o.customer_details && o.customer_details.email) || null, 200),
        amount: money(o.amount_total, o.currency), reason: 'delayed payment failed' }) };
    case 'payment_intent.payment_failed': {
      const email = normEmail(o.receipt_email || (pm.billing_details && pm.billing_details.email)) || null;
      return { entry: Object.assign(base, { type: 'payment_failed', ok: false, email: clip(email, 200), amount: money(o.amount, o.currency),
        code: clip(err.decline_code || err.code, 80), reason: clip(err.message, 200), method: clip([card.brand, card.country].filter(Boolean).join(' ') || pm.type || null, 40) }) };
    }
    case 'charge.refunded':
      return { entry: Object.assign(base, { type: 'refund', email: clip(normEmail(o.billing_details && o.billing_details.email) || normEmail(o.receipt_email) || null, 200),
        amount: money(o.amount_refunded, o.currency) }),
        alert: { level: 'medium', title: 'Refund', detail: 'A payment was refunded (' + (money(o.amount_refunded, o.currency) || 'amount unknown') + '). Paid access is not removed automatically; check the account.' } };
    case 'charge.dispute.created':
      return { entry: Object.assign(base, { type: 'dispute', ok: false, amount: money(o.amount, o.currency), reason: clip(o.reason, 60) }),
        alert: { level: 'high', title: 'Chargeback opened', detail: 'A customer disputed a payment of ' + (money(o.amount, o.currency) || 'unknown amount') + ' (reason: ' + (o.reason || 'not given') + '). Respond in the Stripe dashboard before the deadline.' } };
    case 'charge.dispute.closed':
      return { entry: Object.assign(base, { type: 'dispute_closed', ok: o.status === 'won', amount: money(o.amount, o.currency), reason: clip(o.status, 40) }),
        alert: { level: o.status === 'won' ? 'low' : 'medium', title: 'Chargeback ' + (o.status || 'closed'), detail: 'A dispute of ' + (money(o.amount, o.currency) || 'unknown amount') + ' was closed: ' + (o.status || 'unknown') + '.' } };
    case 'radar.early_fraud_warning.created':
      return { entry: Object.assign(base, { type: 'fraud_warning', ok: false, reason: clip(o.fraud_type, 60) }),
        alert: { level: 'high', title: 'Stripe fraud warning', detail: 'The card issuer reported a payment as likely fraud (' + (o.fraud_type || 'type not given') + '). Consider refunding it before it becomes a chargeback.' } };
    default:
      return null;
  }
}

module.exports = {
  REPORT_MAX, CLIENT_FIELDS,
  clip, normEmail, safeKey, dayKey, bucket, requestIp, pushIdAt,
  parseReport, reportEntry, authEventEntry,
  diffFields, topFields, userChange,
  censusOf, censusDiff, censusChanged, censusAlertLevel,
  stripeSignatureOk, stripeEntry
};
