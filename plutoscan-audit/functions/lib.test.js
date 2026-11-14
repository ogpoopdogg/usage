'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const L = require('./lib');

const AT = Date.UTC(2026, 9, 21, 15, 0, 0);
const admin = { type: 'admin', uid: null };
const owner = { type: 'app_user', uid: 'u1', email: 'a@b.com' };

test('reports from the site are checked before they are logged', () => {
  assert.equal(L.parseReport(''), null);
  assert.equal(L.parseReport('[1]'), null);
  assert.equal(L.parseReport(JSON.stringify({ kind: 'refused' })), null);
  assert.equal(L.parseReport('x'.repeat(L.REPORT_MAX + 1)), null);
  const r = L.parseReport(JSON.stringify({ kind: 'checkout', step: 'hacked', email: ' A@B.com ', at: 3 }));
  assert.equal(r.step, null);
  assert.equal(r.email, 'a@b.com');
  assert.equal(r.clientAt, 3);
  assert.equal(L.parseReport(JSON.stringify({ kind: 'checkout', step: 'returned' })).step, 'returned');
});

test('report entries say what happened and trust the token over the page', () => {
  const failed = L.reportEntry(L.parseReport(JSON.stringify({ kind: 'failed', email: 'x@y.com', code: 'auth/invalid-credential', action: 'login' })), { at: AT, ip: '1.2.3.4' });
  assert.equal(failed.type, 'signin_failed');
  assert.equal(failed.ok, false);
  const visit = L.reportEntry(L.parseReport(JSON.stringify({ kind: 'visit', page: '/' })), { at: AT });
  assert.equal(visit.type, 'visit');
  assert.equal(visit.ok, true);
  const denied = L.reportEntry(L.parseReport(JSON.stringify({ kind: 'denied', reason: 'payment_required', email: 'fake@y.com', idToken: 't' })),
    { at: AT, token: { uid: 'u9', email: 'Real@y.com' } });
  assert.equal(denied.type, 'course_denied');
  assert.equal(denied.email, 'real@y.com');
  assert.equal(denied.claimedEmail, 'fake@y.com');
  assert.equal(denied.uid, 'u9');
  const bad = L.reportEntry(L.parseReport(JSON.stringify({ kind: 'denied', idToken: 't' })), { at: AT, tokenError: 'auth/argument-error' });
  assert.equal(bad.verified, false);
  assert.equal(bad.tokenError, 'auth/argument-error');
  const failedCheckout = L.reportEntry(L.parseReport(JSON.stringify({ kind: 'checkout', step: 'failed' })), { at: AT });
  assert.equal(failedCheckout.ok, false);
});

test('the paid flag turning on from server code is a purchase', () => {
  const got = L.userChange({ uid: 'u1', before: { progress: { 1: {} } }, after: { progress: { 1: {} }, paid: true }, who: admin, at: AT });
  assert.equal(got.events[0].type, 'purchase');
  assert.equal(got.events[0].ok, true);
  assert.deepEqual(got.alerts.map((a) => [a.level, a.title]), [['low', 'New purchase']]);
  assert.equal(got.entry.area, 'Accounts');
});

test('a paid flag with no writer named is still a purchase, not an alarm', () => {
  const got = L.userChange({ uid: 'u1', before: {}, after: { paid: true }, who: { type: 'unknown' }, at: AT });
  assert.equal(got.events[0].ok, true);
  assert.equal(got.alerts[0].level, 'low');
  assert.match(got.alerts[0].detail, /did not say/);
});

test('a user setting their own paid flag is a high alert', () => {
  const got = L.userChange({ uid: 'u1', before: {}, after: { paid: true }, who: owner, at: AT });
  assert.equal(got.events[0].ok, false);
  assert.equal(got.alerts[0].level, 'high');
  assert.match(got.alerts[0].title, /Paid flag set by a user/);
});

test('paid access removed, other accounts, no sign-in and odd fields raise alerts', () => {
  assert.equal(L.userChange({ uid: 'u1', before: { paid: true }, after: { paid: false }, who: admin, at: AT }).events[0].type, 'purchase_removed');
  const other = L.userChange({ uid: 'u2', before: null, after: { review: { stars: 1 } }, who: owner, at: AT });
  assert.ok(other.alerts.some((a) => a.level === 'high' && /someone else/.test(a.title)));
  const anon = L.userChange({ uid: 'u2', before: null, after: { x: 1 }, who: { type: 'unauthenticated' }, at: AT });
  assert.ok(anon.alerts.some((a) => a.title === 'Change with no sign-in'));
  const odd = L.userChange({ uid: 'u1', before: {}, after: { admin: true }, who: owner, at: AT });
  assert.ok(odd.alerts.some((a) => a.title === 'Unexpected data on an account' && /admin/.test(a.detail)));
  const gone = L.userChange({ uid: 'u1', before: { progress: { 1: { a: 1, b: 2 } } }, after: null, who: owner, at: AT });
  assert.ok(gone.alerts.some((a) => a.title === 'Account data deleted'));
});

test('saving course progress is logged without the whole progress object and with no alert', () => {
  const got = L.userChange({ uid: 'u1', before: { paid: true, progress: { 1: { textComplete: false } } }, after: { paid: true, progress: { 1: { textComplete: true } } }, who: owner, at: AT });
  assert.equal(got.progressOnly, true);
  assert.equal(got.entry.area, 'Course progress');
  assert.equal(got.entry.before, null);
  assert.deepEqual(got.entry.fields, [{ f: 'progress/1/textComplete', b: false, a: true }]);
  assert.deepEqual(got.alerts, []);
  assert.deepEqual(got.events, []);
});

test('the census keeps the paid flag and spots changes made outside the site', () => {
  const u = { uid: 'u1', email: 'A@b.com', providerData: [{ providerId: 'password' }], metadata: { creationTime: 'c', lastSignInTime: 'l' } };
  const was = L.censusOf(u, null);
  assert.equal(was.paid, false);
  const now = L.censusOf(Object.assign({}, u, { customClaims: { admin: true } }), true);
  assert.equal(now.paid, true);
  assert.equal(L.censusChanged(was, now), true);
  assert.equal(L.censusChanged(was, L.censusOf(u, false)), false);
  const diff = L.censusDiff(was, now);
  assert.deepEqual(diff.map((d) => d.f), ['claims']);
  assert.equal(L.censusAlertLevel(diff), 'high');
});

test('Stripe signatures are checked the way Stripe documents', () => {
  const crypto = require('crypto');
  const secret = 'whsec_test';
  const body = JSON.stringify({ id: 'evt_1', type: 'charge.refunded' });
  const t = 1792600000;
  const sig = crypto.createHmac('sha256', secret).update(t + '.' + body).digest('hex');
  assert.equal(L.stripeSignatureOk('t=' + t + ',v1=' + sig, body, secret, t + 10), true);
  assert.equal(L.stripeSignatureOk('t=' + t + ',v1=deadbeef,v1=' + sig, body, secret, t), true);
  assert.equal(L.stripeSignatureOk('t=' + t + ',v1=' + sig, body + ' ', secret, t), false);
  assert.equal(L.stripeSignatureOk('t=' + t + ',v1=' + sig, body, 'whsec_other', t), false);
  assert.equal(L.stripeSignatureOk('t=' + t + ',v1=' + sig, body, secret, t + 301), false);
  assert.equal(L.stripeSignatureOk('v1=' + sig, body, secret, t), false);
  assert.equal(L.stripeSignatureOk(undefined, body, secret, t), false);
  assert.equal(L.stripeSignatureOk('t=' + t + ',v1=' + sig, body, '', t), false);
});

test('Stripe events become log entries and alerts', () => {
  const ev = (type, object, livemode) => ({ id: 'evt_x', type, livemode: !!livemode, data: { object } });
  const failed = L.stripeEntry(ev('payment_intent.payment_failed', { amount: 4900, currency: 'usd', receipt_email: 'A@b.com',
    last_payment_error: { code: 'card_declined', decline_code: 'insufficient_funds', message: 'Your card has insufficient funds.', payment_method: { type: 'card', card: { brand: 'visa', country: 'US', last4: '4242' } } } }), AT);
  assert.equal(failed.entry.type, 'payment_failed');
  assert.equal(failed.entry.ok, false);
  assert.equal(failed.entry.email, 'a@b.com');
  assert.equal(failed.entry.code, 'insufficient_funds');
  assert.equal(failed.entry.amount, '49.00 USD');
  assert.equal(failed.entry.method, 'visa US');
  assert.ok(!JSON.stringify(failed).includes('4242'));
  assert.equal(failed.alert, undefined);

  const paid = L.stripeEntry(ev('checkout.session.completed', { amount_total: 4900, currency: 'usd', payment_status: 'paid', client_reference_id: 'u1', customer_details: { email: 'a@b.com' } }, true), AT);
  assert.equal(paid.entry.type, 'stripe_paid');
  assert.equal(paid.entry.uid, 'u1');
  assert.equal(paid.entry.livemode, true);

  assert.equal(L.stripeEntry(ev('checkout.session.expired', { amount_total: 4900, currency: 'usd' }), AT).entry.type, 'checkout_expired');
  assert.equal(L.stripeEntry(ev('charge.refunded', { amount_refunded: 4900, currency: 'usd' }), AT).alert.level, 'medium');
  const dispute = L.stripeEntry(ev('charge.dispute.created', { amount: 4900, currency: 'usd', reason: 'fraudulent' }), AT);
  assert.equal(dispute.alert.level, 'high');
  assert.match(dispute.alert.detail, /fraudulent/);
  assert.equal(L.stripeEntry(ev('charge.dispute.closed', { amount: 4900, currency: 'usd', status: 'won' }), AT).alert.level, 'low');
  assert.equal(L.stripeEntry(ev('radar.early_fraud_warning.created', { fraud_type: 'stolen_card' }), AT).alert.level, 'high');
  assert.equal(L.stripeEntry(ev('customer.created', {}), AT), null);
});
