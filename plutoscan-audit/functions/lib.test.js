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
