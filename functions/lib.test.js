'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const L = require('./lib');

const AT = Date.UTC(2026, 9, 20, 15, 0, 0);

test('reports from the apps are checked before they are logged', () => {
  assert.equal(L.parseReport(''), null);
  assert.equal(L.parseReport('not json'), null);
  assert.equal(L.parseReport('[1]'), null);
  assert.equal(L.parseReport(JSON.stringify({ kind: 'deleted', app: 'garage' })), null);
  assert.equal(L.parseReport('x'.repeat(L.REPORT_MAX + 1)), null);

  const r = L.parseReport(JSON.stringify({ kind: 'failed', app: 'Dispatch', email: ' Bob@EC.com ', code: 'auth/wrong-password', at: 5, idToken: 7 }));
  assert.equal(r.app, 'dispatch');
  assert.equal(r.email, 'bob@ec.com');
  assert.equal(r.code, 'auth/wrong-password');
  assert.equal(r.clientAt, 5);
  assert.equal(r.idToken, null);

  assert.equal(L.parseReport(JSON.stringify({ kind: 'refused', app: '<script>' })).app, 'unknown');
  assert.equal(L.parseReport(JSON.stringify({ kind: 'failed', reason: 'y'.repeat(500) })).reason.length, 200);
});

test('a failed report becomes a signin_failed entry with where it came from', () => {
  const r = L.parseReport(JSON.stringify({ kind: 'failed', app: 'garage', email: 'a@b.com', code: 'auth/invalid-credential' }));
  const e = L.reportEntry(r, { at: AT, ip: '1.2.3.4', ua: 'UA', origin: 'https://ogpoopdogg.github.io' });
  assert.equal(e.type, 'signin_failed');
  assert.equal(e.ok, false);
  assert.equal(e.ip, '1.2.3.4');
  assert.equal(e.verified, false);
  assert.equal(e.tokenError, undefined);
});

test('a refused report trusts the verified token over the email the app sent', () => {
  const r = L.parseReport(JSON.stringify({ kind: 'refused', app: 'routeplanner', email: 'someone@ec.com', reason: 'Not on the staff list', idToken: 'tok' }));
  const e = L.reportEntry(r, { at: AT, token: { uid: 'u1', email: 'Real@Gmail.com' } });
  assert.equal(e.type, 'signin_refused');
  assert.equal(e.verified, true);
  assert.equal(e.uid, 'u1');
  assert.equal(e.email, 'real@gmail.com');
  assert.equal(e.claimedEmail, 'someone@ec.com');

  const bad = L.reportEntry(r, { at: AT, token: null, tokenError: 'auth/argument-error' });
  assert.equal(bad.verified, false);
  assert.equal(bad.tokenError, 'auth/argument-error');
  assert.equal(bad.uid, undefined);
});

test('sign-in events keep the IP, browser and sign-in method', () => {
  const e = L.authEventEntry('signin', {
    data: { uid: 'u1', email: 'Justin@ec.com', providerData: [{ providerId: 'password' }] },
    additionalUserInfo: {}, ipAddress: '9.9.9.9', userAgent: 'Mozilla/5.0 (Linux; Android 14) Chrome/130.0 Mobile Safari/537.36'
  }, AT);
  assert.deepEqual([e.type, e.email, e.uid, e.provider, e.ip, e.staff], ['signin', 'justin@ec.com', 'u1', 'password', '9.9.9.9', true]);
  const sms = L.authEventEntry('sms_sent', { additionalUserInfo: { phoneNumber: '+15555550100' }, smsType: 'SIGN_IN_OR_SIGN_UP' }, AT);
  assert.equal(sms.phone, '+15555550100');
  assert.equal(sms.smsType, 'SIGN_IN_OR_SIGN_UP');
  assert.equal(sms.staff, false);
});

test('devices are named for people and keyed without the version', () => {
  assert.equal(L.deviceName('Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36'), 'Chrome on Android');
  assert.equal(L.deviceName('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1'), 'Safari on iPhone/iPad');
  assert.equal(L.deviceName('Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36 Edg/130.0'), 'Edge on Windows');
  assert.equal(L.deviceName('curl/8.4.0'), 'Script');
  assert.equal(L.deviceName(''), 'Unknown device');
  assert.equal(L.deviceKey('Mozilla/5.0 (Windows NT 10.0) Chrome/129.0 Safari/537.36'), L.deviceKey('Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36'));
});

test('database keys and time helpers', () => {
  assert.equal(L.safeKey('a.b@c.com'), 'a,b@c,com');
  assert.equal(L.safeKey('2001:db8::1/64'), '2001:db8::1,64');
  assert.equal(L.safeKey(null), 'none');
  assert.equal(L.dayKey(AT), '2026-10-20');
  assert.equal(L.bucket(15 * 60 * 1000 * 3 + 5, 15 * 60 * 1000), '3');
  assert.equal(L.requestIp({ headers: { 'x-forwarded-for': '7.7.7.7, 10.0.0.1' } }), '7.7.7.7');
  assert.equal(L.requestIp({ headers: {}, ip: '8.8.8.8' }), '8.8.8.8');
});

test('pushIdAt sorts with real push ids', () => {
  // Push ids are 8 time characters then 12 random ones, so every id made at AT sorts between these
  const id = L.pushIdAt(AT);
  assert.equal(id.length, 8);
  assert.ok(L.pushIdAt(AT - 1) < id);
  assert.ok(id < L.pushIdAt(AT + 1));
  assert.ok(id + 'zzzzzzzzzzzz' < L.pushIdAt(AT + 1));
  assert.equal(L.pushIdAt(0), '--------');
});

test('changes list the fields that changed', () => {
  assert.deepEqual(L.diffFields({ a: 1, b: { c: 'x' } }, { a: 1, b: { c: 'y' }, d: true }), [{ f: 'b/c', b: 'x', a: 'y' }, { f: 'd', b: null, a: true }]);
  assert.deepEqual(L.diffFields('old', 'new'), [{ f: '(value)', b: 'old', a: 'new' }]);
  assert.deepEqual(L.diffFields({ a: 'x' }, 'flat'), [{ f: '(value)', b: '(object)', a: 'flat' }]);
  assert.deepEqual(L.diffFields(null, { a: 1 }), [{ f: 'a', b: null, a: 1 }]);
  const many = Object.fromEntries(Array.from({ length: 100 }, (_, i) => ['k' + i, i]));
  assert.equal(L.diffFields(null, many).length, 40);
  assert.equal(L.countLeaves({ a: 1, b: { c: 2, d: [3, 4] } }), 4);
  assert.equal(L.countLeaves(null), 0);
});

test('a change entry records who, what and before/after', () => {
  const watch = L.WATCHES.find((w) => w.name === 'addressLookup');
  const e = L.changeEntry({ watch, path: 'address_lookup/abc', before: { street: '1 Main' }, after: { street: '2 Main' }, authType: 'app_user', authId: 'u1', email: 'bob@ec.com', at: AT });
  assert.equal(e.area, 'Address lookup');
  assert.equal(e.action, 'updated');
  assert.deepEqual(e.by, { type: 'app_user', uid: 'u1', email: 'bob@ec.com' });
  assert.deepEqual(e.fields, [{ f: 'street', b: '1 Main', a: '2 Main' }]);
  assert.equal(e.n, 1);
  assert.deepEqual(e.before, { street: '1 Main' });

  const del = L.changeEntry({ watch, path: 'address_lookup/abc', before: { a: 1, b: 2, c: 3 }, after: null, authType: 'admin', at: AT });
  assert.equal(del.action, 'deleted');
  assert.equal(del.n, 3);
  assert.deepEqual(del.by, { type: 'admin', uid: null });

  const big = L.changeEntry({ watch, path: 'p', before: null, after: { s: 'x'.repeat(5000) }, authType: 'admin', at: AT });
  assert.equal(big.after._cut, true);
  assert.equal(big.after.json.length, 4000);
});

test('alerts for changes', () => {
  const lookup = L.WATCHES.find((w) => w.name === 'addressLookup');
  const staffW = L.WATCHES.find((w) => w.name === 'staff');
  const sessions = L.WATCHES.find((w) => w.name === 'sessions');
  const entry = (over) => Object.assign({ area: 'A', path: 'p', action: 'updated', by: { type: 'app_user', uid: 'u1', email: 'x@gmail.com' }, fields: [{ f: 'a' }], n: 1 }, over);

  assert.deepEqual(L.changeAlerts(entry(), lookup, { staff: true }), []);
  assert.deepEqual(L.changeAlerts(entry(), lookup, { staff: false }).map((a) => [a.level, a.title]), [['high', 'Non-staff account changed staff data']]);
  // Unknown staff status (lookup failed) raises nothing; admins are never flagged
  assert.deepEqual(L.changeAlerts(entry(), lookup, { staff: null }), []);
  assert.deepEqual(L.changeAlerts(entry(), lookup, { staff: false, adminEmail: true }), []);
  assert.equal(L.changeAlerts(entry({ by: { type: 'unauthenticated', uid: null } }), lookup, {})[0].title, 'Change with no sign-in');
  assert.deepEqual(L.changeAlerts(entry(), staffW, { staff: true }).map((a) => a.level), ['high']);
  assert.deepEqual(L.changeAlerts(entry(), sessions, { staff: true }), []);
  assert.deepEqual(L.changeAlerts(entry({ action: 'deleted', n: 25 }), lookup, { staff: true }).map((a) => a.title), ['Large delete']);
  assert.deepEqual(L.changeAlerts(entry({ by: { type: 'admin', uid: null } }), lookup, { staff: null }), []);
});

test('every watch has a unique name and a path the trigger accepts', () => {
  const names = new Set();
  for (const w of L.WATCHES) {
    assert.ok(!names.has(w.name), w.name);
    names.add(w.name);
    assert.match(w.path, /^[a-z_]+(\/([a-z_]+|\{[a-zA-Z]+\}))*$/, w.path);
    assert.ok(w.area);
    if (w.skip) assert.ok(w.path.includes('{section}'), w.name);
    assert.ok(!w.path.startsWith('security_log'), 'the log must never watch itself');
  }
});

test('the census spots changes made outside the apps', () => {
  const was = L.censusOf({ uid: 'u', email: 'Bob@ec.com', providerData: [{ providerId: 'password' }], metadata: { creationTime: 'c', lastSignInTime: 'l1' } });
  assert.equal(was.email, 'bob@ec.com');
  assert.equal(was.claims, null);
  const now = L.censusOf({ uid: 'u', email: 'bob@ec.com', disabled: true, customClaims: { admin: true }, providerData: [{ providerId: 'password' }, { providerId: 'google.com' }], metadata: { creationTime: 'c', lastSignInTime: 'l2' } });
  const diff = L.censusDiff(was, now);
  assert.deepEqual(diff.map((d) => d.f), ['disabled', 'providers', 'claims']);
  assert.equal(L.censusAlertLevel(diff, 'bob@ec.com'), 'high');
  // Signing in (lastSignIn) is not a change worth logging
  assert.deepEqual(L.censusDiff(was, Object.assign({}, was, { lastSignIn: 'l3' })), []);
  assert.equal(L.censusAlertLevel([{ f: 'disabled' }], 'bob@ec.com'), 'medium');
  assert.equal(L.censusAlertLevel([{ f: 'disabled' }], 'someone@gmail.com'), null);
  // A census record written before a field existed is not reported as a change
  assert.deepEqual(L.censusDiff({ email: 'a' }, { email: 'a', phone: null, claims: null }), []);
});
