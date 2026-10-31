'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const W = require('./watch');

const why = (b, a) => W.suspiciousValues(b, a).map((o) => o.f + ': ' + o.why);

test('ordinary data saved by the apps raises nothing', () => {
  const ordinary = {
    name: "Bob O'Neil", phone: '(204) 555-0100', address: '1234 Rosser Ave, Brandon, MB R7A 0K9',
    note: 'Leave at back door < 5 boxes, call when > 10 min late. 50% off & "fragile"!',
    email: 'bob@ec.com', url: 'https://maps.google.com/?q=49.84,-99.95&z=15', time: '7:30 AM - 4:00 PM',
    tags: ['rush', 'C.O.D.'], updated_by: 'desirae', count: 4, ok: true,
    text: 'Front left tire low (35 psi). Check engine light on since Tue.'
  };
  assert.deepEqual(why(null, ordinary), []);
  assert.deepEqual(why(null, { note: 'Ask for Bob ("the manager"); fetch (the parcel) from shelf "B" > 2' }), []);
  assert.deepEqual(why(null, { reminders: { start: 8, end: 17, updated_by: 'Jo-Anne (dispatch)' } }), []);
});

test('script tags, event handlers and javascript: links are caught', () => {
  assert.match(why(null, { name: '<script>alert(1)</script>' })[0], /^name: an HTML tag/);
  assert.match(why(null, { note: '<img src=x onerror=alert(1)>' })[0], /event handler/);
  assert.match(why(null, { a: { b: 'javascript:alert(1)' } })[0], /^a\/b: a javascript: link/);
  assert.match(why(null, { n: '" onmouseover="alert(1)' })[0], /event handler/);
  assert.match(why(null, { id: "x');alert(1);//" })[0], /break out/);
  assert.match(why(null, { n: '&#60;svg&#62;' })[0], /encoded/);
  assert.match(why(null, { n: 'x" + fetch("//evil") + "' })[0], /break out|browser code/);
  assert.match(why(null, { n: '<SVG/onload=alert(1)>' })[0], /HTML tag/);
});

test('bad key names are caught, and only new or changed text is checked', () => {
  assert.match(why(null, JSON.parse('{"__proto__":{"admin":true}}'))[0], /__proto__/);
  assert.match(why(null, { '<script>': 1 })[0], /in a key name/);
  const old = { name: '<b onclick=x>' };
  assert.deepEqual(why(old, { name: '<b onclick=x>', other: 'fine' }), []);
  assert.equal(why(old, { name: '<b onclick=y>' }).length, 1);
  assert.match(why(null, { big: 'x'.repeat(20001) })[0], /very long/);
  assert.deepEqual(why({ a: 1 }, null), []);
});

test('rules are compared rule by rule, comments allowed', () => {
  const before = '{ "rules": { // staff only\n "staff": { ".read": "auth != null", ".write": false }, "x": { ".read": false } } }';
  const after = '{ "rules": { "staff": { ".read": true, ".write": false }, "y": { ".read": false } } }';
  const d = W.rulesDiff(before, after);
  assert.equal(d.parsed, true);
  assert.deepEqual(d.changes.map((c) => c.path), ['rules/staff/.read', 'rules/x', 'rules/y']);
  assert.deepEqual(W.rulesLoosened(d.changes).map((c) => c.path), ['rules/staff/.read']);
  assert.equal(W.rulesDiff('{ bad', after).parsed, false);
  assert.deepEqual(W.parseRules('{"a":"// not a comment","b":"/* nor this */"}'), { a: '// not a comment', b: '/* nor this */' });
});

test('the live rules copy parses', () => {
  let text;
  try { text = require('fs').readFileSync('/mnt/project-files/reviews/2026-10-31/live-rules-2026-10-31.json', 'utf8'); } catch (e) { return; }
  assert.ok(W.parseRules(text).rules.staff);
  assert.deepEqual(W.rulesDiff(text, text).changes, []);
});

test('night and new-network sign-ins for staff only', () => {
  // 2026-11-02 07:30 UTC = 2:30 AM in Brandon (UTC-5)
  const night = { at: Date.UTC(2026, 10, 2, 7, 30), staff: true, email: 'gil@ec.com', ip: '24.77.1.2' };
  const day = Object.assign({}, night, { at: Date.UTC(2026, 10, 2, 15, 0) });
  assert.equal(W.localHour(night.at), 2);
  assert.deepEqual(W.signInOddities(night, null, 'k').map((a) => a.type), ['night_signin']);
  assert.match(W.signInOddities(night, null, 'k')[0].detail, /2:30 AM/);
  assert.deepEqual(W.signInOddities(day, null, 'k'), []);                    // first network: not news
  assert.deepEqual(W.signInOddities(day, { k: 1 }, 'k'), []);
  assert.deepEqual(W.signInOddities(day, { other: 1 }, 'k').map((a) => a.type), ['new_network']);
  assert.deepEqual(W.signInOddities(Object.assign({}, night, { staff: false }), null, 'k'), []);
  assert.equal(W.networkOf('24.77.1.2'), '24.77.x.x');
  assert.equal(W.networkOf('::ffff:24.77.1.2'), '24.77.x.x');
  assert.equal(W.networkOf('2001:db8:abcd:12::1'), '2001:db8:abcd::/48');
  assert.equal(W.networkOf(''), null);
});

test('punch times changed by a non-admin, and deleted shifts', () => {
  const s = { in: Date.UTC(2026, 10, 2, 13, 0), out: Date.UTC(2026, 10, 2, 22, 0) };
  const path = 'timeclock/shifts/bob@ec,com/s1';
  assert.deepEqual(W.shiftAlerts({ before: { in: s.in }, after: s, path, who: 'bob@ec.com', admin: false }), []);  // punch out
  const moved = W.shiftAlerts({ before: s, after: Object.assign({}, s, { in: s.in - 3600000 }), path, who: 'bob@ec.com', admin: false });
  assert.deepEqual(moved.map((a) => a.type), ['tc_punch_changed']);
  assert.match(moved[0].detail, /punch in 11-02 8:00 AM → 11-02 7:00 AM/);
  assert.deepEqual(W.shiftAlerts({ before: s, after: Object.assign({}, s, { out: s.out + 1 }), path, who: 'justin@ec.com', admin: true }), []);
  assert.deepEqual(W.shiftAlerts({ before: s, after: null, path, who: 'x', admin: true }).map((a) => a.type), ['tc_shift_deleted']);
  assert.deepEqual(W.shiftAlerts({ before: s, after: Object.assign({}, s, { oil: { done: true } }), path, who: 'x', admin: false }), []);
});

test('download spikes compare with the usual hour', () => {
  const day = Array(48).fill(20e6);  // 20 MB an hour
  assert.equal(W.usageSpike(30e6, day), null);
  assert.equal(W.usageSpike(150e6, day), null);                       // 7.5x but under 200 MB
  assert.equal(W.usageSpike(250e6, day).level, 'medium');
  assert.equal(W.usageSpike(250e6, day.slice(0, 10)), null);          // too little history yet
  assert.equal(W.usageSpike(2.5e9, []).level, 'high');
  assert.equal(W.usageSpike(NaN, day), null);
});

test('Google Cloud audit entries become alerts', () => {
  const entry = (methodName, who, extra) => Object.assign({ severity: 'NOTICE', protoPayload: { methodName,
    authenticationInfo: { principalEmail: who }, requestMetadata: { callerIp: '1.2.3.4' }, resourceName: 'projects/p' } }, extra);
  assert.equal(W.cloudLogAlert(entry('SetIamPolicy', 'mallory@gmail.com')).level, 'high');
  assert.equal(W.cloudLogAlert(entry('google.iam.admin.v1.CreateServiceAccountKey', 'a@b.c')).type, 'cloud_access');
  assert.equal(W.cloudLogAlert(entry('google.cloud.functions.v2.FunctionService.UpdateFunction', 'justin@ec.com')).type, 'cloud_functions');
  assert.equal(W.cloudLogAlert(entry('SetIamPolicy', 'robot@x'), ['robot@x']).level, 'medium');
  assert.equal(W.cloudLogAlert(entry('storage.objects.get', 'a@b.c')), null);
  assert.equal(W.cloudLogAlert(entry('storage.setIamPermissions', 'a@b.c')).level, 'high');
  assert.equal(W.cloudLogAlert(entry('storage.buckets.delete', 'a@b.c')).type, 'cloud_access');
  assert.equal(W.cloudLogAlert(entry('google.cloud.scheduler.v1.CloudScheduler.PauseJob', 'a@b.c')).level, 'low');
  assert.equal(W.cloudLogAlert(entry('SetIamPolicy', 'a@b.c', { severity: 'ERROR' })), null);
  assert.equal(W.cloudLogAlert(null), null);
});

test('each budget step alerts once', () => {
  const msg = { budgetDisplayName: 'E&C', costAmount: 6.1, budgetAmount: 10, currencyCode: 'CAD', alertThresholdExceeded: 0.5 };
  const got = W.budgetAlert(msg, null);
  assert.equal(got.step, 0.5);
  assert.match(got.alert.detail, /6\.10 CAD spent of 10\.00 CAD/);
  assert.equal(W.budgetAlert(msg, 0.5), null);
  assert.equal(W.budgetAlert(Object.assign({}, msg, { alertThresholdExceeded: 1 }), 0.5).alert.level, 'high');
  assert.equal(W.budgetAlert({ costAmount: 1 }, null), null);
});

test('GitHub deliveries that matter become alerts', () => {
  const base = { repository: { full_name: 'ogpoopdogg/dispatch', default_branch: 'main' }, sender: { login: 'someone' } };
  const ev = (e, extra) => W.githubAlert(e, Object.assign({}, base, extra));
  assert.equal(ev('member', { action: 'added', member: { login: 'mallory' } }).level, 'high');
  assert.equal(ev('deploy_key', { action: 'created', key: { title: 'k' } }).type, 'github_access');
  assert.equal(ev('repository', { action: 'publicized' }).level, 'high');
  assert.equal(ev('repository', { action: 'edited' }), null);
  assert.equal(ev('push', { ref: 'refs/heads/main', commits: [{}], head_commit: { message: 'x' } }).type, 'github_push');
  assert.equal(ev('push', { ref: 'refs/heads/main', forced: true, commits: [] }).level, 'high');
  assert.equal(ev('push', { ref: 'refs/heads/feature' }), null);
  assert.equal(ev('page_build', { build: { status: 'errored', error: { message: 'bad' } } }).type, 'github_site');
  assert.equal(ev('page_build', { build: { status: 'built' } }), null);
  assert.equal(ev('star', {}), null);
});

test('the heartbeat names watchers that stopped', () => {
  const now = Date.UTC(2026, 10, 2, 13, 0);
  const fresh = Object.fromEntries(Object.keys(W.EXPECTED).map((k) => [k, now - 60000]));
  assert.deepEqual(W.heartbeatProblems(fresh, now), []);
  const stale = Object.assign({}, fresh, { auditBackup: now - 30 * W.HOUR });
  delete stale.auditUserCensus;
  assert.deepEqual(W.heartbeatProblems(stale, now).map((p) => p.name).sort(), ['auditBackup', 'auditUserCensus']);
});
