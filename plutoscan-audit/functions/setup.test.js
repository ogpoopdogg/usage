'use strict';
const test = require('node:test');
const assert = require('node:assert');
const S = require('./setup');
const T = require('../../functions/alert-types');

const AT = 1763150000000;
const typed = (a) => assert.ok(T.TYPES['pluto_' + a.type], 'unknown alert type ' + a.type);

test('a key never shows more than its first 8 characters', () => {
  assert.strictEqual(S.keyPrefix('sk_live_51ABCDEFsecretpart'), 'sk_live_');
  assert.strictEqual(S.keyPrefix(' rk_test_xyz '), 'rk_test_');
  assert.strictEqual(S.keyPrefix(''), null);
});

test('secret-looking fields are dropped from anything kept', () => {
  const out = S.scrub({ url: 'u', secret: 'whsec_x', bank: { routing_number: '110000000', last4: '6789', account_number: '000123' } });
  assert.deepStrictEqual(out, { url: 'u', bank: { last4: '6789' } });
});

test('price archived in Stripe: high alert with the request id', () => {
  const ev = { id: 'evt_1', type: 'price.updated', livemode: true, request: { id: 'req_abc', idempotency_key: null },
    data: { object: { id: 'price_1', object: 'price', active: false, unit_amount: 1699, currency: 'cad', product: 'prod_1' }, previous_attributes: { active: true } } };
  const got = S.stripeSetupChange(ev, AT);
  assert.strictEqual(got.change.area, 'Stripe products and prices');
  assert.strictEqual(got.change.action, 'updated');
  assert.deepStrictEqual(got.change.fields, [{ f: 'active', b: true, a: false }]);
  assert.deepStrictEqual(got.change.by, { type: 'stripe', request: 'req_abc' });
  assert.strictEqual(got.alert.level, 'high');
  assert.match(got.alert.title, /archived/);
  assert.match(got.alert.detail, /req_abc/);
  assert.match(got.change.path, /16\.99 CAD/);
  typed(got.alert);
});

test('product made with no API request says Stripe did it itself', () => {
  const ev = { id: 'evt_2', type: 'product.created', livemode: false, request: { id: null },
    data: { object: { id: 'prod_9', object: 'product', name: 'Course', active: true } } };
  const got = S.stripeSetupChange(ev, AT);
  assert.strictEqual(got.change.action, 'created');
  assert.strictEqual(got.change.before, null);
  assert.deepStrictEqual(got.change.after, { name: 'Course', active: true });
  assert.strictEqual(got.alert.level, 'medium');
  assert.match(got.alert.detail, /Stripe itself/);
  assert.match(got.alert.detail, /test mode/);
});

test('bank account added: high alert, no routing number kept', () => {
  const ev = { id: 'evt_3', type: 'account.external_account.created', livemode: true, request: { id: 'req_x' },
    data: { object: { id: 'ba_1', object: 'bank_account', bank_name: 'RBC', last4: '4321', currency: 'cad', routing_number: '000312345', fingerprint: 'fp' } } };
  const got = S.stripeSetupChange(ev, AT);
  assert.strictEqual(got.alert.type, 'stripe_bank');
  assert.strictEqual(got.alert.level, 'high');
  assert.ok(!JSON.stringify(got).includes('000312345'));
  assert.ok(!JSON.stringify(got).includes('fingerprint'));
  typed(got.alert);
});

test('payouts: logged, alert only when failed; a new destination raises a high alert', () => {
  const paid = S.stripeSetupChange({ id: 'e', type: 'payout.paid', livemode: true, request: null,
    data: { object: { id: 'po_1', object: 'payout', amount: 1699, currency: 'cad', status: 'paid', destination: 'ba_1' } } }, AT);
  assert.strictEqual(paid.alert, null);
  assert.strictEqual(paid.payoutDestination, 'ba_1');
  const failed = S.stripeSetupChange({ id: 'e2', type: 'payout.failed', livemode: true,
    data: { object: { id: 'po_2', object: 'payout', status: 'failed', failure_message: 'closed', destination: 'ba_1' } } }, AT);
  assert.strictEqual(failed.alert.type, 'stripe_payout');
  assert.strictEqual(S.payoutDestinationAlert('ba_1', 'ba_1', 'po_3'), null);
  assert.strictEqual(S.payoutDestinationAlert(null, 'ba_1', 'po_3'), null);
  const moved = S.payoutDestinationAlert('ba_1', 'ba_2', 'po_3');
  assert.strictEqual(moved.level, 'high');
  typed(moved);
});

test('events that are not about the payment setup are ignored', () => {
  assert.strictEqual(S.stripeSetupChange({ type: 'charge.succeeded', data: { object: {} } }, AT), null);
  for (const t of S.SETUP_EVENTS) assert.match(t, /^(product|price|account|payout)\./);
});

const hooks = (list) => S.endpointMap(list);
const good = {
  account: 'acct_A', keyStart: 'sk_live_', keyVersion: '3', latestKeyVersion: '3', priceId: 'price_1',
  price: { state: 'ok' },
  endpoints: hooks([{ id: 'we_1', url: 'https://x/stripeWebhook', status: 'enabled', enabled_events: ['checkout.session.completed'], secret: 'whsec_should_not_be_kept' }])
};

test('endpoint view never keeps the signing secret', () => {
  assert.ok(!JSON.stringify(good.endpoints).includes('whsec_'));
});

test('first look: one entry, no alert when all is well', () => {
  const r = S.checkDiff(null, good);
  assert.strictEqual(r.alerts.length, 0);
  assert.strictEqual(r.changes.length, 1);
  assert.strictEqual(r.changes[0].path, 'first look');
  assert.strictEqual(r.changes[0].after.account, 'acct_A');
  assert.strictEqual(r.changes[0].after.keyStart, 'sk_live_');
});

test('first look with a missing price (today\'s "No such price"): checkout broken alert', () => {
  const r = S.checkDiff(null, Object.assign({}, good, { price: { state: 'missing' } }));
  assert.strictEqual(r.alerts.length, 1);
  assert.strictEqual(r.alerts[0].type, 'checkout_broken');
  assert.match(r.alerts[0].detail, /does not exist in Stripe account acct_A/);
  typed(r.alerts[0]);
  // The next hour, still missing: no second alert
  assert.strictEqual(S.checkDiff(Object.assign({}, good, { price: { state: 'missing' } }), Object.assign({}, good, { price: { state: 'missing' } })).alerts.length, 0);
});

test('a different Stripe account is a high alert; same state is quiet', () => {
  assert.deepStrictEqual(S.checkDiff(good, good), { changes: [], alerts: [] });
  const r = S.checkDiff(good, Object.assign({}, good, { account: 'acct_B', keyVersion: '4', latestKeyVersion: '4' }));
  const types = r.alerts.map((a) => a.type + ':' + a.level);
  assert.ok(types.includes('stripe_key:high'));
  assert.ok(types.includes('stripe_key:medium'));
  r.alerts.forEach(typed);
});

test('webhook endpoints added, changed and removed', () => {
  const now = Object.assign({}, good, { endpoints: hooks([
    { id: 'we_1', url: 'https://x/stripeWebhook', status: 'disabled', enabled_events: ['checkout.session.completed'] },
    { id: 'we_2', url: 'https://evil.example/hook', status: 'enabled', enabled_events: ['*'] }
  ]) });
  const r = S.checkDiff(good, now);
  assert.strictEqual(r.alerts.length, 1);
  assert.strictEqual(r.alerts[0].type, 'stripe_webhooks');
  assert.match(r.alerts[0].detail, /added https:\/\/evil\.example\/hook/);
  assert.match(r.alerts[0].detail, /changed https:\/\/x\/stripeWebhook \(status\)/);
  assert.deepStrictEqual(r.changes.map((c) => c.action).sort(), ['created', 'updated']);
  const gone = S.checkDiff(now, Object.assign({}, good, { endpoints: {} }));
  assert.match(gone.alerts[0].detail, /removed/);
});

test('a check that cannot finish alerts once, then again only when the problem changes', () => {
  const bad = { error: 'Stripe refused the key checkout uses (HTTP 401, key starts sk_live_).' };
  const r = S.checkDiff(good, bad);
  assert.strictEqual(r.alerts[0].level, 'high');
  assert.strictEqual(S.checkDiff(Object.assign({}, good, bad), bad).alerts.length, 0);
  const back = S.checkDiff(Object.assign({}, good, bad), good);
  assert.strictEqual(back.alerts.length, 0);
  assert.strictEqual(back.changes[0].path, 'check working again');
});

function auditEntry(methodName, resourceName, extra) {
  return Object.assign({ protoPayload: { methodName, resourceName, serviceName: extra && extra.service || 'x',
    authenticationInfo: { principalEmail: 'someone@example.com' }, requestMetadata: { callerIp: '203.0.113.9', callerSuppliedUserAgent: 'google-cloud-sdk gcloud/500' },
    request: { payload: { data: 'c2tfbGl2ZV9zZWNyZXQ=' } } } }, extra && extra.entry);
}

test('new STRIPE_SECRET_KEY version: high alert with account and IP, never the value', () => {
  const got = S.cloudChange(auditEntry('google.cloud.secretmanager.v1.SecretManagerService.AddSecretVersion', 'projects/123/secrets/STRIPE_SECRET_KEY'), AT);
  assert.strictEqual(got.alert.type, 'secret_changed');
  assert.strictEqual(got.alert.level, 'high');
  assert.match(got.alert.detail, /someone@example\.com from IP 203\.0\.113\.9 added a new version of the secret STRIPE_SECRET_KEY/);
  assert.deepStrictEqual(got.change.by, { type: 'google', email: 'someone@example.com', ip: '203.0.113.9', agent: 'google-cloud-sdk gcloud/500' });
  assert.ok(!JSON.stringify(got).includes('c2tfbGl2ZV9zZWNyZXQ'));
  typed(got.alert);
  const other = S.cloudChange(auditEntry('google.cloud.secretmanager.v1.SecretManagerService.AddSecretVersion', 'projects/123/secrets/PLUTOSCAN_AUDIT_KEY'), AT);
  assert.strictEqual(other.alert.level, 'medium');
});

test('function deploys: payment functions alert, audit functions are only logged, LRO end ignored', () => {
  const dep = S.cloudChange(auditEntry('google.cloud.functions.v2.FunctionService.UpdateFunction', 'projects/plutoscan/locations/us-central1/functions/createCheckoutSession', { entry: { operation: { first: true } } }), AT);
  assert.strictEqual(dep.alert.type, 'payment_deploy');
  assert.strictEqual(dep.change.path, 'function createCheckoutSession');
  typed(dep.alert);
  const del = S.cloudChange(auditEntry('google.cloud.functions.v2.FunctionService.DeleteFunction', 'projects/p/locations/l/functions/stripeWebhook'), AT);
  assert.strictEqual(del.alert.level, 'high');
  const audit = S.cloudChange(auditEntry('google.cloud.functions.v2.FunctionService.UpdateFunction', 'projects/p/locations/l/functions/auditPlutoCensus'), AT);
  assert.strictEqual(audit.alert, null);
  assert.ok(audit.change);
  assert.strictEqual(S.cloudChange(auditEntry('google.cloud.functions.v2.FunctionService.UpdateFunction', 'projects/p/locations/l/functions/stripeWebhook', { entry: { operation: { last: true } } }), AT), null);
});

test('access and log feed changes are high; unrelated entries ignored', () => {
  const iam = S.cloudChange(auditEntry('SetIamPolicy', 'projects/plutoscan', { service: 'cloudresourcemanager.googleapis.com' }), AT);
  assert.strictEqual(iam.alert.type, 'cloud_change');
  typed(iam.alert);
  const sink = S.cloudChange(auditEntry('google.logging.v2.ConfigServiceV2.DeleteSink', 'projects/plutoscan/sinks/plutoscan-cloud-log'), AT);
  assert.strictEqual(sink.alert.level, 'high');
  assert.strictEqual(S.cloudChange(auditEntry('google.cloud.run.v2.Services.UpdateService', 'x'), AT), null);
  assert.strictEqual(S.cloudChange(null, AT), null);
});

test('can take payments: problems alert once when they appear, and are noted when fixed', () => {
  const okAcct = { charges_enabled: true, payouts_enabled: true, requirements: { currently_due: [], past_due: [], disabled_reason: null } };
  const hook = [{ id: 'we_1', url: 'https://us-central1-plutoscan.cloudfunctions.net/stripeWebhook', status: 'enabled' }];
  const fine = Object.assign({}, good, { payments: S.paymentsState(okAcct, hook) });
  assert.deepStrictEqual(S.paymentProblems(fine.payments), []);
  assert.strictEqual(S.checkDiff(null, fine).alerts.length, 0);
  assert.strictEqual(S.checkDiff(null, fine).changes[0].after.canTakePayments, 'yes');

  const blocked = Object.assign({}, good, { payments: S.paymentsState(
    { charges_enabled: false, payouts_enabled: false, requirements: { past_due: ['individual.id_number'], currently_due: ['individual.id_number'], disabled_reason: 'requirements.past_due' } },
    [{ url: 'https://x/stripeWebhook', status: 'disabled' }]) });
  const r = S.checkDiff(fine, blocked);
  assert.strictEqual(r.alerts.length, 1);
  assert.strictEqual(r.alerts[0].type, 'payments_blocked');
  assert.strictEqual(r.alerts[0].level, 'high');
  assert.match(r.alerts[0].detail, /turned off card payments.*requirements\.past_due/);
  assert.match(r.alerts[0].detail, /overdue/);
  assert.match(r.alerts[0].detail, /paused payouts/);
  assert.match(r.alerts[0].detail, /turned off in Stripe/);
  typed(r.alerts[0]);
  // Same problems next hour: quiet. Fixed: a note, no alert.
  assert.strictEqual(S.checkDiff(blocked, blocked).alerts.length, 0);
  const fixed = S.checkDiff(blocked, fine);
  assert.strictEqual(fixed.alerts.length, 0);
  assert.ok(fixed.changes.some((c) => c.path === 'can take payments' && c.fields.every((f) => f.a === 'fixed')));
  // No stripeWebhook endpoint at all
  assert.match(S.paymentProblems(S.paymentsState(okAcct, [])).map((p) => p.text).join(' '), /no webhook to stripeWebhook/);
  // Information due later is medium, with the date
  const due = S.paymentProblems(S.paymentsState({ charges_enabled: true, requirements: { currently_due: ['a'], past_due: [], current_deadline: 1767225600 } }, hook));
  assert.strictEqual(due[0].level, 'medium');
  assert.match(due[0].text, /by 2026-01-01/);
});

// The database never stores null: what comes back from the last look is missing those fields.
function asStored(v) {
  if (v === null || typeof v !== 'object') return v;
  const out = Array.isArray(v) ? [] : {};
  for (const [k, x] of Object.entries(v)) if (x !== null && x !== undefined) out[k] = asStored(x);
  return out;
}

test('a look read back from the database (nulls dropped) compares the same as before: no false alarms', () => {
  const okAcct = { charges_enabled: true, payouts_enabled: true, requirements: { currently_due: [], past_due: [], disabled_reason: null } };
  const list = [
    { id: 'we_1', url: 'https://us-central1-plutoscan.cloudfunctions.net/auditPlutoStripe', status: 'enabled', enabled_events: ['price.updated'], description: null, api_version: null },
    { id: 'we_2', url: 'https://us-central1-plutoscan.cloudfunctions.net/stripeWebhook', status: 'enabled', enabled_events: ['checkout.session.completed'], description: '' }
  ];
  const look = { account: 'acct_A', keyStart: 'sk_live_', keyVersion: '5', latestKeyVersion: '5', priceId: 'price_1', price: { state: 'ok', amount: null },
    endpoints: S.endpointMap(list), payments: S.paymentsState(okAcct, list) };
  assert.deepStrictEqual(S.checkDiff(asStored(look), look), { changes: [], alerts: [] });
  // A real description change is still caught
  const renamed = Object.assign({}, look, { endpoints: S.endpointMap([Object.assign({}, list[0], { description: 'changed by someone' }), list[1]]) });
  const r = S.checkDiff(asStored(look), renamed);
  assert.strictEqual(r.alerts.length, 1);
  assert.match(r.alerts[0].detail, /auditPlutoStripe \(description\)/);
});
