/* PlutoScan payment setup watch – the parts that don't need Firebase, so they can be tested with
   `node --test`. Used by auditPlutoStripe (Stripe events), auditPlutoStripeCheck (the hourly look
   at Stripe) and auditPlutoCloudLog (Google Cloud audit logs) in index.js.

   Each change becomes a `changes` entry (shown under Database changes in the Security tab, area
   "PlutoScan: Stripe …" or "PlutoScan: Google Cloud"):
     { at, area, path, action: created|updated|deleted, by, fields: [{ f, b, a }], n, before, after }
   by says who or where it came from, as far as Stripe or Google tell:
     { type: 'stripe', request }            Stripe event; request = the API request id (req_…),
                                            null when Stripe made the change itself. Stripe does not
                                            send the Dashboard user or IP address in events.
     { type: 'google', email, ip, agent }   Google Cloud audit log: the Google account, its IP
                                            address and the tool it used (gcloud, firebase-tools, …)
     { type: 'check' }                      the hourly look at Stripe noticed it

   Secrets are never stored: a key shows at most its first 8 characters (sk_live_, rk_test_, …),
   and fields named like secrets, account or routing numbers are dropped from anything kept. */
'use strict';

const TEXT_MAX = 300;
const KEY_SHOWN = 8;
const FIELDS_MAX = 40;

function clip(v, max) {
  if (v == null || v === '') return null;
  return String(v).slice(0, max || TEXT_MAX);
}
function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

/** At most the first 8 characters of a key: enough to tell live from test and secret from restricted. */
function keyPrefix(key) { return key ? String(key).trim().slice(0, KEY_SHOWN) : null; }

const SECRETISH = /secret|password|token|routing_number|account_number|fingerprint|^iban$|client_secret/i;

/** A copy with secret-looking fields removed, nested at most 4 deep. */
function scrub(v, depth) {
  if (v == null) return null;
  if (typeof v === 'string') return v.slice(0, TEXT_MAX);
  if (typeof v !== 'object') return v;
  if ((depth || 0) > 4) return '(more)';
  if (Array.isArray(v)) return v.slice(0, 50).map((x) => scrub(x, (depth || 0) + 1));
  const out = {};
  for (const [k, x] of Object.entries(v)) if (!SECRETISH.test(k)) out[k] = scrub(x, (depth || 0) + 1);
  return out;
}

/** A value short enough for one line of the change list. */
function small(v) {
  if (v === undefined || v === null) return null;
  if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return typeof v === 'string' ? v.slice(0, TEXT_MAX) : v;
  const json = JSON.stringify(scrub(v));
  return json.length > TEXT_MAX ? json.slice(0, TEXT_MAX) + '…' : json;
}

function pick(o, keys) {
  const out = {};
  for (const k of keys) if (o && o[k] !== undefined && o[k] !== null) out[k] = scrub(o[k]);
  return out;
}

function money(amount, currency) {
  if (!Number.isFinite(amount)) return null;
  return (amount / 100).toFixed(2) + ' ' + String(currency || '').toUpperCase();
}

// ---------------------------------------------------------------- Stripe events

// What is kept of each kind of Stripe object (the whole object is never stored).
const KEEP = {
  product: ['name', 'active', 'default_price', 'description', 'livemode'],
  price: ['product', 'active', 'unit_amount', 'currency', 'type', 'nickname', 'lookup_key', 'recurring', 'livemode'],
  bank_account: ['bank_name', 'last4', 'country', 'currency', 'status', 'default_for_currency', 'account_holder_name'],
  card: ['brand', 'last4', 'country', 'currency', 'default_for_currency'],
  payout: ['amount', 'currency', 'status', 'arrival_date', 'destination', 'method', 'type', 'automatic', 'failure_code', 'failure_message'],
  account: ['email', 'country', 'default_currency', 'charges_enabled', 'payouts_enabled', 'details_submitted', 'business_profile']
};

/** The event types auditPlutoStripe watches for the payment setup (the Stripe dashboard list in the README). */
const SETUP_EVENTS = [
  'product.created', 'product.updated', 'product.deleted',
  'price.created', 'price.updated', 'price.deleted',
  'account.updated',
  'account.external_account.created', 'account.external_account.updated', 'account.external_account.deleted',
  'payout.created', 'payout.updated', 'payout.paid', 'payout.failed', 'payout.canceled', 'payout.reconciliation_completed'
];

function stripeBy(ev) {
  return { type: 'stripe', request: clip(ev && ev.request && ev.request.id, 80) || null };
}

/** Where the change came from, in words, for alert text. */
function stripeByText(by) {
  return by.request ? 'Stripe API request ' + by.request + ' (look it up in Stripe: Developers, then Logs)' : 'made by Stripe itself (no API request)';
}

/** Changed fields of an `updated` event, from Stripe's previous_attributes. */
function updatedFields(prev, now) {
  if (!isObj(prev)) return [];
  return Object.keys(prev).filter((k) => k !== 'updated' && !SECRETISH.test(k)).sort().slice(0, FIELDS_MAX)
    .map((k) => ({ f: k, b: small(prev[k]), a: small(now ? now[k] : null) }));
}

function nameOf(o) {
  if (o.object === 'product') return o.name ? ' "' + clip(o.name, 80) + '"' : '';
  if (o.object === 'price') return ' (' + [money(o.unit_amount, o.currency), o.product].filter(Boolean).join(', ') + ')';
  if (o.object === 'bank_account') return ' (' + [o.bank_name, o.last4 ? 'ending ' + o.last4 : null, o.currency ? String(o.currency).toUpperCase() : null].filter(Boolean).join(', ') + ')';
  if (o.object === 'card') return ' (' + [o.brand, o.last4 ? 'ending ' + o.last4 : null].filter(Boolean).join(', ') + ')';
  if (o.object === 'payout') return ' (' + [money(o.amount, o.currency), o.status].filter(Boolean).join(', ') + ')';
  return '';
}

/**
 * The change entry and alert for a Stripe payment setup event, or null for other events.
 * Also returns payoutDestination for payout events, so the caller can spot a payout going to a
 * different bank account than the last one.
 */
function stripeSetupChange(ev, at) {
  if (!ev || !SETUP_EVENTS.includes(ev.type)) return null;
  const o = (ev.data && ev.data.object) || {};
  const prev = ev.data && ev.data.previous_attributes;
  const verb = ev.type.split('.').pop();
  const action = verb === 'created' ? 'created' : verb === 'deleted' ? 'deleted' : 'updated';
  const by = stripeBy(ev);
  const kind = ev.type.startsWith('account.external_account') ? 'external_account' : ev.type.split('.')[0];
  const keep = KEEP[o.object] || KEEP[kind] || [];
  const snap = pick(o, keep);
  const fields = action === 'updated' ? updatedFields(prev, o) : [];
  const test = ev.livemode === false ? ' (Stripe test mode)' : '';
  const id = clip(o.id, 80) || '?';
  const change = {
    at, by, action, stripeEvent: clip(ev.id, 80), livemode: !!ev.livemode,
    fields, n: fields.length,
    before: action === 'created' ? null : action === 'deleted' ? snap : (isObj(prev) ? Object.fromEntries(fields.map((x) => [x.f, x.b])) : null),
    after: action === 'deleted' ? null : snap
  };
  let alert = null;
  if (kind === 'product' || kind === 'price') {
    const archived = action === 'updated' && isObj(prev) && prev.active === true && o.active === false;
    const restored = action === 'updated' && isObj(prev) && prev.active === false && o.active === true;
    const word = archived ? 'archived' : restored ? 'made active again' : action;
    change.area = 'Stripe products and prices';
    change.path = kind + ' ' + id + nameOf(o);
    alert = { type: 'stripe_catalog', level: archived || action === 'deleted' ? 'high' : 'medium',
      title: 'Stripe ' + kind + ' ' + word,
      detail: 'Stripe ' + kind + ' ' + id + nameOf(o) + ' was ' + word + (fields.length ? ' (' + fields.map((x) => x.f).join(', ') + ')' : '') + '. ' + stripeByText(by) + '.' + test };
  } else if (kind === 'external_account') {
    change.area = 'Stripe bank accounts';
    change.path = (o.object === 'card' ? 'debit card ' : 'bank account ') + id + nameOf(o);
    alert = { type: 'stripe_bank', level: 'high', title: 'Stripe payout bank account ' + action,
      detail: 'The bank account or card Stripe pays out to was ' + action + ': ' + change.path + '. ' + stripeByText(by) + '. If this wasn\'t you, sign in to Stripe now.' + test };
  } else if (kind === 'account') {
    change.area = 'Stripe account settings';
    change.path = 'account ' + id;
    alert = { type: 'stripe_account', level: fields.some((x) => /external_accounts|payouts_enabled|email|settings/.test(x.f)) ? 'high' : 'medium',
      title: 'Stripe account settings changed',
      detail: 'Your Stripe account ' + id + ' changed' + (fields.length ? ': ' + fields.map((x) => x.f).join(', ') : '') + '. ' + stripeByText(by) + '.' + test };
  } else if (kind === 'payout') {
    change.area = 'Stripe payouts';
    change.path = 'payout ' + id + nameOf(o);
    if (verb === 'failed' || verb === 'canceled') {
      alert = { type: 'stripe_payout', level: 'medium', title: 'Stripe payout ' + verb,
        detail: 'Payout ' + id + nameOf(o) + ' ' + verb + (o.failure_message ? ': ' + clip(o.failure_message, 200) : '') + '.' + test };
    }
  }
  return { change, alert, payoutDestination: kind === 'payout' ? clip(o.destination, 80) : null, livemode: !!ev.livemode };
}

/** The alert when a payout goes to a different bank account than the last payout, or null. */
function payoutDestinationAlert(before, now, payoutId) {
  if (!before || !now || before === now) return null;
  return { type: 'stripe_bank', level: 'high', title: 'Stripe payout going to a different bank account',
    detail: 'Payout ' + (payoutId || '?') + ' goes to ' + now + '; the last payout went to ' + before + '. If you didn\'t change your bank account, sign in to Stripe now.' };
}

// ---------------------------------------------------------------- the hourly look at Stripe

/** What is compared of a webhook endpoint. The signing secret is never part of it. */
function endpointView(e) {
  return {
    url: clip(e.url, 300), status: clip(e.status, 20),
    events: (Array.isArray(e.enabled_events) ? e.enabled_events.slice().sort() : []).join(', ').slice(0, 2000),
    api_version: clip(e.api_version, 40), description: clip(e.description, 200), livemode: !!e.livemode
  };
}
function endpointMap(list) {
  const out = {};
  for (const e of list || []) if (e && e.id) out[String(e.id).replace(/[.#$[\]/]/g, '_').slice(0, 100)] = endpointView(e);
  return out;
}

function priceState(status, body) {
  if (status === 404) return { state: 'missing' };
  if (status !== 200 || !body) return { state: 'error', status };
  return { state: body.active ? 'ok' : 'archived', amount: money(body.unit_amount, body.currency), product: clip(body.product, 80), livemode: !!body.livemode };
}

const PRICE_WORDS = { missing: 'does not exist', archived: 'is archived', error: 'could not be checked' };

function summary(s) {
  return {
    account: s.account || null, keyStart: s.keyStart || null, keyVersion: s.keyVersion || null, latestKeyVersion: s.latestKeyVersion || null,
    priceId: s.priceId || null, price: s.price ? s.price.state : null, webhookEndpoints: Object.keys(s.endpoints || {}).length
  };
}

/**
 * Compares this hour's look at Stripe with the last one. Returns { changes, alerts } (each
 * change still needs `at`). prev is null on the very first look. cur.error is set when the look
 * couldn't finish; then only the error is compared.
 */
function checkDiff(prev, cur) {
  const changes = [];
  const alerts = [];
  const by = { type: 'check' };
  const ch = (path, action, fields, before, after) => changes.push({ area: 'Stripe hourly check', path, action, by, fields, n: fields.length, before, after });

  if (cur.error) {
    if (!prev || prev.error !== cur.error) {
      ch('check could not finish', 'updated', [{ f: 'problem', b: prev && prev.error || null, a: cur.error }], null, null);
      alerts.push({ type: 'stripe_key', level: /refused the key|401|403/.test(cur.error) ? 'high' : 'medium', title: 'Stripe check could not finish',
        detail: cur.error + ' Checkout may not work. Look at the PlutoScan functions in the Firebase console.' });
    }
    return { changes, alerts };
  }
  if (prev && prev.error) ch('check working again', 'updated', [{ f: 'problem', b: prev.error, a: null }], null, null);

  if (!prev || !prev.account) {
    ch('first look', 'created', [], null, summary(cur));
  } else {
    if (prev.account !== cur.account) {
      ch('Stripe account used by checkout', 'updated', [{ f: 'account', b: prev.account, a: cur.account }], null, null);
      alerts.push({ type: 'stripe_key', level: 'high', title: 'Checkout now uses a different Stripe account',
        detail: 'STRIPE_SECRET_KEY now belongs to Stripe account ' + cur.account + ' (it was ' + prev.account + '). Products, prices and webhooks are separate in each account.' });
    }
    if (prev.keyStart !== cur.keyStart) {
      ch('STRIPE_SECRET_KEY kind', 'updated', [{ f: 'key starts with', b: prev.keyStart, a: cur.keyStart }], null, null);
      alerts.push({ type: 'stripe_key', level: 'high', title: 'Stripe key changed kind',
        detail: 'The key checkout uses now starts with ' + cur.keyStart + ' (it started with ' + prev.keyStart + '): ' + (/test/.test(cur.keyStart || '') ? 'that is a TEST key, real cards won\'t be charged.' : 'check it is the key you meant.') });
    }
    if (prev.keyVersion !== cur.keyVersion) {
      ch('STRIPE_SECRET_KEY version used by checkout', 'updated', [{ f: 'version', b: prev.keyVersion, a: cur.keyVersion }], null, null);
      alerts.push({ type: 'stripe_key', level: 'medium', title: 'Checkout uses a new Stripe key version',
        detail: 'createCheckoutSession now uses version ' + cur.keyVersion + ' of STRIPE_SECRET_KEY (it used ' + prev.keyVersion + '). Same Stripe account: ' + cur.account + '.' });
    }
    if (prev.latestKeyVersion !== cur.latestKeyVersion && cur.latestKeyVersion !== cur.keyVersion) {
      ch('STRIPE_SECRET_KEY newest version (not yet used by checkout)', 'updated', [{ f: 'newest version', b: prev.latestKeyVersion, a: cur.latestKeyVersion }], null, null);
    }
    if (prev.priceId !== cur.priceId) {
      ch('STRIPE_PRICE_ID used by checkout', 'updated', [{ f: 'price id', b: prev.priceId, a: cur.priceId }], null, null);
      alerts.push({ type: 'stripe_key', level: 'medium', title: 'Checkout now sells a different price',
        detail: 'STRIPE_PRICE_ID changed from ' + (prev.priceId || 'none') + ' to ' + (cur.priceId || 'none') + '.' });
    }
  }

  // The price checkout sells: alert when it goes bad (or is bad at the first look), note when it's fixed.
  const was = prev && prev.price ? prev.price.state : null;
  const now = cur.price ? cur.price.state : null;
  if (now && now !== 'ok' && (was !== now || (prev && prev.priceId !== cur.priceId))) {
    alerts.push({ type: 'checkout_broken', level: 'high', title: 'PlutoScan checkout is broken',
      detail: 'The price checkout uses (' + (cur.priceId || 'STRIPE_PRICE_ID not set') + ') ' + (PRICE_WORDS[now] || now) + ' in Stripe account ' + cur.account + '. Nobody can buy the course until this is fixed.' });
    ch('checkout price', 'updated', [{ f: 'price ' + (cur.priceId || '(none)'), b: was, a: now }], null, null);
  } else if (now === 'ok' && was && was !== 'ok') {
    ch('checkout price', 'updated', [{ f: 'price ' + cur.priceId, b: was, a: 'ok' }], null, null);
  }
  if (!cur.priceId && (!prev || prev.priceId)) {
    alerts.push({ type: 'checkout_broken', level: 'high', title: 'PlutoScan checkout has no price set',
      detail: 'createCheckoutSession has no STRIPE_PRICE_ID, so checkout cannot start.' });
  }

  // Webhook endpoints (Stripe sends no event when these change, so they're compared here).
  if (prev && prev.account === cur.account && prev.endpoints) {
    const a = prev.endpoints || {};
    const b = cur.endpoints || {};
    const lines = [];
    for (const id of new Set([...Object.keys(a), ...Object.keys(b)])) {
      if (!a[id]) {
        ch('webhook endpoint ' + id, 'created', [], null, b[id]);
        lines.push('added ' + (b[id].url || id));
      } else if (!b[id]) {
        ch('webhook endpoint ' + id, 'deleted', [], a[id], null);
        lines.push('removed ' + (a[id].url || id));
      } else {
        const fields = Object.keys(b[id]).filter((k) => a[id][k] !== b[id][k]).map((k) => ({ f: k, b: a[id][k], a: b[id][k] }));
        if (fields.length) {
          ch('webhook endpoint ' + id, 'updated', fields, a[id], b[id]);
          lines.push('changed ' + (b[id].url || id) + ' (' + fields.map((x) => x.f).join(', ') + ')');
        }
      }
    }
    if (lines.length) {
      alerts.push({ type: 'stripe_webhooks', level: 'high', title: 'Stripe webhook endpoints changed',
        detail: 'In the last hour: ' + lines.join('; ').slice(0, 450) + '. Stripe does not say who; see Developers, then Logs in Stripe.' });
    }
  }
  return { changes, alerts };
}

// ---------------------------------------------------------------- Google Cloud audit logs

const PAYMENT_FUNCTIONS = ['createCheckoutSession', 'stripeWebhook', 'getModuleContent'];

/**
 * The change entry and alert for one Admin Activity audit log entry (from the log sink, through
 * Pub/Sub), or null for entries not watched. Only names, the caller and the result are kept: the
 * request body is never read, so a secret's value can't end up in the log.
 */
function cloudChange(entry, at) {
  const p = entry && entry.protoPayload;
  if (!p || typeof p.methodName !== 'string') return null;
  // Long-running calls are logged at the start and at the end; the start says who did it.
  if (entry.operation && entry.operation.last && !entry.operation.first) return null;
  const m = p.methodName;
  const res = String(p.resourceName || '');
  const auth = p.authenticationInfo || {};
  const meta = p.requestMetadata || {};
  const by = { type: 'google', email: clip(auth.principalEmail, 120) || 'unknown account', ip: clip(meta.callerIp, 64), agent: clip(meta.callerSuppliedUserAgent, 120) };
  const failed = !!(p.status && p.status.code);
  const ok = failed ? ' (it failed: ' + (clip(p.status.message, 120) || 'code ' + p.status.code) + ')' : '';
  const from = by.email + (by.ip ? ' from IP ' + by.ip : '');
  const base = { at, by, area: 'Google Cloud', fields: [{ f: 'method', b: null, a: clip(m, 120) }], n: 1, before: null, after: { resource: clip(res, 300), ok: !failed }, ok: !failed };
  let mm;

  if ((mm = /SecretManagerService\.(\w+)$/.exec(m))) {
    const what = mm[1];
    const sec = /secrets\/([^/]+)(?:\/versions\/([^/]+))?/.exec(res + ' ' + String((p.response && p.response.name) || '')) || [];
    const name = sec[1] || '?';
    const version = sec[2] || (/\/versions\/([^/\s]+)/.exec(String((p.response && p.response.name) || '')) || [])[1] || null;
    const words = { AddSecretVersion: 'added a new version of', CreateSecret: 'created', DeleteSecret: 'deleted', UpdateSecret: 'changed the settings of',
      DisableSecretVersion: 'disabled a version of', EnableSecretVersion: 'turned on a version of', DestroySecretVersion: 'destroyed a version of', SetIamPolicy: 'changed who can read' };
    if (!words[what]) return null;
    const stripe = /^STRIPE_/.test(name);
    const change = Object.assign(base, { path: 'secret ' + name + (version ? ' version ' + version : ''), action: what === 'CreateSecret' ? 'created' : what === 'DeleteSecret' ? 'deleted' : 'updated' });
    const titles = { AddSecretVersion: 'new version added', CreateSecret: 'created', DeleteSecret: 'deleted', UpdateSecret: 'settings changed',
      DisableSecretVersion: 'version disabled', EnableSecretVersion: 'version turned on', DestroySecretVersion: 'version destroyed', SetIamPolicy: 'access changed' };
    return { change, alert: { type: 'secret_changed', level: stripe ? 'high' : 'medium', title: 'Secret ' + name + ': ' + titles[what],
      detail: from + ' ' + words[what] + ' the secret ' + name + (version ? ' (version ' + version + ')' : '') + ok + '.' + (stripe && what === 'AddSecretVersion' ? ' Functions keep the old version until they are deployed again.' : '') } };
  }

  if ((mm = /functions\.v\d\w*\.\w+\.(CreateFunction|UpdateFunction|DeleteFunction)$/.exec(m))) {
    const fn = (/functions\/([^/]+)/.exec(res) || [])[1] || '?';
    const verb = { CreateFunction: 'created', UpdateFunction: 'updated', DeleteFunction: 'deleted' }[mm[1]];
    const change = Object.assign(base, { path: 'function ' + fn, action: verb });
    if (!PAYMENT_FUNCTIONS.includes(fn)) return { change, alert: null };
    return { change, alert: { type: 'payment_deploy', level: verb === 'deleted' ? 'high' : 'medium', title: 'Payment function ' + fn + ' ' + (verb === 'deleted' ? 'deleted' : 'deployed'),
      detail: from + ' ' + (verb === 'deleted' ? 'deleted' : 'deployed') + ' ' + fn + (by.agent ? ' with ' + by.agent.split(' ')[0] : '') + ok + '.' } };
  }

  let what = null;
  if (/SetIamPolicy$/.test(m) && /cloudresourcemanager/.test(String(p.serviceName || ''))) what = 'changed who has access to the plutoscan project';
  else if (/ConfigServiceV2\.(CreateSink|UpdateSink|DeleteSink|CreateExclusion|UpdateExclusion|DeleteExclusion)$/.test(m)) what = 'changed the log feed (log sinks) this watch depends on';
  else if (/Publisher\.DeleteTopic$/.test(m)) what = 'deleted a Pub/Sub topic';
  if (!what) return null;
  const change = Object.assign(base, { path: clip(res, 200) || m, action: 'updated' });
  return { change, alert: { type: 'cloud_change', level: 'high', title: 'Google Cloud: ' + by.email + ' ' + what.split(' ').slice(0, 3).join(' '),
    detail: from + ' ' + what + ' (' + (clip(res, 150) || m) + ')' + ok + '.' } };
}

module.exports = {
  KEY_SHOWN, SETUP_EVENTS, PAYMENT_FUNCTIONS,
  keyPrefix, scrub, small, stripeSetupChange, payoutDestinationAlert,
  endpointView, endpointMap, priceState, checkDiff, cloudChange
};
