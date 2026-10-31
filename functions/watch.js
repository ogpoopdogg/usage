/* E&C security log – the extra watches added on 2026-10-31, the parts that don't need Firebase
   (tested with `node --test`). index.js calls these and writes the alerts.

   - suspiciousValues: text saved in the database that looks like an attempt to run code in the
     apps (script tags, event handlers, javascript: links) or to break the database's keys.
   - rulesDiff: what changed between two copies of the database rules.
   - signInOddities: a staff sign-in in the middle of the night, or from a network the account
     hasn't used before.
   - shiftAlerts: time clock punches changed after the fact, or deleted.
   - usageSpike: an hour where far more data was downloaded from the database than usual.
   - cloudLogAlert: Google Cloud changes worth knowing about (who can get in, keys, functions).
   - budgetAlert: the monthly spending budget crossing one of its steps.
   - githubAlert: GitHub changes worth knowing about (new collaborators, keys, repo made public).
   - heartbeatProblems: watchers that have stopped running. */
'use strict';

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;

function clip(v, max) {
  if (v == null || v === '') return null;
  return String(v).slice(0, max || 300);
}
function isObj(v) { return v !== null && typeof v === 'object'; }

// ---------------------------------------------------------------- code hidden in saved text

/* Each test is something no driver name, address, note or setting has a reason to contain.
   Plain < and > on their own are allowed (notes like "< 5 boxes"). */
const PATTERNS = [
  { re: /<\s*\/?\s*(script|iframe|object|embed|svg|math|style|link|meta|base|form|template|frame|frameset)\b/i, why: 'an HTML tag that can run code' },
  { re: /<[^>]*\son[a-z]{3,}\s*=/i, why: 'an HTML event handler (onerror=, onclick=, ...)' },
  { re: /\bon(error|load|click|mouseover|focus|toggle|animationstart|pointerover)\s*=\s*["'`]?[^\s"'`]/i, why: 'an HTML event handler (onerror=, onclick=, ...)' },
  { re: /(java|vb)script\s*:/i, why: 'a javascript: link' },
  { re: /data\s*:\s*text\/html/i, why: 'a data:text/html link' },
  { re: /["'`]\s*\)\s*;\s*[\w$.]+\(|["'`]\s*\+\s*[\w$.]+\(|["'`]\s*>\s*<\s*[a-z/!]/i, why: 'text that tries to break out of a quoted value' },
  { re: /\{\{.*\}\}|\$\{[^}]*\}/, why: 'a template expression ({{ }} or ${ })' },
  { re: /&#x?[0-9a-f]+;|\\u00[0-9a-f]{2}|%3c|%3e/i, why: 'encoded < > or quote characters' },
  { re: /\b(document\.cookie|localStorage|sessionStorage|eval\s*\(|new\s+Function\s*\(|fetch\s*\(\s*['"`/]|XMLHttpRequest|importScripts|indexedDB)/i, why: 'browser code (cookies, storage, eval, fetch)' }
];
const BAD_KEYS = /^(__proto__|constructor|prototype)$/;
const LONG_TEXT = 20000;     // characters; longer text in one field is unusual for every app here
const DEEP = 12;             // levels of nesting; deeper is unusual

/** What changed text looks suspicious, comparing the value before and after a write:
 * [{ f: field path, why, sample }]. Only new or changed text is checked, so old data that was
 * already there doesn't raise the alarm again on every unrelated save. */
function suspiciousValues(before, after, limit) {
  const out = [];
  const max = limit || 5;
  (function walk(b, a, p, depth) {
    if (out.length >= max || a == null) return;
    if (depth > DEEP) { out.push({ f: p || '(value)', why: 'nested ' + DEEP + '+ levels deep', sample: null }); return; }
    if (isObj(a)) {
      for (const k of Object.keys(a)) {
        const path = p ? p + '/' + k : k;
        if (BAD_KEYS.test(k)) { out.push({ f: path, why: 'a key that can change how the apps’ code behaves (' + k + ')', sample: null }); continue; }
        if (!isObj(b) || !(k in b)) {
          const hit = check(k);
          if (hit) { out.push({ f: path, why: hit + ' (in a key name)', sample: clip(k, 120) }); continue; }
        }
        walk(isObj(b) ? b[k] : undefined, a[k], path, depth + 1);
      }
      return;
    }
    if (typeof a !== 'string' || a === b) return;
    if (a.length > LONG_TEXT) { out.push({ f: p || '(value)', why: 'very long text (' + a.length + ' characters)', sample: clip(a, 120) }); return; }
    const hit = check(a);
    if (hit) out.push({ f: p || '(value)', why: hit, sample: clip(a, 120) });
  })(before, after, '', 0);
  return out;
}
function check(text) {
  for (const t of PATTERNS) if (t.re.test(text)) return t.why;
  return null;
}

// ---------------------------------------------------------------- database rules

/** Rules as an object; the console accepts // and /* *\/ comments, so they are stripped first.
 * null when it still isn't JSON (the alarm then says only that the text changed). */
function parseRules(text) {
  if (typeof text !== 'string') return null;
  try { return JSON.parse(text); } catch (e) { /* comments? */ }
  let out = '';
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === '\\') { out += text[++i] || ''; continue; }
      if (c === '"') inStr = false;
    } else if (c === '"') { inStr = true; out += c; }
    else if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; out += '\n'; }
    else if (c === '/' && text[i + 1] === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i++; }
    else out += c;
  }
  try { return JSON.parse(out); } catch (e) { return null; }
}

/** The rule paths that differ between two copies of the rules: [{ path, b, a }], at most `limit`. */
function rulesDiff(beforeText, afterText, limit) {
  const max = limit || 15;
  const b = parseRules(beforeText);
  const a = parseRules(afterText);
  if (!b || !a) return { parsed: false, changes: [] };
  const changes = [];
  (function walk(x, y, p) {
    if (changes.length >= max) return;
    if (isObj(x) && isObj(y)) {
      const keys = new Set([...Object.keys(x), ...Object.keys(y)]);
      for (const k of [...keys].sort()) walk(x[k], y[k], p ? p + '/' + k : k);
      return;
    }
    if (JSON.stringify(x) === JSON.stringify(y)) return;
    changes.push({ path: p || '(all)', b: x === undefined ? null : shortJson(x), a: y === undefined ? null : shortJson(y) });
  })(b, a, '');
  return { parsed: true, changes };
}
function shortJson(v) { const s = typeof v === 'string' ? v : JSON.stringify(v); return s.length > 300 ? s.slice(0, 300) + '…' : s; }

/** Rule changes that loosen access: a .read or .write that became true, or a rule removed. */
function rulesLoosened(changes) {
  return changes.filter((c) => /(^|\/)\.(read|write)$/.test(c.path) && (c.a === 'true' || c.a === true || c.a == null));
}

// ---------------------------------------------------------------- sign-ins

// Manitoba stays on Central Daylight Time (UTC-5) all year from 2026-11-01 (news.gov.mb.ca, item
// 75397), and was on it before that this year too, so a fixed offset is right from now on.
// (The runtime's time zone data may not know about the change yet.)
const LOCAL_OFFSET = -5 * HOUR;
const NIGHT_FROM = 0;   // midnight ...
const NIGHT_TO = 5;     // ... to 5 AM, Brandon time

function localHour(at) { return new Date(at + LOCAL_OFFSET).getUTCHours(); }

/** The network an IP address belongs to, roughly: the first two parts of an IPv4 address, the first
 * three of an IPv6 one. Phones change their exact address often; this changes less. */
function networkOf(ip) {
  const s = String(ip || '').trim().toLowerCase();
  if (!s) return null;
  const v4 = s.replace(/^::ffff:/, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v4)) return v4.split('.').slice(0, 2).join('.') + '.x.x';
  if (s.includes(':')) {
    const parts = s.split('::')[0].split(':').filter(Boolean);
    return parts.slice(0, 3).join(':') + '::/48';
  }
  return null;
}

/** Alerts for a staff sign-in. known: the networks this account used before ({ key: true }), or
 * null for an account with none yet (its first network isn't news). */
function signInOddities(entry, known, netKey) {
  const out = [];
  if (!entry || !entry.staff) return out;
  const hour = localHour(entry.at);
  if (hour >= NIGHT_FROM && hour < NIGHT_TO) {
    out.push({ type: 'night_signin', level: 'medium', title: 'Night sign-in: ' + entry.email,
      detail: entry.email + ' signed in at ' + clock(entry.at) + ' Brandon time from IP ' + (entry.ip || 'unknown') + '.' });
  }
  const net = networkOf(entry.ip);
  if (net && known && Object.keys(known).length && !known[netKey]) {
    out.push({ type: 'new_network', level: 'low', title: 'New network for ' + entry.email,
      detail: entry.email + ' signed in from a network it hasn’t used before (' + net + ', IP ' + entry.ip + ').' });
  }
  return out;
}
function clock(at) {
  const d = new Date(at + LOCAL_OFFSET);
  const h = d.getUTCHours();
  const m = String(d.getUTCMinutes()).padStart(2, '0');
  return (h % 12 || 12) + ':' + m + (h < 12 ? ' AM' : ' PM');
}

// ---------------------------------------------------------------- time clock

/** Alerts for a change to one shift (timeclock/shifts/{ek}/{id}). admin: the writer is an admin;
 * the punch in and punch out are server times, so only a later change to them is unusual. */
function shiftAlerts({ before, after, path, who, admin }) {
  const out = [];
  if (before && !after) {
    out.push({ type: 'tc_shift_deleted', level: 'medium', title: 'Time clock shift deleted',
      detail: who + ' deleted ' + path + ' (punch in ' + stamp(before.in) + ', out ' + stamp(before.out) + ').' });
    return out;
  }
  if (!before || !after || admin) return out;
  const moved = [];
  if (typeof before.in === 'number' && after.in !== before.in) moved.push('punch in ' + stamp(before.in) + ' → ' + stamp(after.in));
  if (typeof before.out === 'number' && after.out !== before.out) moved.push('punch out ' + stamp(before.out) + ' → ' + stamp(after.out));
  if (moved.length) {
    out.push({ type: 'tc_punch_changed', level: 'high', title: 'Punch time changed by a non-admin',
      detail: who + ' changed ' + path + ': ' + moved.join('; ') + '. Only an admin should change a saved punch.' });
  }
  return out;
}
function stamp(t) {
  if (typeof t !== 'number') return 'none';
  const d = new Date(t + LOCAL_OFFSET);
  return d.toISOString().slice(5, 10) + ' ' + clock(t);
}

// ---------------------------------------------------------------- database downloads

const SPIKE_TIMES = 5;            // an hour this many times the usual one ...
const SPIKE_MIN = 200 * 1e6;      // ... and at least 200 MB
const SPIKE_HIGH = 2 * 1e9;       // 2 GB in an hour is always high

/** An alert when the last hour's download (bytes) is far above the usual hour. history: earlier
 * hours' bytes. The usual hour is the median, so one busy hour doesn't move it much. */
function usageSpike(bytes, history) {
  if (!Number.isFinite(bytes)) return null;
  const past = (history || []).filter(Number.isFinite).sort((x, y) => x - y);
  const usual = past.length ? past[Math.floor(past.length / 2)] : 0;
  const mb = (n) => (n / 1e6).toFixed(n < 1e7 ? 1 : 0) + ' MB';
  if (bytes >= SPIKE_HIGH) {
    return { type: 'download_spike', level: 'high', title: 'Very large database download',
      detail: mb(bytes) + ' was downloaded from the database in one hour (usual hour: ' + mb(usual) + '). Someone may be copying the data.' };
  }
  if (past.length >= 24 && bytes >= SPIKE_MIN && bytes >= usual * SPIKE_TIMES) {
    return { type: 'download_spike', level: 'medium', title: 'Database download spike',
      detail: mb(bytes) + ' was downloaded from the database in one hour, ' + Math.round(bytes / Math.max(usual, 1)) + '× the usual hour (' + mb(usual) + ').' };
  }
  return null;
}

// ---------------------------------------------------------------- Google Cloud changes

/* Admin Activity audit log entries (sent by a log sink, see the README), by method name. The filter
   on the sink picks the same methods, so anything else that arrives is ignored. */
const CLOUD_METHODS = [
  { re: /SetIamPolicy$/i, type: 'cloud_access', level: 'high', what: 'changed who has access' },
  { re: /CreateServiceAccountKey$|UploadServiceAccountKey$/i, type: 'cloud_access', level: 'high', what: 'made a new service account key' },
  { re: /(Create|Delete|Undelete)ServiceAccount$|DisableServiceAccount$/i, type: 'cloud_access', level: 'high', what: 'changed a service account' },
  { re: /apikeys.*(CreateKey|UpdateKey|DeleteKey|UndeleteKey)$/i, type: 'cloud_access', level: 'high', what: 'changed an API key' },
  { re: /(Create|Update|Delete)Function$/i, type: 'cloud_functions', level: 'medium', what: 'changed a Cloud Function' },
  { re: /^storage\.setIamPermissions$/i, type: 'cloud_access', level: 'high', what: 'changed who can use a storage bucket' },
  { re: /^storage\.buckets\.(create|delete|update|patch)$/i, type: 'cloud_access', level: 'medium', what: 'changed a storage bucket' },
  { re: /(Create|Update|Delete)(Release|Ruleset)$/i, type: 'cloud_access', level: 'medium', what: 'changed Firebase security rules' },
  { re: /CloudScheduler\.(CreateJob|UpdateJob|DeleteJob|PauseJob|ResumeJob)$/i, type: 'cloud_functions', level: 'low', what: 'changed a scheduled job' }
];

/** The alert for one audit log entry, or null. ownAccounts: principals whose deploys are routine
 * (the Firebase deploy service agents); their changes come out one level lower. */
function cloudLogAlert(entry, ownAccounts) {
  const p = entry && entry.protoPayload;
  if (!p || typeof p.methodName !== 'string') return null;
  const m = CLOUD_METHODS.find((x) => x.re.test(p.methodName));
  if (!m) return null;
  if (entry.severity === 'ERROR' || (p.status && p.status.code)) return null;  // refused: nothing changed
  const who = clip((p.authenticationInfo && p.authenticationInfo.principalEmail) || 'unknown account', 120);
  const ip = clip(p.requestMetadata && p.requestMetadata.callerIp, 64);
  const resource = clip(p.resourceName || (entry.resource && entry.resource.type) || '', 200);
  const routine = (ownAccounts || []).includes(who);
  const level = routine && m.level === 'high' ? 'medium' : routine && m.level === 'medium' ? 'low' : m.level;
  return { type: m.type, level, who, method: clip(p.methodName, 120), resource, title: 'Google Cloud: ' + who + ' ' + m.what,
    detail: who + ' ' + m.what + (resource ? ' (' + resource + ')' : '') + ' with ' + p.methodName + (ip ? ' from IP ' + ip : '') + '.' };
}

// ---------------------------------------------------------------- spending budget

/** The alert for a budget notification, or null. Notifications come several times a day with the
 * running total; alertThresholdExceeded is the highest step crossed so far (0.5 = 50%). The caller
 * keeps the last step alerted per month (`lastStep`) so each step raises one alert. */
function budgetAlert(msg, lastStep) {
  if (!msg || !Number.isFinite(msg.alertThresholdExceeded)) return null;
  const step = msg.alertThresholdExceeded;
  if (Number.isFinite(lastStep) && step <= lastStep) return null;
  const money = (n) => (Number.isFinite(n) ? n.toFixed(2) : '?') + ' ' + (msg.currencyCode || '');
  return { step, alert: { type: 'budget', level: step >= 1 ? 'high' : 'medium',
    title: 'Spending passed ' + Math.round(step * 100) + '% of the budget',
    detail: (msg.budgetDisplayName || 'Budget') + ': ' + money(msg.costAmount) + ' spent of ' + money(msg.budgetAmount) + ' this month.' } };
}

// ---------------------------------------------------------------- GitHub

/** The alert for a GitHub webhook delivery, or null. event: the X-GitHub-Event header. */
function githubAlert(event, body) {
  if (!body || typeof body !== 'object') return null;
  const repo = clip((body.repository && body.repository.full_name) || (body.organization && body.organization.login) || 'a repository', 100);
  const who = clip((body.sender && body.sender.login) || 'someone', 60);
  const a = (type, level, title, detail) => ({ type, level, title: 'GitHub: ' + title, detail: detail + ' (' + repo + ', by ' + who + ')' });
  switch (event) {
    case 'member':
      return a('github_access', 'high', 'collaborator ' + (body.action || 'changed'), 'Collaborator ' + clip(body.member && body.member.login, 60) + ' was ' + clip(body.action, 20) + '.');
    case 'deploy_key':
      return a('github_access', 'high', 'deploy key ' + (body.action || 'changed'), 'Deploy key "' + clip(body.key && body.key.title, 80) + '" was ' + clip(body.action, 20) + '.');
    case 'public':
      return a('github_access', 'high', 'repository made public', repo + ' is now public.');
    case 'repository':
      if (['publicized', 'privatized', 'deleted', 'renamed', 'transferred', 'archived', 'unarchived'].includes(body.action)) {
        return a('github_access', 'high', 'repository ' + body.action, repo + ' was ' + body.action + '.');
      }
      return null;
    case 'branch_protection_rule':
      return a('github_access', 'medium', 'branch protection ' + (body.action || 'changed'), 'A branch protection rule was ' + clip(body.action, 20) + '.');
    case 'repository_ruleset':
      return a('github_access', 'medium', 'ruleset ' + (body.action || 'changed'), 'A ruleset was ' + clip(body.action, 20) + '.');
    case 'page_build':
      if (body.build && body.build.status === 'errored') {
        return a('github_site', 'medium', 'site build failed', 'The GitHub Pages build failed: ' + clip(body.build.error && body.build.error.message, 200) + '.');
      }
      return null;
    case 'push': {
      const branch = String(body.ref || '').replace('refs/heads/', '');
      const main = body.repository && body.repository.default_branch;
      if (!main || branch !== main) return null;
      const n = Array.isArray(body.commits) ? body.commits.length : 0;
      const forced = body.forced ? ' (force push: history was rewritten)' : '';
      return a(body.forced ? 'github_access' : 'github_push', body.forced ? 'high' : 'low', (body.forced ? 'force push to ' : 'push to ') + branch,
        n + ' commit' + (n === 1 ? '' : 's') + ' pushed to ' + branch + forced + ': ' + clip(body.head_commit && body.head_commit.message, 120));
    }
    default:
      return null;
  }
}

// ---------------------------------------------------------------- heartbeat

/** Watchers that should have run by now: name -> the longest gap allowed (ms). */
const EXPECTED = {
  auditUserCensus: 2 * HOUR,       // every 30 minutes
  auditRulesCheck: 3 * HOUR,       // every hour
  auditUsageCheck: 3 * HOUR,       // every hour
  auditBackup: 26 * HOUR,          // every day
  auditPrune: 26 * HOUR            // every day
};

/** The watchers that haven't run when they should have: [{ name, last }]. last: { name: time }. */
function heartbeatProblems(last, now) {
  return Object.entries(EXPECTED)
    .filter(([name, gap]) => !(last && Number.isFinite(last[name]) && now - last[name] <= gap))
    .map(([name]) => ({ name, last: last && Number.isFinite(last[name]) ? last[name] : null }));
}

module.exports = {
  HOUR, DAY, suspiciousValues, parseRules, rulesDiff, rulesLoosened, localHour, networkOf, signInOddities,
  shiftAlerts, usageSpike, cloudLogAlert, budgetAlert, githubAlert, EXPECTED, heartbeatProblems
};
