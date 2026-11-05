'use strict';
// Every function index.js exports is deployed under its export name, so two parts of the code must
// never use the same name: the later one silently replaces the earlier (the "canary" watcher and the
// scheduled auditCanary did, on 2026-11-04). Also: the setup script deploys every function.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const L = require('./lib');
const I = require('./index');

const exportName = (w) => 'audit' + w.name[0].toUpperCase() + w.name.slice(1);

test('each database watcher is deployed as a database trigger under its own name', () => {
  const names = L.WATCHES.map(exportName);
  assert.equal(new Set(names).size, names.length);
  for (const n of names) {
    const e = I[n] && I[n].__endpoint;
    assert.ok(e && e.eventTrigger && /database/.test(e.eventTrigger.eventType), n + ' is not a database watcher');
  }
});

test('the setup script deploys every function', () => {
  const sh = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'setup-security-fixes.sh'), 'utf8');
  const batches = sh.slice(sh.indexOf('BATCHES=('), sh.indexOf(')\nfor b in'));
  const listed = new Set(batches.match(/audit[A-Za-z]+/g));
  assert.deepEqual(Object.keys(I).filter((n) => !listed.has(n)), []);
  assert.deepEqual([...listed].filter((n) => !I[n]), []);
});
