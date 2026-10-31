'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('zlib');
const B = require('./backup');

const AT = Date.UTC(2026, 9, 31, 8, 0, 0, 123);

test('backup files are named by time, in the daily folder', () => {
  assert.deepEqual(B.backupNames(AT), {
    data: 'daily/2026-10-31T08:00:00Z_data.json.gz',
    rules: 'daily/2026-10-31T08:00:00Z_rules.json.gz'
  });
});

test('a backup saves the whole database and the rules, gzipped', async () => {
  const saved = {};
  const res = await B.makeBackup({
    readData: async () => ({ staff: { u1: true }, requests: { r1: { status: 'new' } } }),
    readRules: async () => '{ "rules": {} }',
    save: async (name, buf) => { saved[name] = buf; }
  }, AT);
  assert.deepEqual(Object.keys(saved), [res.names.data, res.names.rules]);
  assert.deepEqual(JSON.parse(zlib.gunzipSync(saved[res.names.data]).toString()), { staff: { u1: true }, requests: { r1: { status: 'new' } } });
  assert.equal(zlib.gunzipSync(saved[res.names.rules]).toString(), '{ "rules": {} }');
  assert.equal(res.dataBytes, saved[res.names.data].length);
});

test('an empty database still makes a backup', async () => {
  const saved = {};
  await B.makeBackup({ readData: async () => null, readRules: async () => '{}', save: async (n, b) => { saved[n] = b; } }, AT);
  assert.equal(zlib.gunzipSync(saved['daily/2026-10-31T08:00:00Z_data.json.gz']).toString(), 'null');
});

test('a failed save is not hidden', async () => {
  await assert.rejects(B.makeBackup({
    readData: async () => ({}), readRules: async () => '{}', save: async () => { throw new Error('403 Forbidden'); }
  }, AT), /403/);
});
