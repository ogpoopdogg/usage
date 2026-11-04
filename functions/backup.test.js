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

const { Readable, Writable } = require('stream');

/** A fake bucket: openSave(name) collects what is written; saved[name] is the file once closed. */
function fakeBucket(failOn) {
  const saved = {};
  const openSave = (name) => {
    const parts = [];
    return new Writable({
      write(chunk, enc, done) { if (failOn && failOn.test(name)) return done(new Error('403 Forbidden')); parts.push(chunk); done(); },
      final(done) { saved[name] = Buffer.concat(parts); done(); }
    });
  };
  return { saved, openSave };
}
/** The database as a stream of JSON text, in small pieces like a download. */
const jsonStream = (value) => Readable.from((JSON.stringify(value).match(/.{1,7}/gs) || ['']).map((s) => Buffer.from(s)));

test('a backup saves the whole database and the rules, gzipped', async () => {
  const { saved, openSave } = fakeBucket();
  const db = { staff: { u1: true }, requests: { r1: { status: 'new' } } };
  const res = await B.makeBackup({ openData: async () => jsonStream(db), readRules: async () => '{ "rules": {} }', openSave }, AT);
  assert.deepEqual(Object.keys(saved), [res.names.data, res.names.rules]);
  assert.deepEqual(JSON.parse(zlib.gunzipSync(saved[res.names.data]).toString()), db);
  assert.equal(zlib.gunzipSync(saved[res.names.rules]).toString(), '{ "rules": {} }');
  assert.equal(res.dataBytes, saved[res.names.data].length);
  assert.equal(res.rulesBytes, saved[res.names.rules].length);
});

test('an empty database still makes a backup', async () => {
  const { saved, openSave } = fakeBucket();
  await B.makeBackup({ openData: async () => jsonStream(null), readRules: async () => '{}', openSave }, AT);
  assert.equal(zlib.gunzipSync(saved['daily/2026-10-31T08:00:00Z_data.json.gz']).toString(), 'null');
});

test('a big database is streamed, not held whole', async () => {
  // About 40 MB of JSON produced piece by piece; memory must not grow by anything like that.
  let i = 0;
  const big = new Readable({ read() {
    if (i === 0) this.push('{');
    if (i < 40000) this.push('"k' + i++ + '":"' + 'y'.repeat(1000) + '",');
    else { this.push('"end":1}'); this.push(null); }
  } });
  let bytes = 0;
  const openSave = () => new Writable({ write(chunk, enc, done) { bytes += chunk.length; done(); } });
  global.gc && global.gc();
  const before = process.memoryUsage().rss;
  const res = await B.makeBackup({ openData: async () => big, readRules: async () => '{}', openSave }, AT);
  const grew = process.memoryUsage().rss - before;
  assert.ok(res.dataBytes > 0 && res.dataBytes < 1e6, 'gzips well');
  assert.ok(grew < 30e6, 'rss grew ' + Math.round(grew / 1e6) + ' MB');
});

test('a failed save is not hidden', async () => {
  const { openSave } = fakeBucket(/data/);
  await assert.rejects(B.makeBackup({ openData: async () => jsonStream({}), readRules: async () => '{}', openSave }, AT), /403/);
});

test('a failed download is not hidden', async () => {
  const { openSave } = fakeBucket();
  const broken = new Readable({ read() { this.destroy(new Error('connection reset')); } });
  await assert.rejects(B.makeBackup({ openData: async () => broken, readRules: async () => '{}', openSave }, AT), /connection reset/);
});
