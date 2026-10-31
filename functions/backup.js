/* E&C database backup – a daily copy of the whole Realtime Database and its rules.

   Firebase's own automated backups (Realtime Database > Backups) stopped after 2026-10-28 with a
   job stuck in Queued. auditBackup (index.js) makes the same two files every day in the same
   bucket, under daily/, so there is always a recent copy whatever happens to Firebase's. The
   bucket's 30-day lifecycle rule deletes old copies, as it does Firebase's.

   Kept free of Firebase calls (they are passed in), so it can be tested with `node --test`. */
'use strict';

const zlib = require('zlib');

const BUCKET = 'eandccourier-36fcc-default-rtdb-backups';
const FOLDER = 'daily';

/** The two file names for a backup started at `at`, in the style Firebase uses. */
function backupNames(at) {
  const stamp = new Date(at).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return {
    data: `${FOLDER}/${stamp}_data.json.gz`,
    rules: `${FOLDER}/${stamp}_rules.json.gz`
  };
}

/**
 * Makes one backup. io supplies the Firebase calls:
 *   readData()        -> the whole database as a JSON-ready value
 *   readRules()       -> the rules as text
 *   save(name, buf)   -> writes a gzipped file to the bucket
 * Returns the sizes saved. Throws if either file couldn't be made or saved.
 */
async function makeBackup(io, at) {
  const names = backupNames(at);
  const data = zlib.gzipSync(Buffer.from(JSON.stringify(await io.readData()), 'utf8'));
  const rules = zlib.gzipSync(Buffer.from(String(await io.readRules()), 'utf8'));
  await io.save(names.data, data);
  await io.save(names.rules, rules);
  return { names, dataBytes: data.length, rulesBytes: rules.length };
}

module.exports = { BUCKET, FOLDER, backupNames, makeBackup };
