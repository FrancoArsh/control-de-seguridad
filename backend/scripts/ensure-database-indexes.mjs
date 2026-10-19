import 'dotenv/config';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { initializeApp, cert, deleteApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';

const args = new Map(process.argv.slice(2).map(arg => arg.split('=')));
const raw = process.env.FIREBASE_SERVICE_ACCOUNT || process.env.SERVICE_ACCOUNT_JSON;
const account = JSON.parse(raw || await readFile(resolve(process.env.GOOGLE_APPLICATION_CREDENTIALS || 'serviceAccountKey.json'), 'utf8'));
const expected = args.get('--project');
if (!expected || account.project_id !== expected || new URL(process.env.FIREBASE_DATABASE_URL).hostname !== `${expected}-default-rtdb.firebaseio.com`) throw new Error('Explicit project, credential and database must match.');
if (process.env.FIREBASE_DATABASE_EMULATOR_HOST) throw new Error('Remote index maintenance cannot run with emulator settings.');
const app = initializeApp({ credential: cert(account), databaseURL: process.env.FIREBASE_DATABASE_URL });
try {
  const db = getDatabase(app), before = await db.getRulesJSON(), after = structuredClone(before);
  const wanted = JSON.parse(await readFile(resolve('database.rules.json'), 'utf8'));
  const additions = {};
  for (const [path, rule] of Object.entries(wanted.rules)) {
    if (!rule || typeof rule !== 'object' || !rule['.indexOn']) continue;
    const existing = after.rules[path]?.['.indexOn'] || [];
    const oldIndexes = Array.isArray(existing) ? existing : [existing];
    const extra = rule['.indexOn'].filter(value => !oldIndexes.includes(value));
    if (!extra.length) continue;
    additions[path] = extra;
    after.rules[path] = { ...after.rules[path], '.indexOn': [...oldIndexes, ...extra] };
  }
  if (args.has('--apply') && Object.keys(additions).length) {
    await mkdir(resolve('output/rules-backups'), { recursive: true });
    const backup = resolve(`output/rules-backups/${expected}-${Date.now()}.json`);
    await writeFile(backup, JSON.stringify(before, null, 2), { flag: 'wx' });
    if (!isDeepStrictEqual(await db.getRulesJSON(), before)) throw new Error('Rules changed during review; aborting.');
    await db.setRules(after);
    if (!isDeepStrictEqual(await db.getRulesJSON(), after)) throw new Error('Published rules do not match expected indexes.');
    console.log(JSON.stringify({ project: expected, applied: true, additions, backup, permissionsChanged: false }));
  } else console.log(JSON.stringify({ project: expected, applied: false, additions, permissionsChanged: false }));
} finally { await deleteApp(app); }
