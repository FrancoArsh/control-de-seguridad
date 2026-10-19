import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { initializeApp, cert, deleteApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { getAuth } from 'firebase-admin/auth';
import { readHistoryPage } from '../dist/history.js';

const raw = process.env.FIREBASE_SERVICE_ACCOUNT || process.env.SERVICE_ACCOUNT_JSON;
const account = JSON.parse(raw || await readFile(resolve(process.env.GOOGLE_APPLICATION_CREDENTIALS || 'serviceAccountKey.json'), 'utf8'));
const app = initializeApp({ credential: cert(account), databaseURL: process.env.FIREBASE_DATABASE_URL });
try {
  const db = getDatabase(app);
  console.log(JSON.stringify({ project: account.project_id, database: process.env.FIREBASE_DATABASE_URL }));
  const rules = await db.getRulesJSON();
  console.log(JSON.stringify({ historyIndexes: rules.rules?.accessHistory?.['.indexOn'] || [] }));
  for (const [name, query] of [
    ['firstByKey', db.ref('accessHistory').orderByKey().limitToFirst(3)],
    ['oldestTimestamp', db.ref('accessHistory').orderByChild('timestamp').startAt(0).limitToFirst(3)],
    ['latestTimestamp', db.ref('accessHistory').orderByChild('timestamp').endAt(Date.now()).limitToLast(3)]
  ]) {
    const started = Date.now(), snap = await query.get();
    const rows = [];
    snap.forEach(child => {
      const value = child.val();
      rows.push({ key: child.key, timestamp: value?.timestamp, fields: Object.fromEntries(Object.entries(value || {}).map(([key, v]) => [key, typeof v])) });
    });
    console.log(JSON.stringify({ query: name, durationMs: Date.now() - started, rows }));
  }
  const guards = (await db.ref('guards').get()).val() || {};
  const started = Date.now();
  const page = await readHistoryPage(db, { role: 'admin', id: 'diagnostic', uid: 'diagnostic' }, {});
  console.log(JSON.stringify({ historyPage: { count: page.data.length, hasMore: Boolean(page.nextCursor), durationMs: Date.now() - started,
    oldestOnPage: page.data.at(-1)?.timestamp, newestOnPage: page.data[0]?.timestamp, rawTokenExposed: page.data.some(row => 'token' in row) } }));
  const profiles = (await db.ref('portalProfiles').get()).val() || {};
  const rows = [];
  for (const [id, guard] of Object.entries(guards)) {
    const uid = guard.authUid || Object.entries(profiles).find(([, p]) => p?.role === 'guard' && p.id === id)?.[0];
    let identity;
    if (uid) { try { identity = await getAuth(app).getUser(uid); } catch {} }
    rows.push({ id, name: guard.name, email: identity?.email || guard.email || null,
      active: guard.active !== false, accountEnabled: identity ? !identity.disabled : null, linked: Boolean(identity) });
  }
  console.log(JSON.stringify({ guardAccounts: rows }));
} finally { await deleteApp(app); }
