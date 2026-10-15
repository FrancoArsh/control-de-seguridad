import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { cert, initializeApp, deleteApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';

// Explicit target and credential project prevent accidental production deployment.
const projectId = 'control-seguridad-staging';
const databaseURL = `https://${projectId}-default-rtdb.firebaseio.com`;
if (process.env.FIREBASE_DATABASE_EMULATOR_HOST) throw new Error('Remove emulator configuration before remote verification.');
const serviceAccount = JSON.parse(await readFile(resolve('serviceAccount.staging.json'), 'utf8'));
if (serviceAccount.project_id !== projectId) throw new Error('Credential does not belong to staging.');
const desired = JSON.parse(await readFile(resolve('database.rules.json'), 'utf8'));
if (desired.rules['.read'] !== false || desired.rules['.write'] !== false) throw new Error('Default deny required.');
const app = initializeApp({ projectId, databaseURL, credential: cert(serviceAccount) }, 'staging-rules');
try {
  const db = getDatabase(app);
  const previous = await db.getRulesJSON();
  if (process.argv.includes('--apply')) {
    const directory = resolve('output', 'rules-backups');
    await mkdir(directory, { recursive: true });
    const backup = resolve(directory, `staging-${Date.now()}.json`);
    await writeFile(backup, JSON.stringify(previous, null, 2), { flag: 'wx' });
    await db.setRules(desired);
    console.log(`Previous rules backed up: ${backup}`);
  }
  const actual = await db.getRulesJSON();
  if (!isDeepStrictEqual(actual, desired)) throw new Error('Remote rules differ from repository. Run with --apply to deploy.');
  // Requests are anonymous and read-only; both must be rejected by deployed rules.
  for (const path of ['accessHistory', 'accessState']) {
    const response = await fetch(`${databaseURL}/${path}.json?shallow=true`, { signal: AbortSignal.timeout(15000) });
    if (![401, 403].includes(response.status)) throw new Error(`Anonymous access was not denied: ${path}`);
  }
  await db.ref('accessState').orderByChild('_pendingAccess/status').equalTo('pending').limitToFirst(1).get();
  console.log(JSON.stringify({ projectId, rulesMatch: true, anonymousReadsDenied: true, recoveryQuery: 'ok', applied: process.argv.includes('--apply') }));
} finally { await deleteApp(app); }
