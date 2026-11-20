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
// Firebase indexes are unordered; permission expressions must still match exactly.
function comparableRules(rules) {
  return JSON.parse(JSON.stringify(rules, (key, value) =>
    key === '.indexOn' && Array.isArray(value) ? [...value].sort() : value));
}
const desired = JSON.parse(await readFile(resolve('database.rules.json'), 'utf8'));
// The remote privacy drill uses an isolated subtree. Only staging needs these indexes.
const baseRules = structuredClone(desired);
desired.rules.privacyTestRuns = {
  '$run': {
    accessHistory: { '.indexOn': ['timestamp', 'id'] },
    adminAuditLog: { '.indexOn': ['entityId'] }
  }
};
if (desired.rules['.read'] !== false || desired.rules['.write'] !== false) throw new Error('Default deny required.');
const app = initializeApp({ projectId, databaseURL, credential: cert(serviceAccount) }, 'staging-rules');
try {
  const db = getDatabase(app);
  const previous = await db.getRulesJSON();
  if (process.argv.includes('--add-drill-indexes') &&
      !isDeepStrictEqual(comparableRules(previous), comparableRules(desired)) &&
      !isDeepStrictEqual(comparableRules(previous), comparableRules(baseRules))) {
    throw new Error('Unexpected staging rules; isolated drill index update aborted.');
  }
  if (process.argv.includes('--apply') || process.argv.includes('--add-drill-indexes')) {
    const directory = resolve('output', 'rules-backups');
    await mkdir(directory, { recursive: true });
    const backup = resolve(directory, `staging-${Date.now()}.json`);
    await writeFile(backup, JSON.stringify(previous, null, 2), { flag: 'wx' });
    if (!isDeepStrictEqual(await db.getRulesJSON(), previous)) throw new Error('Staging rules changed during review.');
    await db.setRules(desired);
    console.log(`Previous rules backed up: ${backup}`);
  }
  const actual = await db.getRulesJSON();
  if (!isDeepStrictEqual(comparableRules(actual), comparableRules(desired))) throw new Error('Remote rules differ from repository. Run with --apply to deploy.');
  // Requests are anonymous and read-only; both must be rejected by deployed rules.
  for (const path of ['accessHistory', 'accessState']) {
    const response = await fetch(`${databaseURL}/${path}.json?shallow=true`, { signal: AbortSignal.timeout(15000) });
    if (![401, 403].includes(response.status)) throw new Error(`Anonymous access was not denied: ${path}`);
  }
  await db.ref('accessState').orderByChild('_pendingAccess/status').equalTo('pending').limitToFirst(1).get();
  console.log(JSON.stringify({ projectId, rulesMatch: true, anonymousReadsDenied: true, recoveryQuery: 'ok', applied: process.argv.includes('--apply') || process.argv.includes('--add-drill-indexes') }));
} finally { await deleteApp(app); }
