import { readFile } from 'node:fs/promises';
import { cert, initializeApp, deleteApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';

const args = new Map(process.argv.slice(2).map(arg => { const i = arg.indexOf('='); return i < 0 ? [arg, 'true'] : [arg.slice(0, i), arg.slice(i + 1)]; }));
const id = args.get('--guard');
if (!id || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new Error('Usage: --guard=ID. Read-only by default. Stop ALL backend instances before --apply --backends-stopped --owner=OWNER --reason=TEXT.');
const apply = args.has('--apply');
if (apply && (!args.has('--backends-stopped') || !args.get('--owner') || !args.get('--reason')?.trim())) throw new Error('Recovery requires stopped backends, exact owner and incident reason.');
if (process.env.FIREBASE_DATABASE_EMULATOR_HOST) throw new Error('This tool targets staging only.');
const projectId = 'control-seguridad-staging';
const serviceAccount = JSON.parse(await readFile(new URL('../serviceAccount.staging.json', import.meta.url), 'utf8'));
if (serviceAccount.project_id !== projectId) throw new Error('Wrong credential project.');
const app = initializeApp({ projectId, databaseURL: `https://${projectId}-default-rtdb.firebaseio.com`, credential: cert(serviceAccount) }, 'guard-lock-recovery');
try {
  const db = getDatabase(app), ref = db.ref(`guardOperationLocks/${id}`);
  const listener = () => {};
  ref.on('value', listener, () => {});
  try {
  const before = (await ref.get()).val();
  if (!apply) console.log(JSON.stringify({ projectId, guardId: id, lock: before, changed: false }));
  else {
    if (!before || before.owner !== args.get('--owner')) throw new Error('Lock owner mismatch; nothing released.');
    const audit = db.ref('adminAuditLog').push();
    await audit.set({ action: 'guard.lock.recovery.attempt', guardId: id, owner: before.owner,
      reason: args.get('--reason'), operator: serviceAccount.client_email, timestamp: Date.now(), backendsStoppedConfirmed: true });
    const result = await ref.transaction(current => current?.owner === before.owner ? null : undefined, undefined, false);
    await audit.update({ released: result.committed });
    if (!result.committed) throw new Error('Lock changed; nothing released.');
    console.log(JSON.stringify({ projectId, guardId: id, released: true, auditId: audit.key }));
  }
  } finally { ref.off('value', listener); }
} finally { await deleteApp(app); }
