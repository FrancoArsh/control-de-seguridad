import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { cert, initializeApp, deleteApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { commitManualAccess } from '../dist/manual-access.js';
import { readHistoryPage } from '../dist/history.js';
import { eraseVisitor } from './visitor-erasure.mjs';

const project = 'control-seguridad-staging';
const account = JSON.parse(await readFile('serviceAccount.staging.json', 'utf8'));
assert.equal(account.project_id, project);
assert.ok(!process.env.FIREBASE_DATABASE_EMULATOR_HOST);
const app = initializeApp({ credential: cert(account), projectId: project, databaseURL: 'https://' + project + '-default-rtdb.firebaseio.com' });
const run = getDatabase(app).ref('privacyTestRuns').child(randomUUID());
const db = { ref: path => path ? run.child(path) : run };
try {
  await run.child('guards/guard').set({ active: true });
  await run.child('guardShifts/shift').set({ guardId: 'guard', active: true });
  const visitors = ['12345678-5', '11111111-1'].map((rut, i) => ({
    id: 'manual-' + createHash('sha256').update(rut).digest('hex'), name: 'Visita sintética ' + i, rut
  }));
  for (const v of visitors) {
    const decision = await commitManualAccess(db, { userId: v.id, visitor: { name: v.name, rut: v.rut }, reason: 'Ensayo de privacidad',
      type: 'entry', eventId: db.ref('accessHistory').push().key, sessionId: 'turno',
      audit: { guardId: 'guard', shiftId: 'shift', validatedById: 'guard-uid', validatedByName: 'Guardia sintético', validatedByRole: 'guard' } });
    assert.equal(decision.ok, true);
  }
  async function checkVisible(expected) {
    for (const role of ['guard', 'admin']) {
      const result = await readHistoryPage(db, { role, id: role, uid: role + '-uid' }, {});
      assert.deepEqual(result.data.map(e => e.id).sort(), expected.map(v => v.id).sort());
      for (const v of expected) {
        const event = result.data.find(e => e.id === v.id);
        assert.equal(event.validationMode, 'manual');
        assert.equal(event.rut, v.rut);
        assert.equal(event.name, v.name);
      }
    }
  }
  await checkVisible(visitors);
  // This run has a private, newly allocated subtree; the fixture writer has finished.
  const removed = await eraseVisitor(app, run, visitors[0].id, true);
  assert.deepEqual(removed.counts, { accessHistory: 1, adminAuditLog: 1, attendanceSessions: 1, accessState: 1 });
  await checkVisible(visitors.slice(1));
  assert.ok(Object.values((await eraseVisitor(app, run, visitors[0].id, false)).counts).every(n => n === 0));
  assert.deepEqual((await eraseVisitor(app, run, visitors[1].id, false)).counts, removed.counts);
  console.log(JSON.stringify({ project, isolatedSubtree: true, eachHistoryBefore: 2, eachHistoryAfter: 1, removed: removed.counts, controlVisitorIntact: true }));
} finally {
  try { await run.remove(); assert.equal((await run.get()).exists(), false); }
  finally { await deleteApp(app); }
}
