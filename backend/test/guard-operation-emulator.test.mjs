import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { initializeApp, deleteApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { withGuardOperation, GuardOperationBusy } from '../dist/guard-operation.js';
import { commitDynamicAccess } from '../dist/access-transaction.js';
import { endShift } from '../dist/shifts.js';

test('two backend clients serialize access, closure and guard revocation', { timeout: 30000 }, async () => {
  const host = process.env.FIREBASE_DATABASE_EMULATOR_HOST;
  assert.match(host || '', /^(127\.0\.0\.1|localhost):\d+$/);
  const projectId = `demo-guard-lock-${Date.now()}`;
  const config = { projectId, databaseURL: `http://${host}?ns=${projectId}` };
  const first = initializeApp(config, `${projectId}-1`), second = initializeApp(config, `${projectId}-2`);
  const db = getDatabase(first), other = getDatabase(second);
  const command = nonce => ({ userId: 'person', nonce, eventId: nonce, type: 'entry', sessionId: 'test',
    cooldownMs: 0, issuedAt: Date.now(), expiresAt: Date.now() + 60000, audit: { guardId: 'guard', shiftId: 'shift' } });
  try {
    await db.ref().set({ students: { person: { active: true } }, guards: { guard: { active: true } },
      guardShifts: { shift: { guardId: 'guard', active: true, startTimestamp: 1 } } });
    let release, reached;
    const gate = new Promise(resolve => { release = resolve; });
    const entered = new Promise(resolve => { reached = resolve; });
    const paused = { ref(path) {
      if (path !== 'students/person') return db.ref(path);
      return { async get() { reached(); await gate; return db.ref(path).get(); } };
    } };
    const access = commitDynamicAccess(paused, command('first'));
    await entered;
    let closed = false, revoked = false;
    const closing = endShift(other, 'guard', 'shift', 'admin').then(value => { closed = true; return value; });
    const revoking = withGuardOperation(other, 'guard', 'disable', async () => {
      await other.ref('guards/guard/active').set(false); revoked = true;
    });
    await delay(150);
    assert.equal(closed, false); assert.equal(revoked, false);
    assert.equal(await withGuardOperation(other, 'another', 'independent', async () => 'ok'), 'ok');
    release();
    assert.equal((await access).ok, true);
    const closure = await closing;
    await revoking;
    assert.ok(closure.endTimestamp >= (await db.ref('accessHistory/first/timestamp').get()).val());
    assert.equal((await commitDynamicAccess(other, command('after-disable'))).reason, 'guard disabled');
    await db.ref('guards/guard/active').set(true);
    assert.equal((await commitDynamicAccess(other, command('after-close'))).reason, 'GUARD_NOT_ON_SHIFT');
    await assert.rejects(withGuardOperation(db, 'guard', 'failure', async () => { throw new Error('Injected'); }), /Injected/);
    assert.equal((await db.ref('guardOperationLocks/guard').get()).exists(), false);
    await db.ref('guardOperationLocks/guard').set({ owner: 'orphan', startedAt: 1, operation: 'crashed' });
    await assert.rejects(withGuardOperation(other, 'guard', 'must-not-steal', async () => assert.fail('Never run')), GuardOperationBusy);
    assert.equal((await db.ref('guardOperationLocks/guard/owner').get()).val(), 'orphan');
  } finally { await db.ref().remove(); await deleteApp(first); await deleteApp(second); }
});
