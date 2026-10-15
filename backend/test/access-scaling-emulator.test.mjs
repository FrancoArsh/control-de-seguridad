import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { initializeApp, deleteApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { commitDynamicAccess, AccessPublicationPending, flushPendingAccess, recoverPendingAccess } from '../dist/access-transaction.js';
import { readGuardReport } from '../dist/guard-report.js';

test('isolated access transactions, durable recovery and bounded guard reports', { timeout: 120000 }, async () => {
  const host = process.env.FIREBASE_DATABASE_EMULATOR_HOST;
  assert.match(host || '', /^(127\.0\.0\.1|localhost):\d+$/);
  const project = `demo-scaling-${Date.now()}`;
  const app = initializeApp({ projectId: project, databaseURL: `http://${host}?ns=${project}` }, project);
  const db = getDatabase(app);
  let failPublication = false;
  const guarded = { ref(path) {
    if (path) return db.ref(path);
    return { update(values) { if (failPublication) throw new Error('Injected failure'); return db.ref().update(values); } };
  } };
  const command = (userId, nonce, type = 'entry') => ({ userId, nonce, eventId: nonce, type,
    sessionId: 'test', cooldownMs: 0, issuedAt: Date.now(), expiresAt: Date.now() + 60000,
    audit: { guardId: 'guard', shiftId: 'shift' } });
  try {
    const rules = await fetch(`http://${host}/.settings/rules.json?ns=${project}`, { method: 'PUT',
      headers: { Authorization: 'Bearer owner', 'Content-Type': 'application/json' },
      body: await readFile(new URL('../database.rules.json', import.meta.url), 'utf8') });
    assert.equal(rules.status, 200);
    await db.ref().set({ students: { a: { active: true }, b: { active: true }, c: { active: true } },
      guards: { guard: { active: true, name: 'Synthetic' } },
      guardShifts: { shift: { guardId: 'guard', active: true, startTimestamp: 1 } } });
    const race = await Promise.all(Array.from({ length: 8 }, () => commitDynamicAccess(guarded, command('a', 'same'))));
    assert.equal(race.filter(r => r.ok).length, 1);
    assert.ok(race.filter(r => !r.ok).every(r => r.reason === 'qr already used'));
    const independent = await Promise.all(['b', 'c'].map(id => commitDynamicAccess(guarded, command(id, `entry-${id}`))));
    assert.ok(independent.every(r => r.ok));
    failPublication = true;
    await assert.rejects(commitDynamicAccess(guarded, command('b', 'exit-b', 'exit')), AccessPublicationPending);
    const pending = (await db.ref('accessState/b/_pendingAccess').get()).val();
    assert.equal((await db.ref('accessState/b/inside').get()).val(), false);
    assert.ok((await db.ref('accessState/b/_usedQrNonces/exit-b').get()).exists());
    failPublication = false;
    assert.equal(await recoverPendingAccess(db), 1);
    assert.equal((await db.ref('accessState/b/_pendingAccess').get()).exists(), false);
    assert.ok((await commitDynamicAccess(guarded, command('b', 'again-b'))).ok);
    await flushPendingAccess(db, 'b', pending);
    assert.equal((await db.ref('accessState/b/inside').get()).val(), true, 'Old publication cannot regress presence');
    assert.equal((await db.ref('accessHistory').get()).numChildren(), 5);
    await db.ref('dynamicQrNonces/legacy').set({ expiresAt: Date.now() + 60000 });
    assert.equal((await commitDynamicAccess(guarded, command('a', 'legacy', 'exit'))).reason, 'qr already used');
    await db.ref('students/c/active').set(false);
    assert.equal((await commitDynamicAccess(guarded, command('c', 'disabled', 'exit'))).reason, 'user disabled');
    // Simulate a revocation arriving after the profile snapshot was read.
    const staleProfileDb = { ref(path) {
      if (path !== 'students/a') return guarded.ref(path);
      return { async get() {
        const snapshot = await db.ref(path).get();
        await db.ref().update({ 'students/a/active': false, 'accessState/a/accessDisabled': true });
        return snapshot;
      } };
    } };
    assert.equal((await commitDynamicAccess(staleProfileDb, command('a', 'revoked-race', 'exit'))).reason, 'user disabled');
    assert.equal((await db.ref('accessState/a/inside').get()).val(), true);
    assert.equal((await db.ref('accessHistory/revoked-race').get()).exists(), false);
    await db.ref('students/c/active').set(true);
    for (let round = 0; round < 10; round++) {
      const repeated = await Promise.all(Array.from({ length: 12 }, () => commitDynamicAccess(guarded,
        command('c', `stress-${round}`, round % 2 === 0 ? 'exit' : 'entry'))));
      assert.equal(repeated.filter(r => r.ok).length, 1, `Round ${round}`);
      assert.equal(repeated.filter(r => r.reason === 'qr already used').length, 11, JSON.stringify(repeated));
    }
    const records = Object.fromEntries(Array.from({ length: 10001 }, (_, i) => [`k${String(i).padStart(6, '0')}`, {
      timestamp: 1000 + Math.floor(i / 3), guardId: 'guard', shiftId: 'shift', authorized: true
    }]));
    await db.ref('accessHistory').set(records);
    let report = await readGuardReport(db, { to: '99999', limit: '1' });
    assert.equal(report.data[0].countsComplete, false);
    assert.equal(report.data[0].scanned, 10000);
    assert.equal(report.data[0].totalAccesses, 10000);
    await db.ref('guardShifts/shift/endTimestamp').set(2000);
    report = await readGuardReport(db, { to: '99999', limit: '1' });
    assert.equal(report.data[0].countsComplete, true);
    await db.ref('guardShifts/second').set({ guardId: 'guard', startTimestamp: 1, endTimestamp: 2 });
    report = await readGuardReport(db, { to: '99999', limit: '1' });
    assert.ok(report.nextCursor);
    const next = await readGuardReport(db, { to: '99999', limit: '1', cursor: report.nextCursor });
    assert.notEqual(next.data[0].shiftId, report.data[0].shiftId);
    assert.equal(next.nextCursor, null);
  } finally { await db.ref().remove(); await deleteApp(app); }
});
