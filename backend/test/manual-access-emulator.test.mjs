import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { initializeApp, deleteApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { commitManualAccess } from '../dist/manual-access.js';
import { commitDynamicAccess, AccessPublicationPending, flushPendingAccess } from '../dist/access-transaction.js';

test('manual exceptions preserve pending QR events and recover audit atomically', { timeout: 30000 }, async () => {
  const host = process.env.FIREBASE_DATABASE_EMULATOR_HOST;
  assert.match(host || '', /^127\.0\.0\.1:\d+$/);
  const project = `demo-manual-${Date.now()}`;
  const app = initializeApp({ projectId: project, databaseURL: `http://${host}?ns=${project}` }, project);
  const db = getDatabase(app);
  let failPublication = false;
  const controlled = { ref(path) {
    if (path) return db.ref(path);
    return { update(values) { if (failPublication) throw new Error('Injected publication outage'); return db.ref().update(values); } };
  } };
  const manual = (eventId, type, guardId = 'g1') => ({ userId: 'person', eventId, type, sessionId: 'test', reason: 'Verified exception',
    audit: { guardId, shiftId: guardId, validatedById: guardId, validatedByName: 'Synthetic guard' } });
  try {
    const rules = await fetch(`http://${host}/.settings/rules.json?ns=${project}`, { method: 'PUT',
      headers: { Authorization: 'Bearer owner', 'Content-Type': 'application/json' },
      body: await readFile(new URL('../database.rules.json', import.meta.url), 'utf8') });
    assert.equal(rules.status, 200);
    await db.ref().set({ students: { person: { name: 'Synthetic person', active: true } },
      guards: { g1: { active: true }, g2: { active: true } },
      guardShifts: { g1: { guardId: 'g1', active: true }, g2: { guardId: 'g2', active: true } } });
    failPublication = true;
    await assert.rejects(commitDynamicAccess(controlled, { ...manual('qr-entry', 'entry'), nonce: 'pending-qr', cooldownMs: 0,
      issuedAt: Date.now(), expiresAt: Date.now() + 60000 }), AccessPublicationPending);
    const pendingQr = (await db.ref('accessState/person/_pendingAccess').get()).val();
    await assert.rejects(commitManualAccess(controlled, manual('must-not-overwrite', 'exit')), /Injected publication outage/);
    assert.deepEqual((await db.ref('accessState/person/_pendingAccess').get()).val(), pendingQr);
    assert.equal((await db.ref('accessState/person/inside').get()).val(), true);
    failPublication = false;
    assert.equal((await commitManualAccess(controlled, manual('manual-exit', 'exit'))).ok, true);
    assert.equal((await db.ref('accessHistory/qr-entry/validationMode').get()).val(), 'dynamic');
    assert.equal((await db.ref('dynamicQrNonces/pending-qr').get()).exists(), true);
    assert.equal((await db.ref('accessHistory/manual-exit/validationMode').get()).val(), 'manual');
    assert.equal((await db.ref('adminAuditLog/manual-exit/metadata/reason').get()).val(), 'Verified exception');
    failPublication = true;
    await assert.rejects(commitManualAccess(controlled, manual('manual-pending', 'entry')), AccessPublicationPending);
    assert.equal((await db.ref('accessState/person/inside').get()).val(), true);
    assert.equal((await db.ref('accessState/person/_pendingAccess/adminAudit').get()).exists(), true);
    assert.equal((await db.ref('adminAuditLog/manual-pending').get()).exists(), false);
    failPublication = false;
    await flushPendingAccess(db, 'person');
    assert.equal((await db.ref('accessHistory/manual-pending').get()).exists(), true);
    assert.equal((await db.ref('adminAuditLog/manual-pending').get()).exists(), true);
    assert.equal((await db.ref('adminAuditLog').get()).numChildren(), 2);
    assert.equal((await db.ref('accessState/person/_pendingAccess').get()).exists(), false);
    await db.ref('accessState/person/inside').set(false);
    const races = await Promise.all(Array.from({ length: 8 }, (_, i) => commitManualAccess(controlled,
      manual(`race-${i}`, 'entry', i % 2 ? 'g1' : 'g2'))));
    assert.equal(races.filter(result => result.ok).length, 1);
    assert.equal((await db.ref('accessState/person/inside').get()).val(), true);
    const entries = Object.values((await db.ref('accessHistory').get()).val()).filter(row => row.validationMode === 'manual');
    assert.equal(entries.length, 3);
    await db.ref('accessState/person/accessDisabled').set(true);
    assert.equal((await commitManualAccess(controlled, manual('disabled', 'exit'))).reason, 'user disabled');
    assert.equal((await db.ref('accessHistory/disabled').get()).exists(), false);
  } finally { await db.ref().remove(); await deleteApp(app); }
});
