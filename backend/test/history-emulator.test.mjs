import test from 'node:test';
import assert from 'node:assert/strict';
import { initializeApp, deleteApp } from 'firebase-admin/app';
import { getDatabase } from 'firebase-admin/database';
import { readHistoryPage } from '../dist/history.js';
import { endShift } from '../dist/shifts.js';
import { readFile } from 'node:fs/promises';

test('RTDB emulator: paginate 8501 events with tied timestamps and filters', { timeout: 90000 }, async () => {
  const host = process.env.FIREBASE_DATABASE_EMULATOR_HOST;
  assert.match(host || '', /^(127\.0\.0\.1|localhost):\d+$/, 'Only a local emulator is allowed');
  const project = `demo-history-${Date.now()}`;
  const app = initializeApp({ projectId: project, databaseURL: `http://${host}?ns=${project}` }, project);
  const db = getDatabase(app);
  try {
    const response = await fetch(`http://${host}/.settings/rules.json?ns=${project}`, {
      method: 'PUT', headers: { Authorization: 'Bearer owner', 'Content-Type': 'application/json' },
      body: await readFile(new URL('../database.rules.json', import.meta.url), 'utf8')
    });
    assert.equal(response.status, 200, 'Install repository indexes in the isolated namespace');
    const records = Object.fromEntries(Array.from({ length: 8501 }, (_, i) => [`k${String(i).padStart(6, '0')}`, {
      timestamp: 1000 + Math.floor(i / 3), studentUid: 'student', name: 'Persona', sede: 'Chillan', tipoUsuario: 'estudiante', authorized: i % 2 === 0
    }]));
    await db.ref('accessHistory').set(records);
    const user = { id: 'admin', uid: 'admin', role: 'admin' };
    let cursor, keys = [];
    do {
      const page = await readHistoryPage(db, user, { to: '99999', ...(cursor ? { cursor } : {}) });
      keys.push(...page.data.map(row => row.key)); cursor = page.nextCursor;
    } while (cursor);
    assert.equal(keys.length, 8501); assert.equal(new Set(keys).size, 8501);
    const page = await readHistoryPage(db, user, { from: '2000', to: '2100', outcome: 'no', sede: 'chillan' });
    assert.equal(page.data.length, 100);
    assert.ok(page.data.every(row => !row.authorized && row.timestamp >= 2000 && row.timestamp <= 2100));
    assert.equal((await db.ref('accessHistory').get()).numChildren(), 8501);
    await db.ref('guardShifts/shift-race').set({ guardId: 'guard-1', active: true, startTimestamp: 10, notes: 'Original' });
    assert.equal(await endShift(db, 'other-guard', 'shift-race', 'other'), null);
    const closed = await Promise.all(Array.from({ length: 8 }, (_, i) => endShift(db, 'guard-1', 'shift-race', `actor-${i}`, `note-${i}`)));
    assert.equal(closed.filter(Boolean).length, 1, 'Only one simultaneous close may succeed');
    const saved = (await db.ref('guardShifts/shift-race').get()).val();
    assert.equal(saved.endedBy, closed.find(Boolean).endedBy);
    assert.equal(saved.notes, closed.find(Boolean).notes);
    assert.equal(await endShift(db, 'guard-1', 'shift-race', 'late', 'overwrite'), null);
    assert.deepEqual((await db.ref('guardShifts/shift-race').get()).val(), saved);
  } finally { await db.ref().remove(); await deleteApp(app); }
});
