import test from 'node:test';
import assert from 'node:assert/strict';
import { readHistoryPage, parseHistoryQuery, HistoryInputError } from '../../dist/history.js';

const admin = { id: 'admin', uid: 'a', role: 'admin' };
function database(rows) {
  const calls = [];
  return { calls, ref(path) {
    assert.equal(path, 'accessHistory', 'No full profile reads for complete events');
    let from = 0, to = Infinity, endKey, limit;
    return {
      orderByChild(field) { assert.equal(field, 'timestamp'); return this; },
      startAt(value) { from = value; return this; },
      endAt(value, key) { to = value; endKey = key; return this; },
      limitToLast(value) { limit = value; return this; },
      async get() {
        assert.equal(limit, 101, 'Every database read must be bounded');
        const selected = rows.filter(r => r.timestamp >= from && (r.timestamp < to || (r.timestamp === to && (!endKey || r.key <= endKey))))
          .sort((a,b) => a.timestamp - b.timestamp || (a.key < b.key ? -1 : 1)).slice(-limit);
        calls.push(selected.length);
        return { forEach(fn) { for (const row of selected) fn({ key: row.key, val: () => row }); } };
      }
    };
  } };
}
const rows = Array.from({ length: 8501 }, (_, i) => ({ key: `k${String(i).padStart(6, '0')}`, timestamp: 1000 + Math.floor(i / 3),
  studentUid: i % 2 ? 'member-a' : 'member-b', name: `Persona ${i}`, sede: 'Chillan', tipoUsuario: 'estudiante', authorized: i % 2 === 0, guardId: 'g1' }));

test('8501 movements paginate without duplicates or omissions, including equal timestamps', async () => {
  const db = database(rows), seen = []; let cursor;
  do {
    const page = await readHistoryPage(db, admin, { to: '99999', ...(cursor ? { cursor } : {}) });
    assert.ok(page.data.length <= 100); assert.ok(page.scanned <= 1000);
    seen.push(...page.data.map(r => r.key)); cursor = page.nextCursor;
  } while (cursor);
  assert.equal(seen.length, rows.length); assert.equal(new Set(seen).size, rows.length);
  assert.equal(seen[0], rows.at(-1).key);
});
test('server enforces role scope and combined filters', async () => {
  const page = await readHistoryPage(database(rows), { id: 'member-b', uid: 'b', role: 'member' },
    { from: '2000', to: '3000', sede: 'chill', role: 'estudiante', outcome: 'yes', search: 'Persona' });
  assert.equal(page.data.length, 100);
  assert.ok(page.data.every(r => r.id === 'member-b' && r.authorized && r.timestamp >= 2000 && r.timestamp <= 3000));
  const guard = await readHistoryPage(database(rows), { id: 'other', uid: 'other', role: 'guard' }, { to: '99999' });
  assert.equal(guard.data.length, 0); assert.equal(guard.scanned, 1000); assert.ok(guard.nextCursor);
});
test('sparse filters keep a cursor and eventually reach old matching records', async () => {
  const db = database(rows); let cursor, found = [];
  do {
    const page = await readHistoryPage(db, admin, { to: '99999', search: 'Persona 0', ...(cursor ? { cursor } : {}) });
    assert.ok(db.calls.length); assert.ok(page.scanned <= 1000);
    found.push(...page.data); cursor = page.nextCursor;
  } while (cursor);
  assert.deepEqual(found.map(r => r.key), ['k000000']);
});
test('invalid ranges, filters and cursors are rejected', () => {
  for (const input of [{ limit: '101' }, { limit: '0' }, { from: '10', to: '1' }, { outcome: 'maybe' }, { search: [] }, { cursor: 'bad' }]) {
    assert.throws(() => parseHistoryQuery(input), HistoryInputError);
  }
});
test('empty history and fixed upper bound', async () => {
  assert.equal((await readHistoryPage(database([]), admin, {})).nextCursor, null);
  const page = await readHistoryPage(database(rows), admin, { to: '1000' });
  assert.equal(page.data.length, 3); assert.equal(page.nextCursor, null);
});
