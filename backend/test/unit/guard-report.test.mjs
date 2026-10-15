import test from 'node:test';
import assert from 'node:assert/strict';
import { eventsForShift } from '../../dist/guard-report.js';
const shift = { id: 'shift-1', startTimestamp: 100, endTimestamp: 200 };
test('missing identities cannot attribute anonymous events to a guard', () => {
  assert.equal(eventsForShift([{ timestamp: 150, authorized: true }], 'g1', undefined, shift, 300).length, 0);
  assert.equal(eventsForShift([{ timestamp: 150, guardId: 'g1' }], 'g1', undefined, { id: null }, 300).length, 0);
});
test('explicit shift and guard IDs take precedence over time and auth fallback', () => {
  const rows = [
    { guardId: 'g1', shiftId: 'other', timestamp: 150 },
    { guardId: 'g2', validatedById: 'auth1', shiftId: 'shift-1', timestamp: 150 },
    { guardId: 'g1', shiftId: 'shift-1', timestamp: 200 },
    { validatedById: 'auth1', timestamp: 150 }
  ];
  assert.deepEqual(eventsForShift(rows, 'g1', 'auth1', shift, 300), rows.slice(2));
});
test('legacy event at shift boundary is counted only once', () => {
  const events = [{ guardId: 'g1', timestamp: 200 }];
  assert.equal(eventsForShift(events, 'g1', undefined, shift, 300).length, 0);
  assert.equal(eventsForShift(events, 'g1', undefined, { id: 'shift-2', startTimestamp: 200 }, 300).length, 1);
});
