import test from 'node:test';
import assert from 'node:assert/strict';
import { applyDynamicAccess } from '../../dist/access-transaction.js';

const initial = () => ({ students: { person: { name: 'Synthetic', active: true } }, guards: { guard: { active: true } }, guardShifts: { shift: { guardId: 'guard', active: true } } });
const command = { userId: 'person', type: 'entry', sessionId: 'default', eventId: 'event', cooldownMs: 1000, nonce: 'nonce', issuedAt: 1000, expiresAt: 10000, audit: { guardId: 'guard', shiftId: 'shift', validatedById: 'guard' } };

test('atomic reducer returns nonce, presence, student timestamp, attendance and history together', () => {
  const root = initial(); const previous = structuredClone(root);
  const { value, result } = applyDynamicAccess(root, command, 2000);
  assert.deepEqual(root, previous);
  assert.equal(result.ok, true);
  assert.equal(value.dynamicQrNonces.nonce.usedAt, 2000);
  assert.equal(value.accessState.person.inside, true);
  assert.equal(value.students.person.lastAccessTimestamp, 2000);
  assert.equal(value.accessHistory.event.authorized, true);
  assert.equal(value.attendance.default.person.event.type, 'entry');
  assert.equal(value.accessHistory.event.token, undefined);
});
test('replay and conflicts leave all collections untouched', () => {
  const { value } = applyDynamicAccess(initial(), command, 2000);
  assert.equal(applyDynamicAccess(value, command, 4000).result.reason, 'qr already used');
  const conflict = applyDynamicAccess(value, { ...command, nonce: 'second' }, 4000);
  assert.equal(conflict.value, undefined);
  assert.equal(conflict.result.reason, 'user already inside');
});

test('transaction-local revocation overrides a stale active profile', () => {
  const root = { ...initial(), accessState: { person: { accessDisabled: true } } };
  const rejected = applyDynamicAccess(root, command, 2000);
  assert.equal(rejected.result.reason, 'user disabled');
  assert.equal(rejected.value, undefined);
  root.accessState.person.accessDisabled = false;
  assert.equal(applyDynamicAccess(root, command, 2000).result.ok, true);
});
test('retry rechecks expiry, disabled person and closed shift without consuming nonce', () => {
  for (const [root, now, reason] of [
    [initial(), 10000, 'qr expired'],
    [{ ...initial(), students: { person: { active: false } } }, 2000, 'user disabled'],
    [{ ...initial(), guardShifts: { shift: { guardId: 'guard', active: false } } }, 2000, 'GUARD_NOT_ON_SHIFT']
  ]) {
    const next = applyDynamicAccess(root, command, now);
    assert.equal(next.result.reason, reason); assert.equal(next.value, undefined);
  }
});
test('independent retry after cooldown can succeed and explicit exit is consistent', () => {
  const first = applyDynamicAccess(initial(), command, 2000).value;
  const exit = { ...command, type: 'exit', eventId: 'exit', nonce: 'exit' };
  assert.equal(applyDynamicAccess(first, exit, 2100).value, undefined);
  const next = applyDynamicAccess(first, exit, 4000);
  assert.equal(next.value.accessState.person.inside, false);
  assert.equal(Object.keys(next.value.accessHistory).length, 2);
});
