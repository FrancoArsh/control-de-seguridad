import type { Database } from 'firebase-admin/database';
import { withGuardOperation } from './guard-operation';

export async function endShift(db: Database, guardId: string, shiftId: string, actor: string, notes?: string) {
  return withGuardOperation(db, guardId, 'end-shift', () => endShiftLocked(db, guardId, shiftId, actor, notes));
}

async function endShiftLocked(db: Database, guardId: string, shiftId: string, actor: string, notes?: string) {
  if (!shiftId || /[.#$\[\]/\u0000-\u001f\u007f]/.test(shiftId)) throw new Error('Invalid shift identifier');
  const ref = db.ref(`guardShifts/${shiftId}`);
  // Warm the transaction cache so a missing initial local snapshot is not mistaken for a missing shift.
  const listener = () => {};
  ref.on('value', listener, () => {});
  try {
    await ref.get();
    const result = await ref.transaction(current => {
      if (!current || current.guardId !== guardId || current.active === false || current.endTimestamp) return;
      return { ...current, endTimestamp: Date.now(), active: false, endedBy: actor,
        notes: (notes === undefined ? String(current.notes || '') : notes).slice(0, 500) || null };
    }, undefined, false);
    return result.committed ? { ...result.snapshot.val(), id: shiftId } : null;
  } finally { ref.off('value', listener); }
}

export async function startShift(db: Database, guardId: string, actor: string, notes: string) {
  return withGuardOperation(db, guardId, 'start-shift', async () => {
    const guard = (await db.ref(`guards/${guardId}`).get()).val();
    if (!guard || guard.active === false) throw new Error('Guard disabled');
    return startShiftLocked(db, guardId, actor, notes);
  });
}

async function startShiftLocked(db: Database, guardId: string, actor: string, notes: string) {
  const ref = db.ref('guardShifts');
  const id = ref.push().key!;
  const shift = { guardId, createdBy: actor, startTimestamp: Date.now(), active: true, notes: notes.slice(0, 500) };
  // One transaction covers both the uniqueness check and insertion, including legacy shifts.
  const result = await ref.transaction(current => {
    const shifts = current || {};
    if (Object.values(shifts).some((s: any) => s.guardId === guardId && s.active !== false && !s.endTimestamp)) return;
    return { ...shifts, [id]: shift };
  });
  return result.committed ? { id, ...shift } : null;
}
