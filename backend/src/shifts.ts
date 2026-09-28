import admin from 'firebase-admin';

export async function startShift(db: admin.database.Database, guardId: string, actor: string, notes: string) {
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
