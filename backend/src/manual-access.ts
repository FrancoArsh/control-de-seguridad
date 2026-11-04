import type { Database } from 'firebase-admin/database';
import { withGuardOperation } from './guard-operation';
import { flushPendingAccess, AccessPublicationPending } from './access-transaction';

export type ManualAccessCommand = {
  userId: string;
  type: 'entry' | 'exit' | 'auto';
  sessionId: string;
  eventId: string;
  reason: string;
  audit: Record<string, any>;
};

export type ManualAccessResult =
  | { ok: false; reason: string }
  | { ok: true; accessType: 'entry' | 'exit'; previousInside: boolean; newInside: boolean; name: string | null };

export async function commitManualAccess(db: Database, command: ManualAccessCommand): Promise<ManualAccessResult> {
  return withGuardOperation(db, command.audit.guardId, 'manual-access', async () => {
    const ref = db.ref(`accessState/${command.userId}`);
    const listener = () => {};
    let decision: ManualAccessResult = { ok: false, reason: 'access state conflict' };
    ref.on('value', listener, () => {});
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
      await flushPendingAccess(db, command.userId);
      const [student, guard, shift] = await Promise.all([
        db.ref(`students/${command.userId}`).get(),
        db.ref(`guards/${command.audit.guardId}`).get(),
        db.ref(`guardShifts/${command.audit.shiftId}`).get()
      ]);
      await ref.get();
      const result = await ref.transaction(current => {
        const state = current || {};
        const person = student.val();
        const guardValue = guard.val();
        const shiftValue = shift.val();
        const reject = (reason: string) => { decision = { ok: false, reason }; return; };
        if (state._pendingAccess) return reject('access pending');
        if (!person) return reject('user not found');
        if (person.active === false || state.accessDisabled === true) return reject('user disabled');
        if (!guardValue || guardValue.active === false) return reject('guard disabled');
        if (!shiftValue || shiftValue.guardId !== command.audit.guardId || shiftValue.active === false || shiftValue.endTimestamp) {
          return reject('GUARD_NOT_ON_SHIFT');
        }
        const previousInside = state.inside === true;
        const accessType = command.type === 'auto' ? (previousInside ? 'exit' : 'entry') : command.type;
        if (accessType === 'entry' && previousInside) return reject('user already inside');
        if (accessType === 'exit' && !previousInside) return reject('user already outside');
        const newInside = accessType === 'entry';
        const event = {
          ...command.audit,
          id: command.userId,
          studentUid: command.userId,
          name: person.name || null,
          sede: person.sede || person.campus || null,
          tipoUsuario: person.tipoUsuario || person.role || null,
          authorized: true,
          reason: command.reason,
          sessionId: command.sessionId,
          accessType,
          previousInside,
          newInside,
          validationMode: 'manual',
          qrVersion: null,
          timestamp: Date.now()
        };
        decision = { ok: true, accessType, previousInside, newInside, name: person.name || null };
        return {
          ...state,
          inside: newInside,
          lastAccessType: accessType,
          lastTimestamp: event.timestamp,
          sessionId: command.sessionId,
          _pendingAccess: {
            kind: 'manual', status: 'pending', eventId: command.eventId, event,
            adminAudit: { actorId: command.audit.validatedById, actorName: command.audit.validatedByName || null,
              action: 'guard.manual_exception', entityType: 'access', entityId: command.userId,
              metadata: { reason: command.reason, accessType, shiftId: command.audit.shiftId },
              timestamp: event.timestamp, ip: command.audit.validatorIp || null },
            attendance: { type: accessType, timestamp: event.timestamp, qrVersion: null, validationMode: 'manual', previousInside, newInside }
          }
        };
      }, undefined, false);
      if (!result.committed) {
        if (!decision.ok && decision.reason === 'access pending') continue;
        return decision.ok ? { ok: false, reason: 'access state conflict' } : decision;
      }
      try { await flushPendingAccess(db, command.userId, result.snapshot.val()._pendingAccess); }
      catch { throw new AccessPublicationPending(command.eventId); }
      return decision;
      }
      return { ok: false, reason: 'access pending' };
    } finally { ref.off('value', listener); }
  });
}
