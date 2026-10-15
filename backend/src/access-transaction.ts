import type { Database } from 'firebase-admin/database';

type Root = Record<string, any>;
export type AccessCommand = {
  userId: string;
  type: 'entry' | 'exit' | 'auto';
  sessionId: string;
  eventId: string;
  cooldownMs: number;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  audit: Record<string, any>;
};
export type AccessResult = { ok: false; reason: string } | {
  ok: true; accessType: 'entry' | 'exit'; previousInside: boolean; newInside: boolean; name: string | null;
};

// A pure reducer validates the supplied authorization snapshot and current presence.
export function applyDynamicAccess(current: Root, command: AccessCommand, now: number):
  { result: AccessResult; value?: Root } {
  const reject = (reason: string) => ({ result: { ok: false as const, reason } });
  if (now >= command.expiresAt) return reject('qr expired');
  if (current.dynamicQrNonces?.[command.nonce]) return reject('qr already used');
  const student = current.students?.[command.userId];
  if (!student) return reject('user not found');
  if (student.active === false) return reject('user disabled');
  const guardId = command.audit.guardId;
  if (guardId) {
    const guard = current.guards?.[guardId];
    const shift = current.guardShifts?.[command.audit.shiftId];
    if (!guard || guard.active === false) return reject('guard disabled');
    if (!shift || shift.guardId !== guardId || shift.active === false || shift.endTimestamp) {
      return reject('GUARD_NOT_ON_SHIFT');
    }
  }
  const state = current.accessState?.[command.userId] || {};
  if (state.accessDisabled === true) return reject('user disabled');
  if (now - Math.max(Number(state.lastTimestamp || 0), Number(student.lastAccessTimestamp || 0)) < command.cooldownMs) {
    return reject('cooldown active');
  }
  const previousInside = state.inside === true;
  const accessType = command.type === 'auto' ? (previousInside ? 'exit' : 'entry') : command.type;
  if (accessType === 'entry' && previousInside) return reject('user already inside');
  if (accessType === 'exit' && !previousInside) return reject('user already outside');
  const newInside = accessType === 'entry';
  const event = {
    ...command.audit, id: command.userId, studentUid: command.userId, name: student.name || null,
    sede: student.sede || student.campus || null, tipoUsuario: student.tipoUsuario || student.role || null,
    authorized: true, reason: 'ok', sessionId: command.sessionId, accessType,
    previousInside, newInside, validationMode: 'dynamic', qrVersion: 2, timestamp: now
  };
  const value = {
    ...current,
    dynamicQrNonces: { ...current.dynamicQrNonces, [command.nonce]: {
      userId: command.userId, issuedAt: command.issuedAt, expiresAt: command.expiresAt, usedAt: now
    } },
    students: { ...current.students, [command.userId]: { ...student, lastAccessTimestamp: now, lastAccessType: accessType } },
    accessState: { ...current.accessState, [command.userId]: { ...state, inside: newInside, lastAccessType: accessType, lastTimestamp: now, sessionId: command.sessionId } },
    accessHistory: { ...current.accessHistory, [command.eventId]: event },
    attendance: { ...current.attendance, [command.sessionId]: {
      ...current.attendance?.[command.sessionId], [command.userId]: {
        ...current.attendance?.[command.sessionId]?.[command.userId], [command.eventId]: {
          type: accessType, timestamp: now, qrVersion: 2, validationMode: 'dynamic', previousInside, newInside
        }
      }
    } }
  };
  return { value, result: { ok: true, accessType, previousInside, newInside, name: student.name || null } };
}

export async function commitDynamicAccess(db: Database, command: AccessCommand): Promise<AccessResult> {
  const ref = db.ref(`accessState/${command.userId}`);
  const keepCached = () => {};
  let decision: AccessResult = { ok: false, reason: 'access state conflict' };
  ref.on('value', keepCached, () => {});
  try {
    for (let attempt = 0; attempt < 3; attempt++) {
      await flushPendingAccess(db, command.userId);
      const guardId = command.audit.guardId, shiftId = command.audit.shiftId;
      const [student, guard, shift, legacyNonce] = await Promise.all([
        db.ref(`students/${command.userId}`).get(),
        guardId ? db.ref(`guards/${guardId}`).get() : Promise.resolve(null),
        guardId && shiftId ? db.ref(`guardShifts/${shiftId}`).get() : Promise.resolve(null),
        db.ref(`dynamicQrNonces/${command.nonce}`).get()
      ]);
      await ref.get();
      // Authorization is checked at request time. Only this person's state and nonce
      // consumption participate in the transaction, not global profiles or shifts.
      const result = await ref.transaction(current => {
        const state = current || {};
        if (state._usedQrNonces?.[command.nonce]) { decision = { ok: false, reason: 'qr already used' }; return; }
        if (state._pendingAccess) { decision = { ok: false, reason: 'access pending' }; return; }
        const now = Date.now();
        const nonces: Record<string, any> = Object.fromEntries(Object.entries(state._usedQrNonces || {})
          .filter(([, value]: [string, any]) => Number(value?.expiresAt) > now));
        if (legacyNonce.exists()) nonces[command.nonce] = legacyNonce.val();
        const next = applyDynamicAccess({
          students: { [command.userId]: student.val() }, accessState: { [command.userId]: state },
          guards: guardId ? { [guardId]: guard?.val() } : {},
          guardShifts: shiftId ? { [shiftId]: shift?.val() } : {}, dynamicQrNonces: nonces
        }, command, now);
        decision = next.result;
        if (!next.value) return;
        const nonce = next.value.dynamicQrNonces[command.nonce];
        return { ...next.value.accessState[command.userId], _usedQrNonces: { ...nonces, [command.nonce]: nonce },
          _pendingAccess: { status: 'pending', eventId: command.eventId, event: next.value.accessHistory[command.eventId],
            nonceKey: command.nonce, nonce, attendance: next.value.attendance[command.sessionId][command.userId][command.eventId] } };
      }, undefined, false);
      if (result.committed) {
        try { await flushPendingAccess(db, command.userId, result.snapshot.val()._pendingAccess); }
        catch { throw new AccessPublicationPending(command.eventId); }
        return decision;
      }
      if (decision.ok) return { ok: false, reason: 'access state conflict' };
      if (decision.reason !== 'access pending') return decision;
    }
    return { ok: false, reason: 'access pending' };
  } finally {
    ref.off('value', keepCached);
  }
}

export class AccessPublicationPending extends Error {
  constructor(public readonly eventId: string) { super('Access committed; audit publication pending'); }
}

// The durable outbox is committed with presence and replay protection. Publication
// writes only immutable event paths, so delayed retries cannot overwrite newer presence.
export async function flushPendingAccess(db: Database, userId: string, captured?: any) {
  const ref = db.ref(`accessState/${userId}`);
  const pending = captured || (await ref.child('_pendingAccess').get()).val();
  if (!pending) return;
  const event = pending.event;
  await db.ref().update({
    [`accessHistory/${pending.eventId}`]: event,
    [`attendance/${event.sessionId}/${userId}/${pending.eventId}`]: pending.attendance,
    [`dynamicQrNonces/${pending.nonceKey}`]: pending.nonce
  });
  await ref.child('_pendingAccess').transaction(current => {
    if (current === null) return null;
    if (current?.eventId === pending.eventId) return null;
    return;
  }, undefined, false);
}

export async function recoverPendingAccess(db: Database) {
  const snapshot = await db.ref('accessState').orderByChild('_pendingAccess/status').equalTo('pending').limitToFirst(50).get();
  for (const id of Object.keys(snapshot.val() || {})) await flushPendingAccess(db, id);
  return snapshot.numChildren();
}
