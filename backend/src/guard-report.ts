import type { Database } from 'firebase-admin/database';
import { HistoryInputError, parseHistoryQuery } from './history';

// Prefer explicit shift IDs; legacy events may only carry a guard and a timestamp.
export function eventsForShift(events: any[], guardId: string, authUid: string | undefined, shift: any, now: number) {
  if (!shift.id || !Number.isFinite(Number(shift.startTimestamp))) return [];
  const start = Number(shift.startTimestamp), end = Number(shift.endTimestamp || now);
  return events.filter(event => {
    if (!event || typeof event !== 'object') return false;
    const ownerMatches = event.guardId ? event.guardId === guardId : Boolean(authUid && event.validatedById === authUid);
    if (!ownerMatches) return false;
    if (event.shiftId) return event.shiftId === shift.id;
    const timestamp = Number(event.timestamp);
    // A legacy event at a shared boundary belongs to the shift starting there.
    return Number.isFinite(timestamp) && timestamp >= start && (shift.endTimestamp ? timestamp < end : timestamp <= end);
  });
}

export async function readGuardReport(db: Database, query: Record<string, any>) {
  const options = parseHistoryQuery({ ...query, limit: query.limit ?? '5' });
  if (options.limit > 10) throw new HistoryInputError('Maximo 10 turnos por pagina.');
  let request = db.ref('guardShifts').orderByChild('startTimestamp').startAt(options.from);
  request = options.cursor ? request.endAt(options.cursor.timestamp, options.cursor.key) : request.endAt(options.to);
  const snapshot = await request.limitToLast(options.limit + 2).get();
  const shifts: any[] = [];
  snapshot.forEach(child => { shifts.push({ ...child.val(), id: child.key }); });
  const available = shifts.reverse().filter(shift => shift.id !== options.cursor?.key);
  const page = available.slice(0, options.limit), data = [];
  const generatedAt = Date.now();
  for (const shift of page) {
    const guard = (await db.ref(`guards/${shift.guardId}`).get()).val() || {};
    const end = Number(shift.endTimestamp || generatedAt);
    let cursor: { timestamp: number; key: string } | undefined;
    let scanned = 0, approvedAccesses = 0, rejectedAccesses = 0, countsComplete = false;
    // Read only the selected shift's time window, in bounded batches. Legacy
    // records without shiftId remain visible; no global history download is used.
    while (scanned < 10000) {
      let events = db.ref('accessHistory').orderByChild('timestamp').startAt(Number(shift.startTimestamp));
      events = cursor ? events.endAt(cursor.timestamp, cursor.key) : events.endAt(end);
      const eventSnapshot = await events.limitToLast(251).get();
      const batch: any[] = [];
      eventSnapshot.forEach(child => { batch.push({ ...child.val(), key: child.key }); });
      const remaining = batch.reverse().filter(event => event.key !== cursor?.key);
      const rows = remaining.slice(0, 250);
      for (const event of eventsForShift(rows, shift.guardId, guard.authUid, shift, generatedAt)) {
        if (event.authorized === true) approvedAccesses++;
        if (event.authorized === false) rejectedAccesses++;
      }
      scanned += rows.length;
      if (remaining.length <= 250 && batch.length < 251) { countsComplete = true; break; }
      const last = rows[rows.length - 1];
      if (!last) { countsComplete = true; break; }
      cursor = { timestamp: last.timestamp, key: last.key };
    }
    data.push({ id: shift.guardId, name: guard.name || shift.guardId, email: guard.email || null,
      active: guard.active !== false, shiftId: shift.id, startTimestamp: shift.startTimestamp,
      endTimestamp: shift.endTimestamp || null, shiftActive: shift.active !== false && !shift.endTimestamp,
      approvedAccesses, rejectedAccesses, totalAccesses: approvedAccesses + rejectedAccesses, countsComplete, scanned });
  }
  const last = page[page.length - 1];
  return { data, generatedAt, to: options.to, nextCursor: available.length > options.limit && last
    ? Buffer.from(JSON.stringify({ timestamp: last.startTimestamp, key: last.id })).toString('base64url') : null };
}
