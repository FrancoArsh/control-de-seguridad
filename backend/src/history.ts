import type { Database } from 'firebase-admin/database';

type Viewer = { uid: string; id: string; role: 'admin' | 'guard' | 'member' };
type Cursor = { timestamp: number; key: string };
export class HistoryInputError extends Error {}

export function parseHistoryQuery(query: Record<string, any>) {
  const scalar = (name: string, fallback = '') => {
    const value = query[name] ?? fallback;
    if (typeof value !== 'string' || value.length > 1024) throw new HistoryInputError('Filtro no valido.');
    return value;
  };
  const number = (name: string, fallback: number) => {
    const raw = scalar(name, String(fallback));
    const value = Number(raw);
    if (!/^\d+$/.test(raw) || !Number.isSafeInteger(value) || value < 0) throw new HistoryInputError('Rango no valido.');
    return value;
  };
  const limit = number('limit', 100), from = number('from', 0), to = number('to', Date.now());
  if (limit < 1 || limit > 100 || from > to) throw new HistoryInputError('Rango o limite no valido.');
  const outcome = scalar('outcome', 'all');
  if (!['all', 'yes', 'no'].includes(outcome)) throw new HistoryInputError('Resultado no valido.');
  let cursor: Cursor | undefined;
  const encoded = scalar('cursor');
  if (encoded) {
    try {
      cursor = JSON.parse(Buffer.from(encoded, 'base64url').toString());
      if (!cursor || !Number.isSafeInteger(cursor.timestamp) || cursor.timestamp < from || cursor.timestamp > to ||
          typeof cursor.key !== 'string' || !cursor.key || /[.#$\[\]/\u0000-\u001f\u007f]/.test(cursor.key)) throw new Error();
    } catch { throw new HistoryInputError('Cursor no valido.'); }
  }
  return { limit, from, to, cursor, outcome, search: scalar('search').trim().toLowerCase(), sede: scalar('sede').trim().toLowerCase(), role: scalar('role').trim().toLowerCase() };
}

export async function readHistoryPage(db: Database, user: Viewer, query: Record<string, any>) {
  const filters = parseHistoryQuery(query);
  let cursor = filters.cursor, scanned = 0, exhausted = false;
  const data: any[] = [];
  const profiles = new Map<string, any>();
  // Bound every request, including sparse filters, without dropping unvisited records.
  while (scanned < 1000 && data.length < filters.limit) {
    let request = db.ref('accessHistory').orderByChild('timestamp').startAt(filters.from);
    request = cursor ? request.endAt(cursor.timestamp, cursor.key) : request.endAt(filters.to);
    const snapshot = await request.limitToLast(101).get();
    const batch: { key: string; row: any }[] = [];
    snapshot.forEach(child => { batch.push({ key: child.key!, row: child.val() }); });
    batch.reverse();
    const available = batch.filter(item => item.key !== cursor?.key);
    const entries = available.slice(0, 100);
    if (!entries.length) { exhausted = true; break; }
    // Legacy events lack profile fields. Resolve distinct people in small parallel
    // batches instead of serializing hundreds of network round trips per page.
    const missing = [...new Set(entries.filter(({ row }) => row && typeof row === 'object')
      .filter(({ row }) => user.role === 'admin' || (user.role === 'member'
        ? String(row.studentUid || row.id || '') === user.id : row.validatedById === user.uid || row.guardId === user.id))
      .filter(({ row }) => !row.name || !row.sede || !row.tipoUsuario)
      .map(({ row }) => String(row.studentUid || row.id || '')))]
      .filter(id => id && !/[.#$\[\]/\u0000-\u001f\u007f]/.test(id) && !profiles.has(id));
    for (let offset = 0; offset < missing.length; offset += 8) {
      await Promise.all(missing.slice(offset, offset + 8).map(async id => {
        const values = await Promise.all(['students', 'guards', 'admins'].map(collection => db.ref(`${collection}/${id}`).get()));
        profiles.set(id, values.reverse().find(value => value.exists())?.val() || {});
      }));
    }
    for (const { key, row } of entries) {
      cursor = { timestamp: row.timestamp, key };
      scanned++;
      const id = String(row.studentUid || row.id || '');
      if (user.role === 'member' && id !== user.id) continue;
      if (user.role === 'guard' && row.validatedById !== user.uid && row.guardId !== user.id) continue;
      if (filters.outcome !== 'all' && (row.authorized === true) !== (filters.outcome === 'yes')) continue;
      const person: any = profiles.get(id) || {};
      const item = {
        key, id, name: String(row.name || row.studentName || person.name || id || 'Sin identificar'),
        timestamp: Number(row.timestamp), accessType: row.accessType || null,
        authorized: row.authorized === true, reason: String(row.reason || (row.authorized === true ? 'ok' : 'Sin motivo registrado')),
        sede: String(row.sede || row.campus || person.sede || person.campus || 'Sin sede'),
        tipoUsuario: String(row.tipoUsuario || row.role || person.tipoUsuario || person.role || 'Sin tipo'),
        validatedBy: String(row.validatedByName || row.validatedById || 'Sin registrar'), validatedByRole: String(row.validatedByRole || '')
      };
      if (!`${item.name} ${id}`.toLowerCase().includes(filters.search) || !item.sede.toLowerCase().includes(filters.sede) ||
          !`${item.tipoUsuario} ${item.validatedByRole}`.toLowerCase().includes(filters.role)) continue;
      data.push(item);
      if (data.length === filters.limit) break;
    }
    const consumed = cursor?.key === entries[entries.length - 1].key;
    if (consumed && available.length <= 100 && batch.length < 101) { exhausted = true; break; }
  }
  return { data, nextCursor: !exhausted && cursor ? Buffer.from(JSON.stringify(cursor)).toString('base64url') : null,
    from: filters.from, to: filters.to, limit: filters.limit, scanned };
}
