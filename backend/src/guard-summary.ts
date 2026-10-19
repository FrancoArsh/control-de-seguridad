import type { Database } from 'firebase-admin/database';

export function summarizeGuards(guards: Record<string, any> | null) {
  const rows = Object.values(guards || {}).filter(row => row && typeof row === 'object');
  const active = rows.filter(row => row.active !== false).length;
  return { total: rows.length, active, inactive: rows.length - active };
}

export async function readGuardSummary(db: Database) {
  return summarizeGuards((await db.ref('guards').get()).val());
}
