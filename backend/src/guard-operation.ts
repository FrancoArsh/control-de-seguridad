import { randomUUID } from 'node:crypto';
import type { Database } from 'firebase-admin/database';

export class GuardOperationBusy extends Error {
  constructor() { super('GUARD_OPERATION_BUSY'); }
}

const queues = new WeakMap<Database, Map<string, Promise<void>>>();

export async function withGuardOperation<T>(db: Database, guardId: string, operation: string, work: () => Promise<T>): Promise<T> {
  let queue = queues.get(db);
  if (!queue) { queue = new Map(); queues.set(db, queue); }
  const previous = queue.get(guardId) || Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const tail = previous.then(() => gate);
  queue.set(guardId, tail);
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([previous, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new GuardOperationBusy()), 5000); })]);
    clearTimeout(timer);
    return await withRemoteGuardOperation(db, guardId, operation, work);
  } finally {
    clearTimeout(timer); release();
    void tail.then(() => { if (queue!.get(guardId) === tail) queue!.delete(guardId); });
  }
}

// No lease expiry: an old worker may resume after a pause. Operators must stop
// every backend instance before recovering an orphaned lock, never just age it out.
async function withRemoteGuardOperation<T>(db: Database, guardId: string, operation: string, work: () => Promise<T>): Promise<T> {
  if (!guardId || /[.#$\[\]/\u0000-\u001f\u007f]/.test(guardId)) throw new Error('Invalid guard identifier');
  const ref = db.ref(`guardOperationLocks/${guardId}`);
  const owner = randomUUID(), startedAt = Date.now();
  const listener = () => {};
  ref.on('value', listener, () => {});
  let acquired = false;
  try {
    do {
      await ref.get();
      const result = await ref.transaction(current => current ? undefined : { owner, operation, startedAt }, undefined, false);
      acquired = result.committed;
      if (acquired) break;
      await new Promise(resolve => setTimeout(resolve, 50));
    } while (Date.now() - startedAt < 5000);
    if (!acquired) throw new GuardOperationBusy();
    return await work();
  } finally {
    try {
      if (acquired) await ref.transaction(current => current === null || current.owner === owner ? null : undefined, undefined, false);
    } finally { ref.off('value', listener); }
  }
}
