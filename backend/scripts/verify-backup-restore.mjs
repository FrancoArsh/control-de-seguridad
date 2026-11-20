import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { initializeApp, deleteApp } from "firebase-admin/app";
import { getDatabase } from "firebase-admin/database";
import { decryptBackup } from "./backup-crypto.mjs";

const file = process.argv[2];
const projectId = process.env.GCLOUD_PROJECT;
const host = process.env.FIREBASE_DATABASE_EMULATOR_HOST;
assert.match(projectId || "", /^demo-[a-z0-9-]+$/);
assert.match(host || "", /^(127\.0\.0\.1|localhost):\d+$/);
const databaseURL = 'http://' + host + '?ns=' + projectId;
const start = performance.now();
const envelope = JSON.parse(await fs.readFile(file, "utf8"));
assert.equal(envelope.encrypted, true);
const backup = decryptBackup(envelope);
assert.equal(backup.redacted, true);
assert.equal(backup.projectId, "control-seguridad-staging");
assert.ok(backup.collections.accessHistory && backup.collections.portalProfiles);
const app = initializeApp({ projectId, databaseURL });
try {
  const db = getDatabase(app);
  assert.equal((await db.ref().get()).exists(), false, "El emulador debe estar vacío");
  const restored = spawnSync(process.execPath, [fileURLToPath(new URL("./restore-rtdb.mjs", import.meta.url)), "--file=" + file, "--apply=true"], {
    env: { ...process.env, NODE_ENV: "test", FIREBASE_DATABASE_URL: databaseURL, FIREBASE_SERVICE_ACCOUNT: "", GOOGLE_APPLICATION_CREDENTIALS: "" },
    encoding: "utf8", timeout: 120000
  });
  assert.equal(restored.status, 0, "Falló restore-rtdb.mjs en el emulador");
  for (const [collection, expected] of Object.entries(backup.collections)) {
    const actual = (await db.ref(collection).get()).val() || {};
    assert.ok(isDeepStrictEqual(actual, expected), "Diferencia en " + collection);
  }
  const last = Object.values(backup.collections.accessHistory).reduce((max, e) => Math.max(max, Number(e?.timestamp) || 0), 0);
  console.log(JSON.stringify({ restoredAndCompared: true, source: backup.projectId, target: projectId,
    backupGeneratedAt: backup.generatedAt, lastRecoveredAccessAt: last ? new Date(last).toISOString() : null,
    collections: Object.keys(backup.collections).length, historyRecords: Object.keys(backup.collections.accessHistory).length,
    elapsedMs: Math.round(performance.now() - start), scope: "RTDB", authInventoryOnly: true }));
} finally { await deleteApp(app); }
