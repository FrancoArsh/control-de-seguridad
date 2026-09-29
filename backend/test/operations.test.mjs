import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { initializeApp, deleteApp } from "firebase-admin/app";
import { getDatabase } from "firebase-admin/database";

const root = path.resolve(import.meta.dirname, "..");
const projectId = process.env.GCLOUD_PROJECT || "control-de-seguridad-test";
const emulatorHost = process.env.FIREBASE_DATABASE_EMULATOR_HOST || "127.0.0.1:9000";
const databaseUrl = `http://${emulatorHost}?ns=${projectId}`;
const outputDir = path.join(root, ".tmp", "backup-test");
let seedApp;

function runScript(script, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(root, "scripts", script), ...args], {
      cwd: root,
      env: {
        ...process.env,
        FIREBASE_DATABASE_EMULATOR_HOST: emulatorHost,
        FIREBASE_DATABASE_URL: databaseUrl,
        GCLOUD_PROJECT: projectId,
        BACKUP_ENCRYPTION_KEY: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => {
      if (code !== 0) reject(new Error(`${script} failed (${code}): ${stderr || stdout}`));
      else resolve(JSON.parse(stdout));
    });
  });
}

before(async () => {
  seedApp = initializeApp({ projectId, databaseURL: databaseUrl }, "operations-seed");
  const db = getDatabase(seedApp);
  const oldTimestamp = Date.now() - 120 * 24 * 60 * 60 * 1000;
  await db.ref().set({
    accessHistory: {
      old: { timestamp: oldTimestamp, token: "sensitive-token" },
      recent: { timestamp: Date.now(), authorized: true }
    },
    adminAuditLog: { old: { timestamp: oldTimestamp, actorId: "admin" } },
    securityEvents: { old: { timestamp: oldTimestamp, outcome: "failure" } },
    dynamicQrNonces: {
      expired: { expiresAt: Date.now() - 1000, usedAt: oldTimestamp },
      active: { expiresAt: Date.now() + 60000, usedAt: Date.now() }
    }
  });
  await fs.rm(outputDir, { recursive: true, force: true });
});

after(async () => {
  await fs.rm(path.join(root, ".tmp"), { recursive: true, force: true });
  if (seedApp) await deleteApp(seedApp);
});

test("genera respaldo con secretos redactados", async () => {
  const result = await runScript("backup-rtdb.mjs", [
    `--output=${outputDir}`,
    "--file=integration-backup.json"
  ]);
  assert.equal(result.ok, true);
  assert.equal(result.redacted, true);
  const backup = JSON.parse(await fs.readFile(path.join(outputDir, "integration-backup.json"), "utf8"));
  assert.equal(backup.collections.accessHistory.old.token, "[REDACTED]");
  assert.equal(backup.collections.accessHistory.recent.authorized, true);

  const restorePreview = await runScript("restore-rtdb.mjs", [
    `--file=${path.join(outputDir, "integration-backup.json")}`
  ]);
  assert.equal(restorePreview.mode, "preview");
  assert.equal(restorePreview.collections.accessHistory, 2);
});

test("restaura datos y perfiles, excluyendo sesiones y secretos regenerables", async () => {
  const db = getDatabase(seedApp);
  await db.ref("admins/admin-1").set({ name: "Admin", role: "admin" });
  await db.ref("portalProfiles/user-1").set({ id: "student-1", role: "member", active: true });
  const file = path.join(outputDir, "complete-restore.json");
  await runScript("backup-rtdb.mjs", [`--output=${outputDir}`, "--file=complete-restore.json"]);
  await db.ref().set({ marker: "cleared" });
  const applied = await runScript("restore-rtdb.mjs", [`--file=${file}`, "--apply=true"]);
  assert.equal(applied.mode, "apply");
  assert.equal((await db.ref("admins/admin-1/role").once("value")).val(), "admin");
  assert.equal((await db.ref("portalProfiles/user-1/role").once("value")).val(), "member");
  assert.equal((await db.ref("portalSessions").once("value")).exists(), false);
  assert.equal((await db.ref("dynamicQrNonces").once("value")).exists(), false);
});

test("genera respaldo cifrado y permite previsualizar su restauracion", async () => {
  const encryptedDir = path.join(outputDir, "encrypted");
  const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const result = await runScript("backup-rtdb.mjs", [`--output=${encryptedDir}`, "--file=encrypted.json", "--encrypt=true"]);
  assert.equal(result.encrypted, true);
  const envelope = JSON.parse(await fs.readFile(path.join(encryptedDir, "encrypted.json"), "utf8"));
  assert.equal(envelope.encrypted, true);
  assert.equal(envelope.collections, undefined);
  const restorePreview = await runScript("restore-rtdb.mjs", [`--file=${path.join(encryptedDir, "encrypted.json")}`]);
  assert.equal(restorePreview.mode, "preview");
});

test("retención opera en preview y luego aplica el borrado", async () => {
  const db = getDatabase(seedApp);
  const oldTimestamp = Date.now() - 120 * 24 * 60 * 60 * 1000;
  await db.ref("accessHistory/old").set({ timestamp: oldTimestamp, token: "sensitive-token" });
  await db.ref("dynamicQrNonces/expired").set({ expiresAt: Date.now() - 1000, usedAt: oldTimestamp });
  await db.ref("dynamicQrNonces/active").set({ expiresAt: Date.now() + 60000, usedAt: Date.now() });
  const preview = await runScript("retention-rtdb.mjs", ["--retention-days=90"]);
  assert.equal(preview.mode, "preview");
  assert.equal(preview.affected.dynamicQrNonces, 1);
  assert.equal(preview.affected.accessHistory, 1);

  assert.ok((await db.ref("accessHistory/old").once("value")).exists());

  const applied = await runScript("retention-rtdb.mjs", ["--retention-days=90", "--apply=true"]);
  assert.equal(applied.mode, "apply");
  assert.equal((await db.ref("accessHistory/old").once("value")).exists(), false);
  assert.equal((await db.ref("accessHistory/recent").once("value")).exists(), true);
  assert.equal((await db.ref("dynamicQrNonces/expired").once("value")).exists(), false);
  assert.equal((await db.ref("dynamicQrNonces/active").once("value")).exists(), true);
});
