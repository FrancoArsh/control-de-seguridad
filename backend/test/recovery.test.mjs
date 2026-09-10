import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import bcrypt from "bcrypt";
import { initializeApp, deleteApp } from "firebase-admin/app";
import { getDatabase } from "firebase-admin/database";

const root = path.resolve(import.meta.dirname, "..");
const projectId = process.env.GCLOUD_PROJECT || "control-de-seguridad-test";
const emulatorHost = process.env.FIREBASE_DATABASE_EMULATOR_HOST || "127.0.0.1:9000";
const databaseUrl = `http://${emulatorHost}?ns=${projectId}`;
const outputDir = path.join(root, ".tmp", "recovery-test");
let seedApp;

function runScript(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(root, "scripts", "credential-recovery.mjs"), ...args], {
      cwd: root,
      env: {
        ...process.env,
        FIREBASE_DATABASE_EMULATOR_HOST: emulatorHost,
        FIREBASE_DATABASE_URL: databaseUrl,
        GCLOUD_PROJECT: projectId
      },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => {
      if (code !== 0) reject(new Error(`credential-recovery failed (${code}): ${stderr || stdout}`));
      else resolve(JSON.parse(stdout));
    });
  });
}

before(async () => {
  seedApp = initializeApp({ projectId, databaseURL: databaseUrl }, "recovery-seed");
  const db = getDatabase(seedApp);
  await db.ref().set({
    students: { "student-1": { name: "Estudiante de prueba" } },
    accessTokens: { "student-1": { token: "old-token" } },
    guards: { "guard-1": { name: "Guardia de prueba", pinHash: await bcrypt.hash("111111", 10) } }
  });
  await fs.rm(outputDir, { recursive: true, force: true });
});

after(async () => {
  await fs.rm(path.join(root, ".tmp"), { recursive: true, force: true });
  if (seedApp) await deleteApp(seedApp);
});

test("preview no modifica y apply rota token y PIN", async () => {
  const preview = await runScript([`--output=${outputDir}`]);
  assert.equal(preview.ok, true);
  assert.equal(preview.mode, "preview");
  assert.equal(preview.students, 1);
  assert.equal(preview.guards, 1);

  const db = getDatabase(seedApp);
  assert.equal((await db.ref("accessTokens/student-1/token").once("value")).val(), "old-token");

  const applied = await runScript([`--output=${outputDir}`, "--apply=true"]);
  assert.equal(applied.ok, true);
  assert.equal(applied.mode, "apply");
  const recovery = JSON.parse(await fs.readFile(applied.output, "utf8"));
  assert.equal(recovery.credentials.students.length, 1);
  assert.equal(recovery.credentials.guards.length, 1);
  assert.notEqual((await db.ref("accessTokens/student-1/token").once("value")).val(), "old-token");
  const newPin = recovery.credentials.guards[0].pin;
  const newHash = (await db.ref("guards/guard-1/pinHash").once("value")).val();
  assert.equal(await bcrypt.compare(newPin, newHash), true);
  await fs.rm(outputDir, { recursive: true, force: true });
});
