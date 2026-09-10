import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { deleteApp } from "firebase-admin/app";
import { createDatabaseClient } from "./firebase-runtime.mjs";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const [key, value = "true"] = process.argv[index].split("=", 2);
  args.set(key.replace(/^--/, ""), value);
}

const applyChanges = args.get("apply") === "true";
const outputDir = path.resolve(args.get("output") || process.env.RECOVERY_OUTPUT_DIR || "./recovery");
const { app, db } = createDatabaseClient("credential-recovery");

try {
  const [studentsSnap, guardsSnap] = await Promise.all([
    db.ref("students").once("value"),
    db.ref("guards").once("value")
  ]);
  const students = studentsSnap.val() || {};
  const guards = guardsSnap.val() || {};
  const updates = {};
  const credentials = { students: [], guards: [] };

  for (const id of Object.keys(students)) {
    const token = crypto.randomBytes(24).toString("hex");
    credentials.students.push({ id, token });
    updates[`accessTokens/${id}`] = { token, createdAt: Date.now(), rotatedAt: Date.now(), reason: "credential-recovery" };
  }
  for (const id of Object.keys(guards)) {
    const pin = String(crypto.randomInt(100000, 1000000));
    credentials.guards.push({ id, pin });
    updates[`guards/${id}/pinHash`] = await bcrypt.hash(pin, 10);
    updates[`guards/${id}/pinCreatedAt`] = Date.now();
    updates[`guards/${id}/tempPinHash`] = null;
    updates[`guards/${id}/tempPinExpiresAt`] = null;
  }

  if (!applyChanges) {
    console.log(JSON.stringify({ ok: true, mode: "preview", students: credentials.students.length, guards: credentials.guards.length, message: "No se modificó la base de datos." }, null, 2));
    await deleteApp(app);
    process.exitCode = 0;
  } else {
    await db.ref().update(updates);
    await fs.mkdir(outputDir, { recursive: true });
    const file = path.join(outputDir, `credential-recovery-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
    await fs.writeFile(file, JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), warning: "Archivo sensible. Entregar por canal seguro y eliminar después de confirmar la rotación.", credentials }, null, 2), { encoding: "utf8", mode: 0o600 });
    console.log(JSON.stringify({ ok: true, mode: "apply", students: credentials.students.length, guards: credentials.guards.length, output: file, message: "Credenciales regeneradas. Revise y elimine el archivo por un canal seguro." }, null, 2));
  }
} finally {
  if (applyChanges) await deleteApp(app);
}
