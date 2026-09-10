import { deleteApp } from "firebase-admin/app";
import { createDatabaseClient } from "./firebase-runtime.mjs";

const checkConnection = process.argv.includes("--check-connection=true");
const errors = [];
const warnings = [];

if (process.env.NODE_ENV !== "staging") errors.push("NODE_ENV debe ser staging.");
for (const name of ["FIREBASE_DATABASE_URL", "JWT_SECRET", "QR_SECRET", "ALLOWED_ORIGINS"]) {
  if (!process.env[name]) errors.push(`${name} no está configurado.`);
}
if (process.env.QR_SECRET && process.env.JWT_SECRET === process.env.QR_SECRET) {
  errors.push("QR_SECRET debe ser independiente de JWT_SECRET.");
}
if ((process.env.ALLOWED_ORIGINS || "").match(/localhost|127\.0\.0\.1|your-project/i)) {
  errors.push("ALLOWED_ORIGINS contiene un origen local o de ejemplo.");
}
if (!process.env.FIREBASE_SERVICE_ACCOUNT && !process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  warnings.push("No se detectó credencial explícita; solo es aceptable si el runtime usa identidad administrada.");
}

let app;
if (checkConnection && errors.length === 0) {
  try {
    const client = createDatabaseClient("staging-preflight");
    app = client.app;
    await client.db.ref(".info/serverTimeOffset").once("value");
  } catch (error) {
    errors.push(`No fue posible conectar con Firebase staging: ${error.message}`);
  } finally {
    if (app) await deleteApp(app);
  }
}

console.log(JSON.stringify({ ok: errors.length === 0, environment: process.env.NODE_ENV || null, checkConnection, errors, warnings }, null, 2));
process.exitCode = errors.length ? 1 : 0;
