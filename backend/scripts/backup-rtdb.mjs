import fs from "node:fs/promises";
import path from "node:path";
import { deleteApp } from "firebase-admin/app";
import { createDatabaseClient } from "./firebase-runtime.mjs";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const [key, value = "true"] = process.argv[index].split("=", 2);
  args.set(key.replace(/^--/, ""), value);
}

const defaultCollections = [
  "students",
  "guards",
  "accessState",
  "guardShifts",
  "guardAuthorizations",
  "accessHistory",
  "adminAuditLog",
  "securityEvents"
];
const outputDir = path.resolve(args.get("output") || process.env.BACKUP_OUTPUT_DIR || "./backups");
const includeSecrets = args.get("include-secrets") === "true";
const collections = (args.get("collections") || defaultCollections.join(","))
  .split(",").map(value => value.trim()).filter(Boolean);
const redactedKeys = /token|pinhash|secret|password/i;

function redact(value, key = "") {
  if (!includeSecrets && redactedKeys.test(key)) return "[REDACTED]";
  if (Array.isArray(value)) return value.map(item => redact(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, redact(childValue, childKey)]));
  }
  return value;
}

const { app, db } = createDatabaseClient("backup");
try {
  const data = {};
  const counts = {};
  for (const collection of collections) {
    const snapshot = await db.ref(collection).once("value");
    const value = snapshot.val() || {};
    data[collection] = redact(value);
    counts[collection] = value && typeof value === "object" ? Object.keys(value).length : 0;
  }

  const backup = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    projectId: process.env.GCLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT || "unknown",
    redacted: !includeSecrets,
    collections: data
  };
  await fs.mkdir(outputDir, { recursive: true });
  const filename = args.get("file") || `rtdb-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  const outputPath = path.join(outputDir, filename);
  await fs.writeFile(outputPath, JSON.stringify(backup, null, 2), "utf8");
  console.log(JSON.stringify({ ok: true, outputPath, redacted: !includeSecrets, counts }, null, 2));
} finally {
  await deleteApp(app);
}
