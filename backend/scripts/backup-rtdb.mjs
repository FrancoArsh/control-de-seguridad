import fs from "node:fs/promises";
import path from "node:path";
import { deleteApp } from "firebase-admin/app";
import { createDatabaseClient } from "./firebase-runtime.mjs";
import { getAuth } from "firebase-admin/auth";
import { encryptBackup } from "./backup-crypto.mjs";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const [key, value = "true"] = process.argv[index].split("=", 2);
  args.set(key.replace(/^--/, ""), value);
}

const defaultCollections = [
  "students",
  "guards",
  "admins",
  "portalProfiles",
  "accessState",
  "guardShifts",
  "guardAuthorizations",
  "accessHistory",
  "adminAuditLog",
  "securityEvents"
];
const outputDir = path.resolve(args.get("output") || process.env.BACKUP_OUTPUT_DIR || "./backups");
const includeSecrets = args.get("include-secrets") === "true";
const encrypt = args.get("encrypt") === "true" || process.env.BACKUP_ENCRYPT === "true";
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

  const authUsers = [];
  const authUsersSkipped = Boolean(process.env.FIREBASE_DATABASE_EMULATOR_HOST && !process.env.FIREBASE_AUTH_EMULATOR_HOST);
  if (!authUsersSkipped) {
    let page;
    do {
      page = await getAuth(app).listUsers(1000, page?.pageToken);
      authUsers.push(...page.users.map(user => ({ uid: user.uid, email: user.email || null, disabled: user.disabled, displayName: user.displayName || null, emailVerified: user.emailVerified, createdAt: user.metadata.creationTime || null, lastSignInAt: user.metadata.lastSignInTime || null })));
    } while (page.pageToken);
  }
  const backup = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    projectId: process.env.GCLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT || "unknown",
    redacted: !includeSecrets,
    collections: data,
    authUsers,
    authUsersSkipped,
    restoreNotes: ["Las contrasenas de Firebase Auth no son exportables.", "Las sesiones activas no se respaldan; deben invalidarse y regenerarse tras una recuperacion."]
  };
  await fs.mkdir(outputDir, { recursive: true });
  const filename = args.get("file") || `rtdb-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  const outputPath = path.join(outputDir, filename);
  const document = encrypt ? encryptBackup(backup) : backup;
  await fs.writeFile(outputPath, JSON.stringify(document, null, 2), { encoding: "utf8", mode: 0o600 });
  console.log(JSON.stringify({ ok: true, outputPath, encrypted: encrypt, redacted: !includeSecrets, authUsers: authUsers.length, authUsersSkipped, counts }, null, 2));
} finally {
  await deleteApp(app);
}
