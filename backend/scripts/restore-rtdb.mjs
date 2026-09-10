import fs from "node:fs/promises";
import path from "node:path";
import { deleteApp } from "firebase-admin/app";
import { createDatabaseClient } from "./firebase-runtime.mjs";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const [key, value = "true"] = process.argv[index].split("=", 2);
  args.set(key.replace(/^--/, ""), value);
}

const file = args.get("file");
const applyChanges = args.get("apply") === "true";
if (!file) {
  console.error("Uso: node scripts/restore-rtdb.mjs --file=./backups/rtdb.json [--apply=true]");
  process.exit(2);
}

const backup = JSON.parse(await fs.readFile(path.resolve(file), "utf8"));
const collections = backup.collections || {};
const summary = Object.fromEntries(Object.entries(collections).map(([name, value]) => [
  name,
  value && typeof value === "object" ? Object.keys(value).length : 0
]));

if (!applyChanges) {
  console.log(JSON.stringify({ ok: true, mode: "preview", source: path.resolve(file), redacted: backup.redacted === true, collections: summary }, null, 2));
  process.exit(0);
}

const { app, db } = createDatabaseClient("restore");
try {
  for (const [collection, value] of Object.entries(collections)) {
    await db.ref(collection).set(value);
  }
  console.log(JSON.stringify({ ok: true, mode: "apply", source: path.resolve(file), redacted: backup.redacted === true, collections: summary }, null, 2));
} finally {
  await deleteApp(app);
}
