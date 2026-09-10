import { deleteApp } from "firebase-admin/app";
import { createDatabaseClient } from "./firebase-runtime.mjs";

const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const [key, value = "true"] = process.argv[index].split("=", 2);
  args.set(key.replace(/^--/, ""), value);
}

const retentionDays = Math.max(1, Number(args.get("retention-days") || process.env.RETENTION_DAYS || 90));
const applyChanges = args.get("apply") === "true";
const batchSize = 500;
const eventCollections = ["accessHistory", "adminAuditLog", "securityEvents"];
const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

const { app, db } = createDatabaseClient("retention");
const preview = {};

async function collectExpired(collection) {
  const snapshot = await db.ref(collection)
    .orderByChild("timestamp")
    .endAt(cutoff)
    .limitToFirst(batchSize)
    .once("value");
  return Object.keys(snapshot.val() || {});
}

async function deleteExpired(collection) {
  let deleted = 0;
  while (true) {
    const keys = await collectExpired(collection);
    if (!keys.length) return deleted;
    const updates = Object.fromEntries(keys.map(key => [`${collection}/${key}`, null]));
    await db.ref().update(updates);
    deleted += keys.length;
    if (keys.length < batchSize) return deleted;
  }
}

try {
  const expiredNonces = await db.ref("dynamicQrNonces")
    .orderByChild("expiresAt")
    .endAt(Date.now())
    .limitToFirst(batchSize)
    .once("value");
  const nonceKeys = Object.keys(expiredNonces.val() || {});
  preview.dynamicQrNonces = nonceKeys.length;

  for (const collection of eventCollections) {
    preview[collection] = (await collectExpired(collection)).length;
  }

  if (applyChanges) {
    const nonceUpdates = Object.fromEntries(nonceKeys.map(key => [`dynamicQrNonces/${key}`, null]));
    if (Object.keys(nonceUpdates).length) await db.ref().update(nonceUpdates);
    for (const collection of eventCollections) {
      preview[collection] = await deleteExpired(collection);
    }
  }

  console.log(JSON.stringify({
    ok: true,
    mode: applyChanges ? "apply" : "preview",
    cutoff: new Date(cutoff).toISOString(),
    retentionDays,
    affected: preview
  }, null, 2));
} finally {
  await deleteApp(app);
}
