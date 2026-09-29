import { deleteApp } from "firebase-admin/app";
import { createDatabaseClient } from "./firebase-runtime.mjs";

const args = new Map(process.argv.slice(2).map(item => { const [key, value = "true"] = item.split("=", 2); return [key.replace(/^--/, ""), value]; }));
const id = String(args.get("id") || "").trim();
const confirm = args.get("confirm") === "true";
if (!id || /[.#$\[\]/]/.test(id)) throw new Error("Debe indicar --id valido.");
if (!confirm) { console.log(JSON.stringify({ ok: true, mode: "preview", id, message: "No se modifico la base. Use --confirm=true despues de aprobar la solicitud." }, null, 2)); process.exit(0); }

const { app, db } = createDatabaseClient("personal-data-delete");
try {
  const updates = {};
  for (const collection of ["students", "guards", "admins"]) updates[`${collection}/${id}`] = null;
  updates[`portalProfiles/${id}`] = null;
  updates[`accessState/${id}`] = null;
  updates[`accessTokens/${id}`] = null;
  updates[`attendance/${id}`] = null;
  await db.ref().update(updates);
  const auditKey = db.ref("adminAuditLog").push().key;
  await db.ref(`adminAuditLog/${auditKey}`).set({ action: "personal_data.delete", entityId: id, timestamp: Date.now(), reason: "approved deletion request" });
  console.log(JSON.stringify({ ok: true, mode: "apply", id, deletedPaths: Object.keys(updates).length, authIdentity: "must be deleted separately with Firebase Admin Auth" }, null, 2));
} finally { await deleteApp(app); }
