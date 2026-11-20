import { deleteApp } from "firebase-admin/app";
import { createDatabaseClient } from "./firebase-runtime.mjs";

const args = new Map(process.argv.slice(2).map(item => { const [key, value = "true"] = item.split("=", 2); return [key.replace(/^--/, ""), value]; }));
const id = String(args.get("id") || "").trim();
const confirm = args.get("confirm") === "true";
if (!id || /[.#$\[\]/]/.test(id)) throw new Error("Debe indicar --id valido.");
const visitor = /^manual-[a-f0-9]{64}$/.test(id);
if (visitor && confirm && args.get("writers-stopped") !== "true") {
  throw new Error("Detenga API, recuperación y demás escritores antes de aplicar; confirme con --writers-stopped=true.");
}
if (!visitor && !confirm) { console.log(JSON.stringify({ ok: true, mode: "preview", id, message: "No se modifico la base. Use --confirm=true despues de aprobar la solicitud." }, null, 2)); process.exit(0); }

const { app, db } = createDatabaseClient("personal-data-delete");
try {
  if (visitor) {
    const report = await eraseVisitor(app, db, id, confirm);
    console.log(JSON.stringify(report, null, 2));
  } else {
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
  }
} finally { await deleteApp(app); }

async function eraseVisitor(app, db, id, apply) {
  // Attendance is partitioned by session. A history record may already have expired.
  const url = new URL(app.options.databaseURL);
  const emulator = process.env.FIREBASE_DATABASE_EMULATOR_HOST;
  let token;
  if (emulator) {
    if (url.host !== emulator || !/^(127\.0\.0\.1|localhost):\d+$/.test(emulator)) {
      throw new Error("El inventario del emulador requiere una URL local coincidente.");
    }
    token = "owner";
  } else {
    if (url.protocol !== "https:" || !/\.(firebaseio\.com|firebasedatabase\.app)$/.test(url.hostname)) {
      throw new Error("URL de Firebase no válida para el inventario.");
    }
    token = (await app.options.credential.getAccessToken()).access_token;
  }
  url.pathname = "/attendance.json";
  url.searchParams.set("shallow", "true");
  const sessions = await fetch(url, { headers: { Authorization: "Bearer " + token }, redirect: "error" });
  if (!sessions.ok) throw new Error("No se pudo inventariar la asistencia: HTTP " + sessions.status);

  const updates = {};
  const counts = { accessHistory: 0, adminAuditLog: 0, attendanceSessions: 0, accessState: 0 };
  for (const [collection, field] of [["accessHistory", "id"], ["adminAuditLog", "entityId"]]) {
    const records = await db.ref(collection).orderByChild(field).equalTo(id).get();
    records.forEach(record => {
      updates[collection + "/" + record.key] = null;
      counts[collection]++;
    });
  }
  for (const session of Object.keys(await sessions.json() || {})) {
    const ref = db.ref("attendance").child(session).child(id);
    if ((await ref.limitToFirst(1).get()).exists()) {
      updates["attendance/" + session + "/" + id] = null;
      counts.attendanceSessions++;
    }
  }
  if ((await db.ref("accessState").child(id).get()).exists()) {
    updates["accessState/" + id] = null;
    counts.accessState++;
  }
  if (apply && Object.keys(updates).length) {
    const key = db.ref("adminAuditLog").push().key;
    updates["adminAuditLog/" + key] = { action: "visitor_data.delete", timestamp: Date.now(), counts };
    await db.ref().update(updates);
  }
  return { ok: true, mode: apply ? "apply" : "preview", scope: "live-visitor-records", counts };
}
