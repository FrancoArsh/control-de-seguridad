export async function eraseVisitor(app, root, id, apply) {
  if (!/^manual-[a-f0-9]{64}$/.test(id)) throw new Error("Identificador de visita inválido.");
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
  url.pathname = new URL(root.child("attendance").toString()).pathname + ".json";
  url.searchParams.set("shallow", "true");
  const sessions = await fetch(url, { headers: { Authorization: "Bearer " + token }, redirect: "error" });
  if (!sessions.ok) throw new Error("No se pudo inventariar la asistencia: HTTP " + sessions.status);

  const updates = {};
  const counts = { accessHistory: 0, adminAuditLog: 0, attendanceSessions: 0, accessState: 0 };
  for (const [collection, field] of [["accessHistory", "id"], ["adminAuditLog", "entityId"]]) {
    const records = await root.child(collection).orderByChild(field).equalTo(id).get();
    records.forEach(record => {
      updates[collection + "/" + record.key] = null;
      counts[collection]++;
    });
  }
  for (const session of Object.keys(await sessions.json() || {})) {
    const ref = root.child("attendance").child(session).child(id);
    if ((await ref.limitToFirst(1).get()).exists()) {
      updates["attendance/" + session + "/" + id] = null;
      counts.attendanceSessions++;
    }
  }
  if ((await root.child("accessState").child(id).get()).exists()) {
    updates["accessState/" + id] = null;
    counts.accessState++;
  }
  if (apply && Object.keys(updates).length) {
    const key = root.child("adminAuditLog").push().key;
    updates["adminAuditLog/" + key] = { action: "visitor_data.delete", timestamp: Date.now(), counts };
    await root.update(updates);
  }
  return { ok: true, mode: apply ? "apply" : "preview", scope: "live-visitor-records", counts };
}
