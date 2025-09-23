import express from "express";
import cors from "cors";
import admin from "firebase-admin";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const SERVICE_ACCOUNT_PATH =
  process.env.GOOGLE_APPLICATION_CREDENTIALS || "./serviceAccountKey.json";
const FIREBASE_DB_URL =
  process.env.FIREBASE_DATABASE_URL ||
  "https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/";

let serviceAccount;
try {
  serviceAccount = JSON.parse(fs.readFileSync(path.resolve(SERVICE_ACCOUNT_PATH), "utf8"));
} catch (err) {
  console.warn("Aviso: serviceAccountKey.json no se encontró o es inválido. Asegúrate de colocarlo en backend/ antes de ejecutar en modo producción.");
  serviceAccount = null as any;
}

if (serviceAccount) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: FIREBASE_DB_URL,
  });
} else {
  try {
    admin.initializeApp({ databaseURL: FIREBASE_DB_URL });
  } catch (e) {
    console.warn("Inicialización parcial de Firebase falló: ", e);
  }
}

const db = admin.database ? admin.database() : null;

const app = express();
app.use(cors());
app.use(express.json());

app.get("/ping", (_req, res) => res.json({ ok: true, now: Date.now() }));

app.post("/validate", async (req, res) => {
  const { token, sessionId = "default", type = "entry" } = req.body;
  if (!token) return res.status(400).json({ ok: false, error: "token required" });

  if (!db) return res.status(500).json({ ok: false, error: "database not initialized" });

  try {
    const tokenRef = db.ref(`tokens/${token}`);
    const tokenSnap = await tokenRef.once("value");
    if (!tokenSnap.exists())
      return res.status(404).json({ ok: false, error: "token not found" });

    const tokenData = tokenSnap.val();
    const now = Date.now();

    if (tokenData.used)
      return res.status(400).json({ ok: false, error: "token already used" });
    if (tokenData.expiresAt && now > tokenData.expiresAt)
      return res.status(400).json({ ok: false, error: "token expired" });

    await tokenRef.update({ used: true, usedAt: now });

    const attendanceRef = db
      .ref(`attendance/${sessionId}/${tokenData.studentUid}`)
      .push();

    await attendanceRef.set({
      type,
      timestamp: now,
      tokenId: token,
    });

    return res.json({ ok: true, studentUid: tokenData.studentUid });
  } catch (err) {
    console.error("validate error", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
