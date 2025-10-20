// parte relevante de server.ts (TypeScript)
import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

dotenv.config();

// inicialización admin (mantén tu lógica actual)
const SERVICE_ACCOUNT_PATH = process.env.GOOGLE_APPLICATION_CREDENTIALS || "./serviceAccountKey.json";
const FIREBASE_DB_URL = process.env.FIREBASE_DATABASE_URL || "https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/";

let serviceAccount: any = null;
try {
  serviceAccount = JSON.parse(fs.readFileSync(path.resolve(SERVICE_ACCOUNT_PATH), "utf8"));
} catch (e) {
  console.warn("serviceAccountKey.json no encontrado; asegúrate localmente para pruebas que requieran admin.");
}

if (serviceAccount) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: FIREBASE_DB_URL,
  });
} else {
  admin.initializeApp({ databaseURL: FIREBASE_DB_URL });
}

const db = admin.database();
const app = express();
app.use(express.json());

// POST /validate
app.post("/validate", async (req, res) => {
  const tokenId = String(req.body?.token || "").trim();
  const sessionId = String(req.body?.sessionId || "default");
  const type = String(req.body?.type || "entry");

  if (!tokenId) return res.status(400).json({ ok: false, error: "token required" });

  const tokenRef = db.ref(`tokens/${tokenId}`);
  const now = Date.now();

  try {
    // Ejecutar transacción atómica sobre el nodo del token
    const txResult = await tokenRef.transaction((currentData: any) => {
      // Si no existe token -> abortar (return undefined)
      if (currentData === null) return;
      // Si ya usado -> abortar
      if (currentData.used) return;
      // Si expiró -> abortar
      if (currentData.expiresAt && now > Number(currentData.expiresAt)) return;
      // Marcar como usado
      currentData.used = true;
      currentData.usedAt = now;
      return currentData;
    });

    // txResult: { committed: boolean, snapshot: DataSnapshot }
    if (!txResult.committed) {
      // Determinar motivo por inspección de snapshot (si existe)
      const snap = txResult.snapshot;
      if (!snap || !snap.exists()) {
        return res.status(404).json({ ok: false, error: "token not found" });
      }
      const final = snap.val();
      if (final.used) return res.status(400).json({ ok: false, error: "token already used" });
      if (final.expiresAt && now > Number(final.expiresAt))
        return res.status(400).json({ ok: false, error: "token expired" });
      // Fallback
      return res.status(400).json({ ok: false, error: "token validation failed" });
    }

    // Si llegamos aquí, transacción committed -> token marcado como usado
    const tokenData = txResult.snapshot!.val();

    // Registrar asistencia (push bajo attendance)
    const attendanceRef = db.ref(`attendance/${sessionId}/${tokenData.studentUid}`).push();
    await attendanceRef.set({
      type,
      timestamp: now,
      tokenId,
    });

    // Escribir comando para device (opcional)
    if (tokenData.deviceId) {
      const cmdRef = db.ref(`deviceCommands/${tokenData.deviceId}`).push();
      await cmdRef.set({ color: "green", tokenId, timestamp: now });
    }

    return res.json({ ok: true, studentUid: tokenData.studentUid });
  } catch (err) {
    console.error("validate error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});
// --- Nuevo endpoint /verify ---
// Este endpoint comprueba si el estudiante con cierto ID y token tiene acceso autorizado
app.post("/verify", async (req, res) => {
  try {
    const { id, token } = req.body;

    if (!id || !token) {
      return res.status(400).json({ authorized: false, message: "Faltan datos: id o token" });
    }

    const studentRef = db.ref(`tokens/${id}`);
    const snapshot = await studentRef.once("value");
    const tokenData = snapshot.val();

    if (!tokenData) {
      return res.status(404).json({ authorized: false, message: "ID no encontrado" });
    }

    // Verificar token y expiración
    if (tokenData.token === token && tokenData.expiresAt > Date.now()) {
      return res.json({ authorized: true, message: "Acceso autorizado" });
    } else {
      return res.json({ authorized: false, message: "Token inválido o expirado" });
    }

  } catch (error) {
    console.error("Error en /verify:", error);
    return res.status(500).json({ authorized: false, message: "Error interno del servidor" });
  }
});

// --- Inicio del servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
