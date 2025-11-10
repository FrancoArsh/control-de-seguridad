// parte relevante de server.ts (TypeScript)
import express from "express";
import admin from "firebase-admin";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import cors from "cors";
import * as QRCode from "qrcode";
import crypto from "crypto";


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
app.use(cors());

// ----------------------
// Función para registrar accesos
// ----------------------
async function logAccess(params: {
  id?: string;             // est-001
  studentUid?: string;     // mismo que id, por compatibilidad
  name?: string;           // nombre si está disponible
  token?: string;          // token usado
  authorized: boolean;     // true/false
  reason?: string;         // texto explicativo
  sessionId?: string;
}) {
  try {
    const now = Date.now();
    const entry = {
      id: params.id || params.studentUid || null,
      studentUid: params.studentUid || params.id || null,
      name: params.name || null,
      token: params.token || null,
      authorized: !!params.authorized,
      reason: params.reason || null,
      sessionId: params.sessionId || null,
      timestamp: now
    };
    // push bajo accessHistory
    const pushRef = db.ref(`accessHistory`).push();
    await pushRef.set(entry);
    // opcional: también mantener un index/últimos n si necesitas lecturas rápidas
    return entry;
  } catch (err) {
    console.error("logAccess error:", err);
    return null;
  }
}


// POST /validate  (búsqueda por valor + logging)
// Nota: usa orderByChild(...).equalTo(tokenId) para encontrar el studentUid cuando el token está guardado como valor.
app.post("/validate", async (req, res) => {
  const tokenId = String(req.body?.token || "").trim();
  const sessionId = String(req.body?.sessionId || "default");
  const type = String(req.body?.type || "entry");
  const now = Date.now();

  if (!tokenId) {
    await logAccess({ token: tokenId, authorized: false, reason: "token required", sessionId });
    return res.status(400).json({ ok: false, error: "token required" });
  }

  try {
    // 1) Intentar encontrar el token dentro de accessTokens (estructura: accessTokens/{studentId}.token)
    let tokenNodeSnap = await db.ref('accessTokens').orderByChild('token').equalTo(tokenId).once('value');
    let foundKey: string | null = null;
    let tokenData: any = null;

    if (tokenNodeSnap.exists()) {
      const val = tokenNodeSnap.val();
      const keys = Object.keys(val);
      foundKey = keys[0];           // studentId (ej: est-001)
      tokenData = val[foundKey];    // { token: "...", ... }
    } else {
      // 2) si no está en accessTokens, intentar en tokens/ (si existe ese nodo con otra estructura)
      const altSnap = await db.ref('tokens').orderByChild('token').equalTo(tokenId).once('value');
      if (altSnap.exists()) {
        const v = altSnap.val();
        const keys2 = Object.keys(v);
        foundKey = keys2[0];        // puede ser studentId u otra key
        tokenData = v[foundKey];
      }
    }

    if (!foundKey || !tokenData) {
      // no existe token en la DB (por valor)
      await logAccess({ token: tokenId, authorized: false, reason: "token not found", sessionId });
      return res.status(404).json({ ok: false, error: "token not found" });
    }

    // Al encontrar tokenData y foundKey: si tu flujo requiere marcar token como "usado" mediante transacción
    // (esto aplica si tokens estaban indexados por token y querías que se vuelvan 'used').
    // Aquí asumimos tokens permanentes; si quieres soportar "usar una sola vez" activa la sección de transaction:

    // Si tokenData tiene campo `used` o `expiresAt` y quieres respetarlo, manejarlo:
    if (tokenData.used) {
      await logAccess({ id: foundKey, studentUid: foundKey, token: tokenId, authorized: false, reason: "token already used", sessionId });
      return res.status(400).json({ ok: false, error: "token already used" });
    }
    if (tokenData.expiresAt && now > Number(tokenData.expiresAt)) {
      await logAccess({ id: foundKey, studentUid: foundKey, token: tokenId, authorized: false, reason: "token expired", sessionId });
      return res.status(400).json({ ok: false, error: "token expired" });
    }

    // Marcar used si es necesario (opcional — solo si quieres invalidar tokens de una sola vez)
    // Ejemplo (descomenta si quieres que token se marque como usado):
    /*
    const tokenRefByStudent = db.ref(`accessTokens/${foundKey}`);
    await tokenRefByStudent.update({ used: true, usedAt: now });
    */

    // Registrar attendance (si tu estructura lo necesita)
    try {
      const attendanceRef = db.ref(`attendance/${sessionId}/${foundKey}`).push();
      await attendanceRef.set({ type, timestamp: now, tokenId });
    } catch (e) {
      console.warn("No se pudo registrar attendance:", e);
    }

    // Log en accessHistory
    let name = null;
    try {
      const studentSnap = await db.ref(`students/${foundKey}`).once('value');
      if (studentSnap.exists()) name = studentSnap.val().name || null;
    } catch (e) { /* ignore */ }

    await logAccess({
      id: foundKey,
      studentUid: foundKey,
      name,
      token: tokenId,
      authorized: true,
      reason: "ok",
      sessionId
    });

    return res.json({ ok: true, studentUid: foundKey });

  } catch (err) {
    console.error("validate error:", err);
    await logAccess({ token: tokenId, authorized: false, reason: "server error", sessionId });
    return res.status(500).json({ ok: false, error: "server error" });
  }
});



// --- Endpoint /verify (simplificado y con logging) ---
app.post("/verify", async (req, res) => {
  try {
    const { id, token } = req.body;

    if (!id || !token) {
      await logAccess({ id, token, authorized: false, reason: "missing data" });
      return res.status(400).json({ authorized: false, message: "Faltan datos: id o token" });
    }

    const studentRef = db.ref(`accessTokens/${id}`);
    const snapshot = await studentRef.once("value");

    if (!snapshot.exists()) {
      await logAccess({ id, token, authorized: false, reason: "ID no encontrado" });
      return res.status(404).json({ authorized: false, message: "ID no encontrado" });
    }

    const tokenData = snapshot.val();
    const dbToken = String(tokenData.token || "");
    const now = Date.now();

    // Comprobar token permanentes (sin expiración)
    if (dbToken === token) {
      // obtener nombre si existe
      let name = null;
      try {
        const sSnap = await db.ref(`students/${id}`).once("value");
        if (sSnap.exists()) name = sSnap.val().name || null;
      } catch (e) { /* ignora */ }

      await logAccess({ id, studentUid: id, name, token, authorized: true, reason: "ok" });
      console.log(`✅ Acceso autorizado para ${id}`);
      return res.json({ authorized: true, message: "Acceso autorizado" });
    } else {
      await logAccess({ id, token, authorized: false, reason: "token incorrecto" });
      console.log(`❌ Token incorrecto para ${id}`);
      return res.json({ authorized: false, message: "Token incorrecto" });
    }

  } catch (error) {
    console.error("Error en /verify:", error);
    await logAccess({ id: req.body?.id, token: req.body?.token, authorized: false, reason: "server error" });
    return res.status(500).json({ authorized: false, message: "Error interno del servidor" });
  }
});


// GET /history?limit=50  -> devuelve los últimos registros (orden descendente)
app.get("/history", async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 500); // tope 500
    const snap = await db.ref('accessHistory').orderByChild('timestamp').limitToLast(limit).once('value');
    const val = snap.val() || {};
    // convertir a array ordenado desc
    const arr = Object.keys(val).map(k => ({ key: k, ...val[k] }))
                   .sort((a,b) => b.timestamp - a.timestamp);
    return res.json({ ok: true, count: arr.length, data: arr });
  } catch (err) {
    console.error("GET /history error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

// GET /user/:id -> devuelve info pública del usuario + qrDataUrl
app.get("/user/:id", async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ ok: false, error: "missing id" });

    // Intentar leer datos desde students/{id}
    let name: string | null = null;
    let role: string | null = null;
    try {
      const sSnap = await db.ref(`students/${id}`).once("value");
      if (sSnap.exists()) {
        const sVal = sSnap.val();
        name = sVal.name || null;
        role = sVal.role || null; // si guardas role en students
      }
    } catch (e) {
      console.warn("user/:id -> error reading students:", e);
    }

    // Intentar leer token desde accessTokens/{id}
    let token: string | null = null;
    try {
      const tSnap = await db.ref(`accessTokens/${id}`).once("value");
      if (tSnap.exists()) {
        const tVal = tSnap.val();
        token = String(tVal.token || "");
      } else {
        // fallback: tokens/{id}
        const alt = await db.ref(`tokens/${id}`).once("value");
        if (alt.exists()) {
          token = String(alt.val().token || "");
        }
      }
    } catch (e) {
      console.warn("user/:id -> error reading tokens:", e);
    }

    // Construir payload QR: un JSON con id y token (si no hay token, devolverá null)
    const qrPayload = token ? JSON.stringify({ id, token }) : null;

    // Generar Data URL del QR (si hay payload)
    let qrDataUrl: string | null = null;
    if (qrPayload) {
      try {
        qrDataUrl = await QRCode.toDataURL(qrPayload, { margin: 1, scale: 8 });
      } catch (e) {
        console.warn("user/:id -> error generating QR:", e);
      }
    }

    return res.json({
      ok: true,
      id,
      name,
      role,
      token: token ? token : null,
      qrDataUrl
    });
  } catch (err) {
    console.error("GET /user/:id error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

// ---------------------------
// Admin endpoints: GET /users  and POST /users
// - GET /users -> lista todos los usuarios con token (si existe)
// - POST /users -> crea o actualiza user. body: { id?, name, role, token?, regenerate? }
//    if regenerate==true -> crea un token nuevo y actualiza accessTokens/{id}
//    returns object with qrDataUrl
// ---------------------------

app.get("/users", async (req, res) => {
  try {
    const studentsSnap = await db.ref("students").once("value");
    const studentsVal = studentsSnap.val() || {};

    // Convertir a array y leer tokens en paralelo
    const ids = Object.keys(studentsVal);
    const users = await Promise.all(ids.map(async (id) => {
      let token = null;
      try {
        const tSnap = await db.ref(`accessTokens/${id}`).once("value");
        if (tSnap.exists()) token = String(tSnap.val().token || null);
      } catch (e) { /* ignore */ }
      return {
        id,
        name: studentsVal[id].name || null,
        role: studentsVal[id].role || null,
        token
      };
    }));

    return res.json({ ok: true, count: users.length, data: users });
  } catch (err) {
    console.error("GET /users error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

app.post("/users", async (req, res) => {
  try {
    let { id, name, role, token, regenerate } = req.body || {};

    // Generar id si no viene
    if (!id || String(id).trim() === "") {
      // id formato est-XXX
      id = `est-${Math.floor(Math.random() * 900 + 100)}`;
    }
    id = String(id);

    // Guardar/actualizar datos del estudiante
    await db.ref(`students/${id}`).update({
      name: name || null,
      role: role || null
    });

    // Leer token existente si no se pasó token
    if (!token) {
      const existingSnap = await db.ref(`accessTokens/${id}`).once("value");
      if (existingSnap.exists()) token = String(existingSnap.val().token || null);
    }

    // Regenerar token si piden o si no hay token
    if (regenerate === true || !token) {
      token = crypto.randomBytes(12).toString("hex");
    }

    // Escribir token en accessTokens/{id}
    await db.ref(`accessTokens/${id}`).set({
      token,
      createdAt: Date.now()
    });

    // Generar QR data URL con payload {id, token}
    let qrDataUrl: string | null = null;
    try {
      const payload = JSON.stringify({ id, token });
      qrDataUrl = await QRCode.toDataURL(payload, { margin: 1, scale: 8 });
    } catch (e) {
      console.warn("POST /users -> QR generation failed:", e);
    }

    return res.json({
      ok: true,
      id,
      name: name || null,
      role: role || null,
      token,
      qrDataUrl
    });

  } catch (err) {
    console.error("POST /users error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});


// --- Inicio del servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
