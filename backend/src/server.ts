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

// Añade estas importaciones si no están
import { Request, Response, NextFunction } from "express";

// --- Middleware ADMIN_SECRET ---
/**
 * Requiere que el header `x-admin-secret` coincida con process.env.ADMIN_SECRET.
 * Si ADMIN_SECRET no está definido, detenemos el servidor para evitar exposición.
 */
function ensureAdminSecretConfigured() {
  if (!process.env.ADMIN_SECRET) {
    console.error(
      "\n[ERROR] ADMIN_SECRET no está configurado en las variables de entorno.\n" +
      "Crea backend/.env con ADMIN_SECRET=tu_valor_secreto y reinicia el servidor.\n" +
      "Ejemplo: ADMIN_SECRET=mi_secreto_super_seguro\n"
    );
    // Terminamos la ejecución para forzar que lo configures
    process.exit(1);
  }
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  // Si no existe ADMIN_SECRET abortamos (esto normalmente no ocurrirá porque forzamos en startup)
  const secret = process.env.ADMIN_SECRET;
  if (!secret) return res.status(500).json({ ok: false, error: "ADMIN_SECRET not configured on server" });

  // Revisar header (aceptamos mayúsculas/minúsculas)
  const header = (req.headers["x-admin-secret"] || req.headers["x-admin-token"] || "") as string;

  if (String(header).trim() !== String(secret).trim()) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  return next();
}

// Llamar a esta función durante startup para verificar que ADMIN_SECRET existe
ensureAdminSecretConfigured();


async function ensureTokenForId(id: string) {
  const tRef = db.ref(`accessTokens/${id}`);
  const tSnap = await tRef.once("value");
  if (tSnap.exists() && tSnap.val().token) {
    return String(tSnap.val().token);
  }
  const newToken = crypto.randomBytes(12).toString("hex");
  await tRef.set({ token: newToken, createdAt: Date.now() });
  return newToken;
}

async function genQrDataUrl(id: string, token: string | null) {
  if (!token) return null;
  try {
    return await QRCode.toDataURL(JSON.stringify({ id, token }), { margin:1, scale:8 });
  } catch (e) {
    console.warn("QR gen failed for", id, e);
    return null;
  }
}

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

// Modificar GET /users para aceptar ?role=estudiante|docente|admin (si no, devuelve todos)
// GET /users?role=...
app.get("/users", async (req, res) => {
  try {
    const qRole = String(req.query.role || "").trim().toLowerCase();
    const studentsSnap = await db.ref("students").once("value");
    const studentsVal = studentsSnap.val() || {};
    const ids = Object.keys(studentsVal);

    const users = await Promise.all(ids.map(async (id) => {
      const s = studentsVal[id] || {};
      let token = null;
      try {
        const tSnap = await db.ref(`accessTokens/${id}`).once("value");
        if (tSnap.exists()) token = String(tSnap.val().token || null);
      } catch (e) { /* ignore */ }
      return {
        id,
        name: s.name || null,
        role: s.role || null,
        token
      };
    }));

    const filtered = qRole ? users.filter(u => (u.role || "").toLowerCase() === qRole) : users;
    return res.json({ ok:true, count: filtered.length, data: filtered });
  } catch (err) {
    console.error("GET /users error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});


// POST /users -> crear o actualizar usuario (upsert seguro)
app.post("/users", requireAdmin, async (req, res) => {
  try {
    let { id, name, role, token, regenerate } = req.body || {};

    // Normalizar y validar
    name = typeof name === "string" ? name.trim() : "";
    role = typeof role === "string" ? role.trim().toLowerCase() : "";

    // Validar role aceptado; si viene vacío, obligamos a 'estudiante'
    const allowedRoles = ["estudiante", "docente", "admin"];
    if (!role || !allowedRoles.includes(role)) role = "estudiante";

    // Si no hay name, no permitimos crear un usuario vacío
    if (!name) {
      return res.status(400).json({ ok: false, error: "name required" });
    }

    // Generar id si no viene
    if (!id || String(id).trim() === "") {
      const now = new Date();
      const y = now.getFullYear();
      const m = String(now.getMonth()+1).padStart(2,'0');
      const d = String(now.getDate()).padStart(2,'0');
      const rand = crypto.randomBytes(4).toString('hex').slice(0,6);
      id = `est-${y}${m}${d}-${rand}`;
    }
    id = String(id);

    // Upsert: usar update() para mezclar (no borrar otros campos accidentales)
    await db.ref(`students/${id}`).update({
      name,
      role
    });

    // Token: si piden regenerar o no existe, generarlo
    const tokenSnap = await db.ref(`accessTokens/${id}`).once("value");
    if (regenerate === true || !tokenSnap.exists()) {
      token = crypto.randomBytes(12).toString("hex");
      await db.ref(`accessTokens/${id}`).set({ token, createdAt: Date.now() });
    } else {
      token = String(tokenSnap.val().token || "");
    }

    // Generar QR data URL
    let qrDataUrl: string | null = null;
    try {
      qrDataUrl = await QRCode.toDataURL(JSON.stringify({ id, token }), { margin:1, scale:8 });
    } catch (e) {
      console.warn("QR gen failed:", e);
    }

    return res.json({ ok: true, id, name, role, token, qrDataUrl });
  } catch (err) {
    console.error("POST /users error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});


// PUT /users/:id -> actualizar nombre/role y opcionalmente regenerar token
// PUT /users/:id -> actualizar (merge) y opcionalmente regenerar token
app.put("/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });

    const { name, role, regenerate } = req.body || {};

    // Validar role (si viene)
    const allowedRoles = ["estudiante", "docente", "admin"];
    const updates: any = {};
    if (typeof name === "string" && name.trim() !== "") updates.name = name.trim();
    if (typeof role === "string" && allowedRoles.includes(role.trim().toLowerCase())) updates.role = role.trim().toLowerCase();

    // Si no hay campos válidos y no pide regenerar token, no hacer nada
    if (Object.keys(updates).length === 0 && !regenerate) {
      return res.status(400).json({ ok:false, error:"nothing to update" });
    }

    // Aplicar cambios (merge)
    if (Object.keys(updates).length) {
      await db.ref(`students/${id}`).update(updates);
    }

    // Regenerar token si solicitó
    let token = null;
    if (regenerate === true) {
      token = crypto.randomBytes(12).toString("hex");
      await db.ref(`accessTokens/${id}`).set({ token, createdAt: Date.now() });
    } else {
      const tSnap = await db.ref(`accessTokens/${id}`).once("value");
      if (tSnap.exists()) token = String(tSnap.val().token || null);
    }

    // Obtener datos actuales para respuesta
    const sSnap = await db.ref(`students/${id}`).once("value");
    const student = sSnap.exists() ? sSnap.val() : {};

    let qrDataUrl: string | null = null;
    if (token) {
      try {
        qrDataUrl = await QRCode.toDataURL(JSON.stringify({ id, token }), { margin:1, scale:8 });
      } catch (e) { /* ignore */ }
    }

    return res.json({ ok:true, id, name: student.name || null, role: student.role || null, token, qrDataUrl });
  } catch (err) {
    console.error("PUT /users/:id error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});


// DELETE /users/:id -> eliminar student y token (cuidado: irreversible)
app.delete("/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });

    // Opcional: respaldar antes de borrar (puedes implementarlo si quieres)
    // Eliminamos student y token, NOTA: también podrías querer borrar attendance o accessHistory relacionadas
    await db.ref(`students/${id}`).remove();
    await db.ref(`accessTokens/${id}`).remove();

    return res.json({ ok: true, id, message: "deleted" });
  } catch (err) {
    console.error("DELETE /users/:id error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// POST /guard/shift/start { guardId, createdByAdminId, notes? }
app.post("/guard/shift/start", requireAdmin, async (req, res) => {
  try {
    const { guardId, createdByAdminId, notes } = req.body || {};
    if (!guardId) return res.status(400).json({ ok:false, error:"guardId required" });

    const shiftRef = db.ref("guardShifts").push();
    const shiftId = shiftRef.key!;
    const now = Date.now();
    await shiftRef.set({
      guardId,
      startTimestamp: now,
      createdByAdminId: createdByAdminId || null,
      notes: notes || null
    });
    return res.json({ ok:true, shiftId, startTimestamp: now });
  } catch (err) {
    console.error("guard/shift/start", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// POST /guard/shift/end { shiftId, guardId, notes? }
app.post("/guard/shift/end", requireAdmin, async (req, res) => {
  try {
    const { shiftId, guardId, notes } = req.body || {};
    if (!shiftId) return res.status(400).json({ ok:false, error:"shiftId required" });

    const endTs = Date.now();
    await db.ref(`guardShifts/${shiftId}`).update({
      endTimestamp: endTs,
      notes: notes || null
    });
    return res.json({ ok:true, shiftId, endTimestamp: endTs });
  } catch (err) {
    console.error("guard/shift/end", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// POST /guard/authorize { guardId, studentId?, token?, sessionId?, note? }
app.post("/guard/authorize", requireAdmin, async (req, res) => {
  try {
    const { guardId, studentId, token, sessionId = "default", note } = req.body || {};
    if (!guardId) return res.status(400).json({ ok:false, error:"guardId required" });
    if (!studentId && !token) return res.status(400).json({ ok:false, error:"studentId or token required" });

    const now = Date.now();
    // crear registro de autorización manual
    const authRef = db.ref("guardAuthorizations").push();
    const authId = authRef.key!;
    await authRef.set({
      guardId,
      studentId: studentId || null,
      token: token || null,
      authorized: true,
      reason: "manual_override",
      note: note || null,
      timestamp: now,
      sessionId
    });

    // si tenemos studentId, registrar asistencia
    if (studentId) {
      await db.ref(`attendance/${sessionId}/${studentId}`).push({
        type: "manual_entry_by_guard",
        timestamp: now,
        guardId,
        authId
      });
    }

    // registrar en accessHistory para tracking
    await db.ref("accessHistory").push({
      id: studentId || null,
      token: token || null,
      authorized: true,
      reason: "manual_override",
      timestamp: now,
      guardOverrideId: authId
    });

    // opcional: enviar comando al totem/deviceCommands si quieres
    // if student has deviceId, we can push deviceCommands...

    return res.json({ ok:true, authId, timestamp: now });
  } catch (err) {
    console.error("guard/authorize", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

app.get("/guardShifts", async (req, res) => {
  try {
    const guardId = String(req.query.guardId || "").trim();
    const snap = await db.ref("guardShifts").once("value");
    const val = snap.val() || {};
    const arr = Object.keys(val).map(k => ({ id: k, ...val[k] }));
    const filtered = guardId ? arr.filter(s => s.guardId === guardId) : arr;
    return res.json({ ok:true, count: filtered.length, data: filtered });
  } catch (err) {
    console.error("GET guardShifts", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// guardAuthorizations list
app.get("/guardAuthorizations", async (req, res) => {
  try {
    const guardId = String(req.query.guardId || "").trim();
    const snap = await db.ref("guardAuthorizations").once("value");
    const val = snap.val() || {};
    const arr = Object.keys(val).map(k => ({ id: k, ...val[k] }));
    const filtered = guardId ? arr.filter(a => a.guardId === guardId) : arr;
    return res.json({ ok:true, count: filtered.length, data: filtered });
  } catch (err) {
    console.error("GET guardAuthorizations", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// GET /teachers -> lista todos los docentes
app.get("/teachers", requireAdmin, async (req, res) => {
  try {
    const snap = await db.ref("teachers").once("value");
    const val = snap.val() || {};
    const ids = Object.keys(val);
    const out = await Promise.all(ids.map(async id => {
      const token = await (async () => {
        const tSnap = await db.ref(`accessTokens/${id}`).once("value");
        return tSnap.exists() ? String(tSnap.val().token || null) : null;
      })();
      const qrDataUrl = token ? await genQrDataUrl(id, token) : null;
      return { id, name: val[id].name || null, createdAt: val[id].createdAt || null, token, qrDataUrl };
    }));
    return res.json({ ok:true, count: out.length, data: out });
  } catch (err) {
    console.error("GET /teachers", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// POST /teachers -> crear/upsert teacher { id?, name }
app.post("/teachers", requireAdmin, async (req, res) => {
  try {
    let { id, name } = req.body || {};
    if (!name || String(name).trim()==="") return res.status(400).json({ ok:false, error:"name required" });
    name = String(name).trim();

    if (!id || String(id).trim()==="") {
      const now = Date.now();
      const rand = crypto.randomBytes(3).toString('hex');
      id = `teacher-${now.toString().slice(-6)}-${rand}`;
    }
    id = String(id);

    await db.ref(`teachers/${id}`).update({ name, role:"docente", createdAt: Date.now() });

    // ensure token exists and QR
    const token = await ensureTokenForId(id);
    const qrDataUrl = await genQrDataUrl(id, token);

    return res.json({ ok:true, id, name, token, qrDataUrl });
  } catch (err) {
    console.error("POST /teachers", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// PUT /teachers/:id -> actualizar nombre
app.put("/teachers/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const { name } = req.body || {};
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });
    if (!name) return res.status(400).json({ ok:false, error:"name required" });
    await db.ref(`teachers/${id}`).update({ name });
    const tSnap = await db.ref(`accessTokens/${id}`).once("value");
    const token = tSnap.exists() ? String(tSnap.val().token || null) : null;
    const qrDataUrl = token ? await genQrDataUrl(id, token) : null;
    return res.json({ ok:true, id, name, token, qrDataUrl });
  } catch (err) {
    console.error("PUT /teachers/:id", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// DELETE /teachers/:id
app.delete("/teachers/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });
    await db.ref(`teachers/${id}`).remove();
    // opcional: borrar token relacionado si quieres
    await db.ref(`accessTokens/${id}`).remove();
    return res.json({ ok:true, id, message:"deleted" });
  } catch (err) {
    console.error("DELETE /teachers/:id", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

/* ---------------- ADMINS ---------------- */
// GET /admins
app.get("/admins", requireAdmin, async (req, res) => {
  try {
    const snap = await db.ref("admins").once("value");
    const val = snap.val() || {};
    const ids = Object.keys(val);
    const out = await Promise.all(ids.map(async id => {
      const tSnap = await db.ref(`accessTokens/${id}`).once("value");
      const token = tSnap.exists() ? String(tSnap.val().token || null) : null;
      const qrDataUrl = token ? await genQrDataUrl(id, token) : null;
      return { id, name: val[id].name || null, createdAt: val[id].createdAt || null, token, qrDataUrl };
    }));
    return res.json({ ok:true, count: out.length, data: out });
  } catch (err) {
    console.error("GET /admins", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// POST /admins { id?, name }
app.post("/admins", requireAdmin, async (req, res) => {
  try {
    let { id, name } = req.body || {};
    if (!name || String(name).trim()==="") return res.status(400).json({ ok:false, error:"name required" });
    name = String(name).trim();
    if (!id || String(id).trim()==="") {
      const now = Date.now();
      const rand = crypto.randomBytes(3).toString('hex');
      id = `admin-${now.toString().slice(-6)}-${rand}`;
    }
    id = String(id);
    await db.ref(`admins/${id}`).update({ name, role:"admin", createdAt: Date.now() });
    const token = await ensureTokenForId(id);
    const qrDataUrl = await genQrDataUrl(id, token);
    return res.json({ ok:true, id, name, token, qrDataUrl });
  } catch (err) {
    console.error("POST /admins", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// PUT /admins/:id
app.put("/admins/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const { name } = req.body || {};
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });
    if (!name) return res.status(400).json({ ok:false, error:"name required" });
    await db.ref(`admins/${id}`).update({ name });
    const tSnap = await db.ref(`accessTokens/${id}`).once("value");
    const token = tSnap.exists() ? String(tSnap.val().token || null) : null;
    const qrDataUrl = token ? await genQrDataUrl(id, token) : null;
    return res.json({ ok:true, id, name, token, qrDataUrl });
  } catch (err) {
    console.error("PUT /admins/:id", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// DELETE /admins/:id
app.delete("/admins/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });
    await db.ref(`admins/${id}`).remove();
    await db.ref(`accessTokens/${id}`).remove();
    return res.json({ ok:true, id, message:"deleted" });
  } catch (err) {
    console.error("DELETE /admins/:id", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});


// --- Inicio del servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
