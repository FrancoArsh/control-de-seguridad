// backend/src/server.ts
import express, { Request, Response, NextFunction } from "express";
import admin from "firebase-admin";
import { getDatabase } from 'firebase-admin/database';
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import cors from "cors";
import * as QRCode from "qrcode";
import crypto from "crypto";
import jwt, { SignOptions, Secret } from "jsonwebtoken";
import bcrypt from "bcrypt";

dotenv.config();


console.log('DEBUG cwd:', process.cwd());
console.log('DEBUG __dirname:', __dirname);
console.log('DEBUG FIREBASE_DATABASE_URL:', process.env.FIREBASE_DATABASE_URL);
console.log('DEBUG serviceAccount path:', path.resolve(__dirname, '../serviceAccountKey.json'));


/* --------------------
   Verificaciones de env / secret
   -------------------- */
function ensureAdminSecretConfigured() {
  if (!process.env.ADMIN_SECRET) {
    console.error(
      "\n[ERROR] ADMIN_SECRET no está configurado en las variables de entorno.\n" +
      "Crea backend/.env con ADMIN_SECRET=tu_valor_secreto y reinicia el servidor.\n" +
      "Ejemplo: ADMIN_SECRET=mi_secreto_super_seguro\n"
    );
    process.exit(1);
  }
}

function ensureEnv() {
  if (!process.env.ADMIN_SECRET) {
    console.error("ADMIN_SECRET no configurado. Agrega en backend/.env");
    process.exit(1);
  }
  if (!process.env.JWT_SECRET) {
    console.error("JWT_SECRET no configurado. Agrega en backend/.env");
    process.exit(1);
  }
}

// Ejecutar comprobaciones iniciales
ensureAdminSecretConfigured();
ensureEnv();

const ADMIN_SECRET = process.env.ADMIN_SECRET!;
const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_EXP = process.env.JWT_EXP || "6h";

/* --------------------
   Inicialización Firebase
   -------------------- */
const SERVICE_ACCOUNT_PATH = process.env.GOOGLE_APPLICATION_CREDENTIALS || "./serviceAccountKey.json";
const FIREBASE_DB_URL = process.env.FIREBASE_DATABASE_URL || "https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/";

let serviceAccount: any = null;
try {
  serviceAccount = JSON.parse(fs.readFileSync(path.resolve(SERVICE_ACCOUNT_PATH), "utf8"));
} catch (e) {
  console.warn("serviceAccountKey.json no encontrado; si haces admin ops localmente, colócalo en backend/.");
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

/* --------------------
   Middlewares
   -------------------- */
function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const header = (req.headers["x-admin-secret"] || "") as string;
  if (!header || String(header).trim() !== String(ADMIN_SECRET).trim()) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  return next();
}

function requireGuard(req: Request, res: Response, next: NextFunction) {
  const auth = (req.headers["authorization"] || "") as string;
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ ok: false, error: "no token" });
  const token = m[1];
  try {
    const decoded: any = jwt.verify(token, JWT_SECRET);
    (req as any).guard = { id: decoded.guardId, name: decoded.name };
    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: "invalid token" });
  }
}

/* --------------------
   Helpers (usar después de init db)
   -------------------- */
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
    return await QRCode.toDataURL(JSON.stringify({ id, token }), { margin: 1, scale: 8 });
  } catch (e) {
    console.warn("QR gen failed for", id, e);
    return null;
  }
}

async function logAccess(params: {
  id?: string;
  studentUid?: string;
  name?: string;
  token?: string;
  authorized: boolean;
  reason?: string;
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
    const pushRef = db.ref(`accessHistory`).push();
    await pushRef.set(entry);
    return entry;
  } catch (err) {
    console.error("logAccess error:", err);
    return null;
  }
}

/* --------------------
   Endpoints: Validate / Verify / History / User
   -------------------- */

// POST /validate
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
    let tokenNodeSnap = await db.ref('accessTokens').orderByChild('token').equalTo(tokenId).once('value');
    let foundKey: string | null = null;
    let tokenData: any = null;

    if (tokenNodeSnap.exists()) {
      const val = tokenNodeSnap.val();
      const keys = Object.keys(val);
      foundKey = keys[0];
      tokenData = val[foundKey];
    } else {
      const altSnap = await db.ref('tokens').orderByChild('token').equalTo(tokenId).once('value');
      if (altSnap.exists()) {
        const v = altSnap.val();
        const keys2 = Object.keys(v);
        foundKey = keys2[0];
        tokenData = v[foundKey];
      }
    }

    if (!foundKey || !tokenData) {
      await logAccess({ token: tokenId, authorized: false, reason: "token not found", sessionId });
      return res.status(404).json({ ok: false, error: "token not found" });
    }

    if (tokenData.used) {
      await logAccess({ id: foundKey, studentUid: foundKey, token: tokenId, authorized: false, reason: "token already used", sessionId });
      return res.status(400).json({ ok: false, error: "token already used" });
    }
    if (tokenData.expiresAt && now > Number(tokenData.expiresAt)) {
      await logAccess({ id: foundKey, studentUid: foundKey, token: tokenId, authorized: false, reason: "token expired", sessionId });
      return res.status(400).json({ ok: false, error: "token expired" });
    }

    // Registrar attendance
    try {
      const attendanceRef = db.ref(`attendance/${sessionId}/${foundKey}`).push();
      await attendanceRef.set({ type, timestamp: now, tokenId });
    } catch (e) {
      console.warn("No se pudo registrar attendance:", e);
    }

    // Log accessHistory
    let name = null;
    try {
      const studentSnap = await db.ref(`students/${foundKey}`).once("value");
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

// POST /verify
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

    if (dbToken === token) {
      let name = null;
      try {
        const sSnap = await db.ref(`students/${id}`).once("value");
        if (sSnap.exists()) name = sSnap.val().name || null;
      } catch (e) { /* ignore */ }

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

// GET /history
app.get("/history", async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 500);
    const snap = await db.ref('accessHistory').orderByChild('timestamp').limitToLast(limit).once('value');
    const val = snap.val() || {};
    const arr = Object.keys(val).map(k => ({ key: k, ...val[k] }))
                   .sort((a,b) => b.timestamp - a.timestamp);
    return res.json({ ok: true, count: arr.length, data: arr });
  } catch (err) {
    console.error("GET /history error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

// GET /user/:id
app.get("/user/:id", async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ ok: false, error: "missing id" });

    let name: string | null = null;
    let role: string | null = null;
    try {
      const sSnap = await db.ref(`students/${id}`).once("value");
      if (sSnap.exists()) {
        const sVal = sSnap.val();
        name = sVal.name || null;
        role = sVal.role || null;
      }
    } catch (e) {
      console.warn("user/:id -> error reading students:", e);
    }

    let token: string | null = null;
    try {
      const tSnap = await db.ref(`accessTokens/${id}`).once("value");
      if (tSnap.exists()) {
        token = String(tSnap.val().token || "");
      } else {
        const alt = await db.ref(`tokens/${id}`).once("value");
        if (alt.exists()) token = String(alt.val().token || "");
      }
    } catch (e) {
      console.warn("user/:id -> error reading tokens:", e);
    }

    let qrDataUrl: string | null = null;
    if (token) {
      try {
        qrDataUrl = await QRCode.toDataURL(JSON.stringify({ id, token }), { margin: 1, scale: 8 });
      } catch (e) {
        console.warn("user/:id -> error generating QR:", e);
      }
    }

    return res.json({ ok: true, id, name, role, token: token ? token : null, qrDataUrl });
  } catch (err) {
    console.error("GET /user/:id error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

/* --------------------
   Admin Users endpoints (students)
   -------------------- */

// GET /users
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
      return { id, name: s.name || null, role: s.role || null, token };
    }));

    const filtered = qRole ? users.filter(u => (u.role || "").toLowerCase() === qRole) : users;
    return res.json({ ok:true, count: filtered.length, data: filtered });
  } catch (err) {
    console.error("GET /users error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// POST /users
app.post("/users", requireAdmin, async (req, res) => {
  try {
    let { id, name, role, token, regenerate } = req.body || {};

    name = typeof name === "string" ? name.trim() : "";
    role = typeof role === "string" ? role.trim().toLowerCase() : "";
    const allowedRoles = ["estudiante", "docente", "admin"];
    if (!role || !allowedRoles.includes(role)) role = "estudiante";
    if (!name) return res.status(400).json({ ok: false, error: "name required" });

    if (!id || String(id).trim() === "") {
      const now = new Date();
      const y = now.getFullYear();
      const m = String(now.getMonth()+1).padStart(2,'0');
      const d = String(now.getDate()).padStart(2,'0');
      const rand = crypto.randomBytes(4).toString('hex').slice(0,6);
      id = `est-${y}${m}${d}-${rand}`;
    }
    id = String(id);

    await db.ref(`students/${id}`).update({ name, role });

    const tokenSnap = await db.ref(`accessTokens/${id}`).once("value");
    if (regenerate === true || !tokenSnap.exists()) {
      token = crypto.randomBytes(12).toString("hex");
      await db.ref(`accessTokens/${id}`).set({ token, createdAt: Date.now() });
    } else {
      token = String(tokenSnap.val().token || "");
    }

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

// PUT /users/:id
app.put("/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });

    const { name, role, regenerate } = req.body || {};
    const allowedRoles = ["estudiante", "docente", "admin"];
    const updates: any = {};
    if (typeof name === "string" && name.trim() !== "") updates.name = name.trim();
    if (typeof role === "string" && allowedRoles.includes(role.trim().toLowerCase())) updates.role = role.trim().toLowerCase();

    if (Object.keys(updates).length === 0 && !regenerate) {
      return res.status(400).json({ ok:false, error:"nothing to update" });
    }

    if (Object.keys(updates).length) {
      await db.ref(`students/${id}`).update(updates);
    }

    let token = null;
    if (regenerate === true) {
      token = crypto.randomBytes(12).toString("hex");
      await db.ref(`accessTokens/${id}`).set({ token, createdAt: Date.now() });
    } else {
      const tSnap = await db.ref(`accessTokens/${id}`).once("value");
      if (tSnap.exists()) token = String(tSnap.val().token || null);
    }

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

// DELETE /users/:id
app.delete("/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });

    await db.ref(`students/${id}`).remove();
    await db.ref(`accessTokens/${id}`).remove();

    return res.json({ ok: true, id, message: "deleted" });
  } catch (err) {
    console.error("DELETE /users/:id error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

/* --------------------
   Guardias / Shifts / Authorizations
   - guard.login -> requireGuard (JWT)
   - guard/shift/start, guard/shift/end, guard/authorize
   -------------------- */

// guard/login
// --- GUARD AUTH / LOGIN ---
// --- GUARD AUTH / LOGIN (mejorado, reemplaza tu versión actual) ---
app.post("/guard/login", async (req, res) => {
  try {
    let { id, pin } = req.body || {};
    if (!id || (pin === undefined || pin === null)) return res.status(400).json({ ok: false, error: "id & pin required" });

    // Normalizar pin como string y trim
    const pinStr = String(pin).trim();

    console.log('LOGIN ATTEMPT -> id:', id, 'pin_len:', pinStr.length);

    const snap = await db.ref(`guards/${id}`).once("value");
    console.log('LOGIN DEBUG - snap.exists:', snap.exists());

    if (!snap.exists()) {
      console.log('LOGIN DEBUG -> guard not found for id:', id);
      return res.status(404).json({ ok: false, error: "guard not found" });
    }

    const guard = snap.val();
    const storedHash = guard.pinHash || guard.pin || null;
    console.log('LOGIN DEBUG - guard record name:', guard.name || null);
    console.log('LOGIN DEBUG - pinHash exists:', !!storedHash, 'prefix:', storedHash ? String(storedHash).slice(0,6) : null, 'len:', storedHash ? String(storedHash).length : 0);

    if (!storedHash) {
      console.log('LOGIN DEBUG -> no pinHash stored for guard:', id);
      return res.status(500).json({ ok:false, error: 'no pin configured for guard' });
    }

    // Comparar (bcrypt) — pinStr es el plaintext
    const match = await bcrypt.compare(pinStr, String(storedHash));
    console.log('LOGIN DEBUG - bcrypt.compare result:', match);

    if (!match) {
      return res.status(401).json({ ok: false, error: "invalid pin" });
    }

    // Si correcto -> firmar JWT
    const payload = { guardId: id, name: guard.name, role: "guard" };
    const rawExp = process.env.JWT_EXP || "6h";
    const maybeNum = Number(rawExp);
    const jwtExpVal = Number.isFinite(maybeNum) ? maybeNum : String(rawExp);
 
    const opts: SignOptions = {
  // TypeScript a veces no reconoce las uniones personalizadas; casteamos solo aquí (seguro en runtime)
    expiresIn: jwtExpVal as unknown as SignOptions["expiresIn"]
};
    const secret: Secret = (process.env.JWT_SECRET || "dev_fallback_secret") as Secret;
    const token = jwt.sign(payload as any, secret, opts);


    return res.json({ ok: true, token, guardId: id, name: guard.name });
  } catch (err) {
    console.error('guard/login error:', err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});




// POST /guard/shift/start  (requireGuard)
app.post("/guard/shift/start", requireGuard, async (req, res) => {
  try {
    const guardId = (req as any).guard.id;
    const { notes, createdByAdminId, force } = req.body || {};

    // comprobar si ya hay un shift activo para este guard (evitar duplicados)
    const snap = await db.ref("guardShifts").orderByChild("guardId").equalTo(guardId).once("value");
    const val = snap.val() || {};
    const open = Object.keys(val)
      .map(k => ({ id: k, ...(val[k] || {}) }))
      .filter(s => !s.endTimestamp && s.active !== false); // mayor tolerancia

    if (open.length && !force) {
      // devolver el shift activo (evita abrir duplicados)
      return res.status(400).json({ ok:false, error:"already active", shift: open[0] });
    }

    const ref = db.ref("guardShifts").push();
    const shiftId = ref.key!;
    const now = Date.now();
    await ref.set({
      guardId,
      startTimestamp: now,
      active: true,
      createdByAdminId: createdByAdminId || null,
      notes: notes || null
    });
    return res.json({ ok:true, shiftId, startTimestamp: now });
  } catch (err) {
    console.error("guard/shift/start error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});


// POST /guard/shift/end  (requireGuard) - mejorado
app.post("/guard/shift/end", requireGuard, async (req, res) => {
  try {
    const guardId = (req as any).guard.id;
    const { shiftId, notes } = req.body || {};

    if (shiftId) {
      const sSnap = await db.ref(`guardShifts/${shiftId}`).once("value");
      if (!sSnap.exists()) return res.status(404).json({ ok:false, error:"shift not found" });
      const shift = sSnap.val();
      if (String(shift.guardId) !== String(guardId)) return res.status(403).json({ ok:false, error:"not owner of shift" });
      if (shift.endTimestamp) return res.status(400).json({ ok:false, error:"shift already ended" });

      const endTs = Date.now();
      await db.ref(`guardShifts/${shiftId}`).update({ endTimestamp: endTs, active: false, notes: notes || shift.notes || null });
      return res.json({ ok:true, shiftId, endTimestamp: endTs });
    }

    // buscar shift activo más reciente para este guard
    const snap = await db.ref("guardShifts").orderByChild("guardId").equalTo(guardId).once("value");
    const val = snap.val() || {};
    const openShifts = Object.keys(val)
      .map(k => ({ id: k, ...(val[k] || {}) }))
      .filter(s => !s.endTimestamp && s.active !== false)
      .sort((a:any,b:any)=> (b.startTimestamp||0) - (a.startTimestamp||0));

    if (!openShifts.length) return res.status(404).json({ ok:false, error:"no active shift found for guard" });

    const target = openShifts[0];
    const endTs = Date.now();
    await db.ref(`guardShifts/${target.id}`).update({ endTimestamp: endTs, active: false, notes: notes || target.notes || null });

    return res.json({ ok:true, shiftId: target.id, endTimestamp: endTs, message:"closed latest active shift" });
  } catch (err) {
    console.error("guard/shift/end (improved) error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// guard/authorize (requireGuard)
app.post("/guard/authorize", requireGuard, async (req, res) => {
  try {
    const guardId = (req as any).guard.id;
    const { studentId, token, sessionId = "default", note, shiftId } = req.body || {};
    if (!studentId && !token) return res.status(400).json({ ok: false, error: "studentId or token required" });

    const now = Date.now();
    const authRef = db.ref("guardAuthorizations").push();
    const authId = authRef.key!;
    await authRef.set({
      guardId,
      shiftId: shiftId || null,
      studentId: studentId || null,
      token: token || null,
      authorized: true,
      reason: "manual_override",
      note: note || null,
      timestamp: now,
      sessionId
    });

    if (studentId) {
      await db.ref(`attendance/${sessionId}/${studentId}`).push({
        type: "manual_entry_by_guard",
        timestamp: now,
        guardId,
        authId,
        shiftId: shiftId || null
      });
    }

    await db.ref("accessHistory").push({
      id: studentId || null,
      token: token || null,
      authorized: true,
      reason: "manual_override",
      note: note || null,
      timestamp: now,
      guardOverrideId: authId,
      shiftId: shiftId || null
    });

    return res.json({ ok: true, authId, timestamp: now });
  } catch (err) {
    console.error("guard/authorize", err);
    return res.status(500).json({ ok: false, error: "server" });
  }
});

/* --------------------
   Admin read endpoints for shifts/authorizations/teachers/admins
   -------------------- */

// GET /guardShifts?active=true&guardId=xxx  (admin or public read)
app.get("/guardShifts", async (req, res) => {
  try {
    const guardIdQ = String(req.query.guardId || "").trim();
    const activeQ = String(req.query.active || "").toLowerCase(); // "true"|"false"|""
    const snap = await db.ref("guardShifts").once("value");
    const val = snap.val() || {};
    let arr = Object.keys(val).map(k => ({ id: k, ...(val[k] || {}) }));
    if (guardIdQ) arr = arr.filter(s => String(s.guardId) === guardIdQ);
    if (activeQ === "true") arr = arr.filter(s => !s.endTimestamp && s.active !== false);
    if (activeQ === "false") arr = arr.filter(s => s.endTimestamp || s.active === false);
    // ordenar desc por startTimestamp
    arr.sort((a:any,b:any)=> (b.startTimestamp||0) - (a.startTimestamp||0));
    return res.json({ ok:true, count: arr.length, data: arr });
  } catch (err) {
    console.error("GET guardShifts", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// GET /guardAuthorizations
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

// GET /guards  (requireAdmin)
app.get('/guards', requireAdmin, async (req, res) => {
  try {
    const snap = await db.ref('guards').once('value');
    const val = snap.val() || {};
    const out = Object.keys(val).map(k => ({ id: k, name: val[k].name || null }));
    return res.json({ ok:true, count: out.length, data: out });
  } catch (err) {
    console.error('/guards error:', err);
    return res.status(500).json({ ok:false, error: 'server error' });
  }
});


/* --------------------
   Teachers endpoints
   -------------------- */

// GET /teachers
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

// POST /teachers
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
    const token = await ensureTokenForId(id);
    const qrDataUrl = await genQrDataUrl(id, token);
    return res.json({ ok:true, id, name, token, qrDataUrl });
  } catch (err) {
    console.error("POST /teachers", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// PUT /teachers/:id
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
    await db.ref(`accessTokens/${id}`).remove();
    return res.json({ ok:true, id, message:"deleted" });
  } catch (err) {
    console.error("DELETE /teachers/:id", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

/* --------------------
   Admins endpoints
   -------------------- */

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

// POST /admins
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

// POST /admin/guard/shift/start  (requireAdmin)
app.post('/admin/guard/shift/start', requireAdmin, async (req, res) => {
  try {
    const { guardId, notes, force } = req.body || {};
    if (!guardId) return res.status(400).json({ ok:false, error: 'guardId required' });

    // comprobar si ya hay un shift activo para este guard
    const snap = await db.ref("guardShifts").orderByChild("guardId").equalTo(guardId).once("value");
    const val = snap.val() || {};
    const open = Object.keys(val)
      .map(k => ({ id: k, ...(val[k] || {}) }))
      .filter(s => !s.endTimestamp && s.active !== false);

    if (open.length && !force) {
      return res.status(400).json({ ok:false, error: 'already active', shift: open[0] });
    }

    const ref = db.ref("guardShifts").push();
    const shiftId = ref.key!;
    const now = Date.now();
    await ref.set({
      guardId,
      startTimestamp: now,
      active: true,
      createdByAdminId: 'admin-ui',
      notes: notes || null
    });
    return res.json({ ok:true, shiftId, startTimestamp: now });
  } catch (err) {
    console.error('/admin/guard/shift/start error:', err);
    return res.status(500).json({ ok:false, error: 'server error' });
  }
});

app.post('/admin/guard/shift/end', requireAdmin, async (req, res) => {
  try {
    const { guardId, shiftId, notes } = req.body || {};

    if (shiftId) {
      const sSnap = await db.ref(`guardShifts/${shiftId}`).once("value");
      if (!sSnap.exists()) return res.status(404).json({ ok:false, error: 'shift not found' });
      const shift = sSnap.val();
      if (shift.endTimestamp) return res.status(400).json({ ok:false, error: 'shift already ended' });
      const endTs = Date.now();
      await db.ref(`guardShifts/${shiftId}`).update({ endTimestamp: endTs, active: false, notes: notes || shift.notes || null });
      return res.json({ ok:true, shiftId, endTimestamp: endTs });
    }

    if (!guardId) return res.status(400).json({ ok:false, error: 'guardId or shiftId required' });

    const snap = await db.ref("guardShifts").orderByChild("guardId").equalTo(guardId).once("value");
    const val = snap.val() || {};
    const openShifts = Object.keys(val)
      .map(k => ({ id: k, ...(val[k] || {}) }))
      .filter(s => !s.endTimestamp && s.active !== false)
      .sort((a:any,b:any)=> (b.startTimestamp||0) - (a.startTimestamp||0));

    if (!openShifts.length) return res.status(404).json({ ok:false, error: 'no active shift found for guard' });

    const target = openShifts[0];
    const endTs = Date.now();
    await db.ref(`guardShifts/${target.id}`).update({ endTimestamp: endTs, active: false, notes: notes || target.notes || null });

    return res.json({ ok:true, shiftId: target.id, endTimestamp: endTs, message: 'closed latest active shift' });
  } catch (err) {
    console.error('/admin/guard/shift/end error:', err);
    return res.status(500).json({ ok:false, error: 'server error' });
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

/* --------------------
   Shift history by shiftId (admin)
   -------------------- */
app.get("/shift/:shiftId/history", requireAdmin, async (req, res) => {
  try {
    const shiftId = String(req.params.shiftId || "");
    if (!shiftId) return res.status(400).json({ ok: false, error: "missing shiftId" });
    const sSnap = await db.ref(`guardShifts/${shiftId}`).once("value");
    if (!sSnap.exists()) return res.status(404).json({ ok: false, error: "shift not found" });
    const shift = sSnap.val();
    const start = Number(shift.startTimestamp || 0);
    const end = Number(shift.endTimestamp || (Date.now() + 1000*60*60*24));
    const ahSnap = await db.ref("accessHistory").once("value");
    const ah = ahSnap.val() || {};
    const rows = Object.keys(ah)
      .map(k => ({ id: k, ...ah[k] }))
      .filter((r: any) => {
        if (r.shiftId) return r.shiftId === shiftId;
        return Number(r.timestamp || 0) >= start && Number(r.timestamp || 0) <= end;
      })
      .sort((a:any,b:any)=> (a.timestamp||0) - (b.timestamp||0));
    const enriched = await Promise.all(rows.map(async (r: any) => {
      if (r.id) {
        const s = await db.ref(`students/${r.id}`).once("value");
        r.studentName = s.exists() ? s.val().name : null;
      }
      return r;
    }));
    return res.json({ ok: true, count: enriched.length, data: enriched, shift });
  } catch (err) {
    console.error("GET shift history", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

app.post('/guards/create', async (req, res) => {
  try {
    const { id, name, pin } = req.body;
    if (!id || !name || !pin) return res.status(400).json({ ok: false, error: 'missing fields' });

    const hash = await bcrypt.hash(pin, 10);
    await db.ref(`guards/${id}`).set({
      name,
      pinHash: hash,
      createdAt: Date.now()
    });

    res.json({ ok: true, id, name });
  } catch (err) {
    console.error('Error creando guard:', err);
    res.status(500).json({ ok: false, error: 'server' });
  }
});

/* --------------------
   Inicio servidor
   -------------------- */
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
