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

const svcEnv = process.env.SERVICE_ACCOUNT_JSON || process.env.SERVICE_ACCOUNT_JSON_BASE64 || null;

if (svcEnv) {
  try {
    const outPath = path.resolve(__dirname, '../serviceAccountKey.json');
    // Si enviaron base64 (opcional), detectarlo:
    let content = svcEnv;
    // si parece base64 (opcional), decodificar
    if (/^[A-Za-z0-9+/=\\s]+$/.test(svcEnv) && svcEnv.length > 200 && !svcEnv.trim().startsWith('{')) {
      // intenta decodificar base64
      try {
        content = Buffer.from(svcEnv, 'base64').toString('utf8');
      } catch (e) {
        // no era base64, usan JSON directo
      }
    }
    // Escribe el archivo (sobrescribe si ya existe)
    fs.writeFileSync(outPath, typeof content === 'string' ? content : JSON.stringify(content), { encoding: 'utf8', flag: 'w' });
    console.log('[INIT] Service account file written to', outPath);
  } catch (e) {
    console.error('[INIT] Could not write service account from env:', e);
  }
}
// --- END ---

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
      "Ejemplo: ADMIN_SECRET=usa_un_valor_largo_aleatorio\n"
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
  if (process.env.NODE_ENV === "production" && !process.env.QR_SECRET) {
    console.error("QR_SECRET es obligatorio en producción y debe ser distinto de JWT_SECRET.");
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
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    // En Railway pegaremos el contenido del JSON en esta variable
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    console.log("✅ [NUBE] Cargando credenciales desde variable de entorno.");
  } catch (e) {
    console.error("❌ Error leyendo la variable FIREBASE_SERVICE_ACCOUNT", e);
  }
} 
// 2. Si no hay variable, buscamos el archivo (Tu PC Local)
else {
  const localPath = path.resolve(__dirname, "../serviceAccountKey.json");
  if (fs.existsSync(localPath)) {
    try {
      serviceAccount = JSON.parse(fs.readFileSync(localPath, "utf8"));
      console.log("✅ [LOCAL] Cargando credenciales desde archivo local.");
    } catch (e) {
      console.warn("⚠️ Error leyendo archivo local", e);
    }
  }
}

// 3. Iniciamos Firebase
if (serviceAccount) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: FIREBASE_DB_URL,
  });
} else {
  console.warn("⚠️ ADVERTENCIA: Iniciando SIN credenciales Admin. Algunas funciones fallarán.");
  admin.initializeApp({ databaseURL: FIREBASE_DB_URL });
}

const db = admin.database();
const app = express();
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";
const DEFAULT_ALLOWED_ORIGINS = ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"];
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(express.json({ limit: "256kb" }));
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=()");
  next();
});
app.use(cors({
  origin(origin, callback) {
    if (!origin || !IS_PRODUCTION || DEFAULT_ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("CORS origin not allowed"));
  }
}));

/* --------------------
   Middlewares
   -------------------- */

function requireGuard(req: Request, res: Response, next: NextFunction) {
  const auth = (req.headers["authorization"] || "") as string;
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ ok: false, error: "no token" });
  const token = m[1];
  try {
    const decoded: any = jwt.verify(token, JWT_SECRET);
    if (!decoded?.guardId) return res.status(401).json({ ok: false, error: "invalid token" });
    (req as any).guard = { id: decoded.guardId, name: decoded.name };
    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: "invalid token" });
  }
}

/* --------------------
   Helpers (usar después de init db)
   -------------------- */

async function requireFirebaseAdmin(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = (req.headers['authorization'] || '') as string;
    const m = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ ok:false, error: 'no token' });
    const idToken = m[1];
    // verifica token con Firebase Admin SDK
    const decoded = await admin.auth().verifyIdToken(idToken);
    const uid = decoded.uid;
    // verifica que el uid sea admin en la RTDB
    const snap = await db.ref(`admins/${uid}`).once('value');
    if (!snap.exists()) return res.status(403).json({ ok:false, error: 'not admin' });
    const profile = snap.val();
    if (profile.role !== 'admin') return res.status(403).json({ ok:false, error:'not admin role' });

    // adjunta info útil
    (req as any).admin = { uid, name: profile.name || null, email: profile.email || null };
    return next();
  } catch (err: any) {
    console.error('requireFirebaseAdmin error:', err);
    const code = err?.errorInfo?.code || '';
    if (code === 'auth/id-token-expired') {
      return res.status(401).json({ ok:false, error: 'id-token-expired' });
    }
    return res.status(401).json({ ok:false, error: 'invalid token' });
  }
}

async function requireAdminOrGuard(req: Request, res: Response, next: NextFunction) {
  const authHeader = (req.headers["authorization"] || "") as string;
  const m = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ ok: false, error: "no token" });

  const token = m[1];
  try {
    const decoded: any = jwt.verify(token, JWT_SECRET);
    if (decoded?.guardId) {
      (req as any).guard = { id: decoded.guardId, name: decoded.name || null };
      return next();
    }
  } catch (_) {
    // Puede ser un token Firebase de administrador; se valida abajo.
  }

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    const uid = decoded.uid;
    const snap = await db.ref(`admins/${uid}`).once("value");
    if (!snap.exists()) return res.status(403).json({ ok: false, error: "not admin" });
    const profile = snap.val();
    if (profile.role !== "admin") return res.status(403).json({ ok: false, error: "not admin role" });
    (req as any).admin = { uid, name: profile.name || null, email: profile.email || null };
    return next();
  } catch (err: any) {
    const code = err?.errorInfo?.code || "";
    if (code === "auth/id-token-expired") {
      return res.status(401).json({ ok: false, error: "id-token-expired" });
    }
    return res.status(401).json({ ok: false, error: "invalid token" });
  }
}

function adminActor(req: Request) {
  const adminUser = (req as any).admin;
  if (adminUser?.uid) return adminUser.uid;
  return "system";
}

function safeCompareString(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}


// MIGRATE: invalida tempPinHash vencidos para que no puedan convertirse en credenciales permanentes.
async function migrateExpiredTempPins() {
  try {
    const now = Date.now();
    const snap = await db.ref('guards').once('value');
    // Tipado explícito para que TypeScript sepa que podemos indexar por id
    const guards: Record<string, any> = snap.val() || {};
    const updates: Record<string, any> = {};

    for (const id of Object.keys(guards)) {
      const g: any = guards[id] || {};
      if (g.tempPinHash && g.tempPinExpiresAt && Number(g.tempPinExpiresAt) <= now) {
        updates[`guards/${id}/tempPinHash`] = null;
        updates[`guards/${id}/tempPinCreatedAt`] = null;
        updates[`guards/${id}/tempPinExpiresAt`] = null;
        updates[`guards/${id}/tempPinInvalidatedAt`] = now;
        console.log(`migrateExpiredTempPins: guard ${id} -> expired temp pin invalidated`);
      }
    }

    if (Object.keys(updates).length) {
      await db.ref().update(updates);
    }
  } catch (e) {
    console.error('migrateExpiredTempPins error:', e);
  }
}


async function genDynamicQrDataUrl(token: string | null) {
  if (!token) return null;
  try {
    return await QRCode.toDataURL(token, { margin: 1, scale: 8 });
  } catch (e) {
    console.warn("Dynamic QR gen failed", e);
    return null;
  }
}

const QR_SECRET = process.env.QR_SECRET || JWT_SECRET;
if (!process.env.QR_SECRET) {
  console.warn("[SECURITY] QR_SECRET no está definido; se usará JWT_SECRET solo para desarrollo local.");
}
if (IS_PRODUCTION && QR_SECRET === JWT_SECRET) {
  console.error("[SECURITY] QR_SECRET debe ser independiente de JWT_SECRET en producción.");
  process.exit(1);
}
const configuredQrTtl = Number(process.env.QR_TTL_MS || 60 * 1000);
const QR_TTL_MS = Number.isFinite(configuredQrTtl) && configuredQrTtl >= 10_000 && configuredQrTtl <= 5 * 60 * 1000
  ? configuredQrTtl
  : 60 * 1000;

type AccessType = "entry" | "exit";
const ACCESS_COOLDOWN_MS = 15000;

type DynamicQrPayload = {
  v: 2;
  purpose: "access";
  sub: string;
  iat: number;
  exp: number;
  nonce: string;
};

function signQrPayload(payload: DynamicQrPayload) {
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = crypto.createHmac("sha256", QR_SECRET).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function createDynamicQrToken(id: string) {
  const now = Date.now();
  const payload: DynamicQrPayload = {
    v: 2,
    purpose: "access",
    sub: id,
    iat: now,
    exp: now + QR_TTL_MS,
    nonce: crypto.randomBytes(16).toString("hex")
  };
  return { payload, token: signQrPayload(payload) };
}

function verifyDynamicQrToken(token: string): { ok: true; payload: DynamicQrPayload } | { ok: false; reason: string } {
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, reason: "invalid qr format" };

  const [encoded, signature] = parts;
  const expectedSignature = crypto.createHmac("sha256", QR_SECRET).update(encoded).digest("base64url");
  if (!safeCompareString(signature, expectedSignature)) {
    return { ok: false, reason: "invalid qr signature" };
  }

  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as DynamicQrPayload;
    const issuedAt = Number(payload.iat);
    const expiresAt = Number(payload.exp);
    if (
      payload.v !== 2 ||
      payload.purpose !== "access" ||
      typeof payload.sub !== "string" ||
      payload.sub.length > 160 ||
      typeof payload.nonce !== "string" ||
      payload.nonce.length < 16 ||
      !Number.isFinite(issuedAt) ||
      !Number.isFinite(expiresAt) ||
      expiresAt <= issuedAt
    ) {
      return { ok: false, reason: "invalid qr payload" };
    }
    if (Date.now() > expiresAt) {
      return { ok: false, reason: "qr expired" };
    }
    return { ok: true, payload };
  } catch (_) {
    return { ok: false, reason: "invalid qr payload" };
  }
}

async function markDynamicQrNonceUsed(payload: DynamicQrPayload) {
  const nonceRef = db.ref(`dynamicQrNonces/${payload.nonce}`);
  const result = await nonceRef.transaction((current) => {
    if (current) return;
    return {
      userId: payload.sub,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
      usedAt: Date.now()
    };
  });
  return result.committed === true;
}

async function cleanupExpiredQrNonces() {
  try {
    const now = Date.now();
    const snap = await db.ref("dynamicQrNonces")
      .orderByChild("expiresAt")
      .endAt(now)
      .limitToFirst(500)
      .once("value");
    const expired = snap.val() || {};
    const updates: Record<string, null> = {};
    for (const nonce of Object.keys(expired)) {
      updates[`dynamicQrNonces/${nonce}`] = null;
    }
    if (Object.keys(updates).length) {
      await db.ref().update(updates);
      console.log(`[MAINTENANCE] Removed ${Object.keys(updates).length} expired QR nonces.`);
    }
  } catch (err) {
    console.error("cleanupExpiredQrNonces error:", err);
  }
}

const QR_NONCE_CLEANUP_INTERVAL_MS = Math.max(
  60_000,
  Number(process.env.QR_NONCE_CLEANUP_INTERVAL_MS || 5 * 60 * 1000)
);
const qrNonceCleanupTimer = setInterval(() => {
  void cleanupExpiredQrNonces();
}, QR_NONCE_CLEANUP_INTERVAL_MS);
qrNonceCleanupTimer.unref?.();
void cleanupExpiredQrNonces();

async function resolveStaticAccessToken(token: string) {
  let tokenNodeSnap = await db.ref('accessTokens').orderByChild('token').equalTo(token).once('value');
  let foundKey: string | null = null;
  let tokenData: any = null;

  if (tokenNodeSnap.exists()) {
    const val = tokenNodeSnap.val();
    const keys = Object.keys(val);
    foundKey = keys[0];
    tokenData = val[foundKey];
  } else {
    const altSnap = await db.ref('tokens').orderByChild('token').equalTo(token).once('value');
    if (altSnap.exists()) {
      const v = altSnap.val();
      const keys2 = Object.keys(v);
      foundKey = keys2[0];
      tokenData = v[foundKey];
    }
  }

  return { foundKey, tokenData };
}

async function commitAccessTransition(userId: string, requestedType: string, sessionId: string): Promise<{
  ok: true;
  accessType: AccessType;
  previousInside: boolean;
  newInside: boolean;
} | { ok: false; reason: string }> {
  const normalized = requestedType === "entry" || requestedType === "exit" ? requestedType : "auto";
  const stateRef = db.ref(`accessState/${userId}`);
  let rejectedReason: string | null = null;
  let acceptedTransition: { accessType: AccessType; previousInside: boolean; newInside: boolean } | null = null;
  const now = Date.now();

  const result = await stateRef.transaction((current: any) => {
    const state = current && typeof current === "object" ? current : {};
    const previousInside = state.inside === true;

    if (now - Number(state.lastTimestamp || 0) < ACCESS_COOLDOWN_MS) {
      rejectedReason = "cooldown active";
      return;
    }

    const accessType: AccessType = normalized === "auto" ? (previousInside ? "exit" : "entry") : normalized;
    if (accessType === "entry" && previousInside) {
      rejectedReason = "user already inside";
      return;
    }
    if (accessType === "exit" && !previousInside) {
      rejectedReason = "user already outside";
      return;
    }

    acceptedTransition = {
      accessType,
      previousInside,
      newInside: accessType === "entry"
    };
    return {
      ...state,
      inside: accessType === "entry",
      lastAccessType: accessType,
      lastTimestamp: now,
      sessionId
    };
  });

  const committedTransition: { accessType: AccessType; previousInside: boolean; newInside: boolean } | null = acceptedTransition as {
    accessType: AccessType;
    previousInside: boolean;
    newInside: boolean;
  } | null;
  if (!result.committed || committedTransition === null) {
    return { ok: false, reason: rejectedReason || "access state conflict" };
  }

  return {
    ok: true,
    accessType: committedTransition.accessType,
    previousInside: committedTransition.previousInside,
    newInside: committedTransition.newInside
  };
}

async function logAccess(params: {
  id?: string;
  studentUid?: string;
  name?: string;
  token?: string;
  authorized: boolean;
  reason?: string;
  sessionId?: string;
  accessType?: AccessType | null;
  previousInside?: boolean | null;
  newInside?: boolean | null;
  validationMode?: "static" | "dynamic" | "manual" | null;
  qrVersion?: number | null;
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
      accessType: params.accessType || null,
      previousInside: params.previousInside ?? null,
      newInside: params.newInside ?? null,
      validationMode: params.validationMode || null,
      qrVersion: params.qrVersion || null,
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

async function logAdminAction(req: Request, params: {
  action: string;
  entityType: string;
  entityId?: string | null;
  metadata?: Record<string, any>;
}) {
  try {
    const now = Date.now();
    await db.ref("adminAuditLog").push({
      actorId: adminActor(req),
      actorEmail: (req as any).admin?.email || null,
      action: params.action,
      entityType: params.entityType,
      entityId: params.entityId || null,
      metadata: params.metadata || {},
      timestamp: now,
      ip: req.ip || null,
      userAgent: req.headers["user-agent"] || null
    });
  } catch (err) {
    console.error("logAdminAction error:", err);
  }
}

function sanitizeLimit(raw: any, defaultValue = 200, maxValue = 1000) {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return defaultValue;
  return Math.min(Math.floor(parsed), maxValue);
}

async function logSecurityEvent(params: {
  type: string;
  subjectId?: string | null;
  outcome: "success" | "failure" | "blocked";
  reason?: string | null;
  ip?: string | null;
}) {
  try {
    await db.ref("securityEvents").push({
      type: params.type,
      subjectId: params.subjectId || null,
      outcome: params.outcome,
      reason: params.reason || null,
      ip: params.ip || null,
      timestamp: Date.now()
    });
  } catch (err) {
    console.error("logSecurityEvent error:", err);
  }
}

const guardLoginAttempts = new Map<string, { count: number; lockedUntil: number }>();
const GUARD_LOGIN_MAX_ATTEMPTS = Number(process.env.GUARD_LOGIN_MAX_ATTEMPTS || 5);
const GUARD_LOGIN_LOCK_MS = Number(process.env.GUARD_LOGIN_LOCK_MS || 5 * 60 * 1000);

function guardLoginKey(req: Request, guardId: string) {
  return `${guardId}:${req.ip || "unknown"}`;
}

function isGuardLoginLocked(req: Request, guardId: string) {
  const current = guardLoginAttempts.get(guardLoginKey(req, guardId));
  return !!current && current.lockedUntil > Date.now();
}

function recordGuardLoginFailure(req: Request, guardId: string) {
  const key = guardLoginKey(req, guardId);
  const current = guardLoginAttempts.get(key) || { count: 0, lockedUntil: 0 };
  const nextCount = current.lockedUntil > Date.now() ? current.count : current.count + 1;
  guardLoginAttempts.set(key, {
    count: nextCount,
    lockedUntil: nextCount >= GUARD_LOGIN_MAX_ATTEMPTS ? Date.now() + GUARD_LOGIN_LOCK_MS : current.lockedUntil
  });
}

function clearGuardLoginFailures(req: Request, guardId: string) {
  guardLoginAttempts.delete(guardLoginKey(req, guardId));
}

/* --------------------
   Endpoints: Validate / Verify / History / User
   -------------------- */

app.get("/health", (_req, res) => {
  return res.json({
    ok: true,
    service: "control-de-seguridad-api",
    status: "operational",
    timestamp: Date.now(),
    environment: NODE_ENV
  });
});

async function getCurrentPresence() {
  const [stateSnap, studentsSnap] = await Promise.all([
    db.ref("accessState").once("value"),
    db.ref("students").once("value")
  ]);
  const states = stateSnap.val() || {};
  const students = studentsSnap.val() || {};

  return Object.keys(states)
    .filter(id => states[id]?.inside === true)
    .map(id => ({
      id,
      name: students[id]?.name || "Usuario sin nombre",
      role: students[id]?.role || "sin rol",
      inside: true,
      lastAccessType: states[id]?.lastAccessType || "entry",
      lastTimestamp: Number(states[id]?.lastTimestamp || 0),
      sessionId: states[id]?.sessionId || "default"
    }))
    .sort((a, b) => b.lastTimestamp - a.lastTimestamp);
}

app.get("/presence", requireAdminOrGuard, async (req, res) => {
  try {
    const data = await getCurrentPresence();
    if ((req as any).admin) {
      await logAdminAction(req, {
        action: "presence.read",
        entityType: "access_state",
        metadata: { count: data.length }
      });
    }
    return res.json({ ok: true, generatedAt: Date.now(), count: data.length, data });
  } catch (err) {
    console.error("GET /presence error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

app.get("/admin/metrics", requireFirebaseAdmin, async (req, res) => {
  try {
    const now = Date.now();
    const dayStart = now - 24 * 60 * 60 * 1000;
    const weekStart = now - 7 * 24 * 60 * 60 * 1000;

    const [historySnap, shiftsSnap, usersSnap, guardsSnap, presence] = await Promise.all([
      db.ref("accessHistory").orderByChild("timestamp").startAt(weekStart).once("value"),
      db.ref("guardShifts").once("value"),
      db.ref("students").once("value"),
      db.ref("guards").once("value"),
      getCurrentPresence()
    ]);

    const historyVal = historySnap.val() || {};
    const rows = Object.keys(historyVal).map(k => ({ id: k, ...(historyVal[k] || {}) }));
    const last24 = rows.filter((r: any) => Number(r.timestamp || 0) >= dayStart);
    const authorized24 = last24.filter((r: any) => r.authorized === true);
    const rejected24 = last24.filter((r: any) => r.authorized === false);
    const manualOverrides24 = last24.filter((r: any) => r.reason === "manual_override");
    const shiftsVal = shiftsSnap.val() || {};
    const shifts = Object.keys(shiftsVal).map(k => ({ id: k, ...(shiftsVal[k] || {}) }));
    const activeShifts = shifts.filter((s: any) => !s.endTimestamp && s.active !== false);

    const usersVal = usersSnap.val() || {};
    const guardsVal = guardsSnap.val() || {};

    await logAdminAction(req, {
      action: "metrics.read",
      entityType: "operational_dashboard",
      metadata: { windowHours: 24 }
    });

    return res.json({
      ok: true,
      generatedAt: now,
      window: { last24HoursStart: dayStart, last7DaysStart: weekStart },
      kpis: {
        accessEvents24h: last24.length,
        authorizedAccesses24h: authorized24.length,
        rejectedAccesses24h: rejected24.length,
        rejectionRate24h: last24.length ? Number((rejected24.length / last24.length).toFixed(4)) : 0,
        manualOverrides24h: manualOverrides24.length,
        peopleCurrentlyInside: presence.length,
        activeGuardShifts: activeShifts.length,
        registeredUsers: Object.keys(usersVal).length,
        registeredGuards: Object.keys(guardsVal).length
      }
    });
  } catch (err) {
    console.error("GET /admin/metrics error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

app.get("/admin/audit-log", requireFirebaseAdmin, async (_req, res) => {
  try {
    const limit = sanitizeLimit(_req.query.limit, 100, 500);
    const snap = await db.ref("adminAuditLog").orderByChild("timestamp").limitToLast(limit).once("value");
    const val = snap.val() || {};
    const data = Object.keys(val)
      .map(k => ({ id: k, ...(val[k] || {}) }))
      .sort((a: any, b: any) => Number(b.timestamp || 0) - Number(a.timestamp || 0));

    return res.json({ ok: true, count: data.length, data });
  } catch (err) {
    console.error("GET /admin/audit-log error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

// POST /validate
app.post("/validate", async (req, res) => {
  const rawToken = String(req.body?.qr || req.body?.qrToken || req.body?.token || "").trim();
  const sessionId = String(req.body?.sessionId || "default").trim() || "default";
  const requestedType = String(req.body?.type || "auto").trim().toLowerCase();
  const now = Date.now();

  if (!rawToken) {
    await logAccess({ token: rawToken, authorized: false, reason: "token required", sessionId });
    return res.status(400).json({ ok: false, error: "token required" });
  }

  try {
    let foundKey: string | null = null;
    let tokenData: any = null;
    let validationMode: "static" | "dynamic" = "static";
    let qrVersion = 1;
    let dynamicPayload: DynamicQrPayload | null = null;

    const dynamicQr = verifyDynamicQrToken(rawToken);
    if (dynamicQr.ok) {
      foundKey = dynamicQr.payload.sub;
      dynamicPayload = dynamicQr.payload;
      validationMode = "dynamic";
      qrVersion = 2;
    } else if (rawToken.includes(".")) {
      await logAccess({
        token: rawToken,
        authorized: false,
        reason: dynamicQr.reason,
        sessionId,
        validationMode: "dynamic",
        qrVersion: 2
      });
      return res.status(400).json({ ok: false, error: dynamicQr.reason, reason: dynamicQr.reason });
    } else {
      const resolved = await resolveStaticAccessToken(rawToken);
      foundKey = resolved.foundKey;
      tokenData = resolved.tokenData;
    }

    if (!foundKey) {
      await logAccess({ token: rawToken, authorized: false, reason: "token not found", sessionId, validationMode, qrVersion });
      return res.status(404).json({ ok: false, error: "token not found", reason: "token not found" });
    }

    const studentSnap = await db.ref(`students/${foundKey}`).once("value");
    if (!studentSnap.exists()) {
      await logAccess({ id: foundKey, studentUid: foundKey, token: rawToken, authorized: false, reason: "user not found", sessionId, validationMode, qrVersion });
      return res.status(404).json({ ok: false, error: "user not found", reason: "user not found" });
    }

    const studentVal = studentSnap.val();
    const studentName = studentVal.name || null;
    const lastAccessTimestamp = Number(studentVal.lastAccessTimestamp || 0);

    if (now - lastAccessTimestamp < ACCESS_COOLDOWN_MS) {
      const remainingMs = ACCESS_COOLDOWN_MS - (now - lastAccessTimestamp);
      const remainingSec = Math.ceil(remainingMs / 1000);

      await logAccess({
        id: foundKey,
        studentUid: foundKey,
        name: studentName,
        token: rawToken,
        authorized: false,
        reason: "cooldown active",
        sessionId,
        validationMode,
        qrVersion
      });

      return res.status(403).json({
        ok: false,
        error: `Acceso denegado. Este QR fue usado recientemente. Espere ${remainingSec} segundos.`,
        reason: "COOLDOWN_ACTIVE"
      });
    }

    if (validationMode === "static") {
      if (tokenData?.used) {
        await logAccess({ id: foundKey, studentUid: foundKey, token: rawToken, authorized: false, reason: "token already used", sessionId, validationMode, qrVersion });
        return res.status(400).json({ ok: false, error: "token already used", reason: "token already used" });
      }
      if (tokenData?.expiresAt && now > Number(tokenData.expiresAt)) {
        await logAccess({ id: foundKey, studentUid: foundKey, token: rawToken, authorized: false, reason: "token expired", sessionId, validationMode, qrVersion });
        return res.status(400).json({ ok: false, error: "token expired", reason: "token expired" });
      }
    }

    const transition = await commitAccessTransition(foundKey, requestedType, sessionId);
    if (!transition.ok) {
      await logAccess({
        id: foundKey,
        studentUid: foundKey,
        name: studentName,
        token: rawToken,
        authorized: false,
        reason: transition.reason,
        sessionId,
        validationMode,
        qrVersion
      });
      if (transition.reason === "cooldown active") {
        return res.status(403).json({ ok: false, error: "Acceso denegado por cooldown operativo.", reason: "COOLDOWN_ACTIVE" });
      }
      return res.status(409).json({ ok: false, error: transition.reason, reason: transition.reason });
    }

    if (dynamicPayload) {
      const nonceAccepted = await markDynamicQrNonceUsed(dynamicPayload);
      if (!nonceAccepted) {
        await logAccess({
          id: foundKey,
          studentUid: foundKey,
          name: studentName,
          token: rawToken,
          authorized: false,
          reason: "qr already used",
          sessionId,
          validationMode,
          qrVersion
        });
        return res.status(409).json({ ok: false, error: "qr already used", reason: "qr already used" });
      }
    }

    await db.ref(`students/${foundKey}`).update({
      lastAccessTimestamp: now,
      lastAccessType: transition.accessType
    });
    try {
      const attendanceRef = db.ref(`attendance/${sessionId}/${foundKey}`).push();
      await attendanceRef.set({
        type: transition.accessType,
        timestamp: now,
        tokenId: validationMode === "static" ? rawToken : null,
        qrVersion,
        validationMode,
        previousInside: transition.previousInside,
        newInside: transition.newInside
      });
    } catch (e) {
      console.warn("No se pudo registrar attendance:", e);
    }

    await logAccess({
      id: foundKey,
      studentUid: foundKey,
      name: studentName,
      token: rawToken,
      authorized: true,
      reason: "ok",
      sessionId,
      accessType: transition.accessType,
      previousInside: transition.previousInside,
      newInside: transition.newInside,
      validationMode,
      qrVersion
    });

    return res.json({
      ok: true,
      studentUid: foundKey,
      name: studentName,
      accessType: transition.accessType,
      inside: transition.newInside,
      validationMode,
      qrVersion,
      message: transition.accessType === "entry" ? "Entrada registrada" : "Salida registrada"
    });

  } catch (err) {
    console.error("validate error:", err);
    await logAccess({ token: rawToken, authorized: false, reason: "server error", sessionId });
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

// POST /verify
app.post("/verify", async (_req, res) => {
  return res.status(410).json({
    ok: false,
    error: "legacy endpoint disabled",
    message: "Use /validate para aplicar cooldown, expiración, historial y controles actuales."
  });
});

// GET /history
// GET /history (mejorado) -> soporta ?limit=50 & ?guardId=... & ?shiftId=...
app.get("/history", requireFirebaseAdmin, async (req: Request, res: Response) => {
  try {
    const limit = sanitizeLimit(req.query.limit, 200, 1000);
    const guardIdQ = String(req.query.guardId || "").trim();
    const shiftIdQ = String(req.query.shiftId || "").trim();
    // Cargamos accessHistory (limitar lectura es posible si la DB crece)
    const ahSnap = await db.ref("accessHistory").orderByChild("timestamp").limitToLast(10000).once("value");
    const ahVal = ahSnap.val() || {};
    let rows = Object.keys(ahVal).map(k => ({ key: k, ...ahVal[k] as any }));

    // Si piden guardId -> buscar guardAuthorizations del guard y guardShifts para hacer match
    let gaIds: string[] = [];
    let guardShiftIds: string[] = [];
    if (guardIdQ) {
      const gaSnap = await db.ref("guardAuthorizations").orderByChild("guardId").equalTo(guardIdQ).once("value");
      const gaVal = gaSnap.val() || {};
      gaIds = Object.keys(gaVal);

      const gsSnap = await db.ref("guardShifts").orderByChild("guardId").equalTo(guardIdQ).once("value");
      const gsVal = gsSnap.val() || {};
      guardShiftIds = Object.keys(gsVal);

      rows = rows.filter((r: any) => {
        // si el registro contiene guardId directo
        if (String(r.guardId || "") === guardIdQ) return true;
        // si tiene guardOverrideId y ese id pertenece a guardAuthorizations
        if (r.guardOverrideId && gaIds.includes(r.guardOverrideId)) return true;
        // si tiene shiftId y ese shift pertenece al guard
        if (r.shiftId && guardShiftIds.includes(r.shiftId)) return true;
        return false;
      });
    }

    // Si piden shiftId -> filtrar por shiftId exacto (también funciona solo con shiftId)
    if (shiftIdQ) {
      rows = rows.filter((r: any) => String(r.shiftId || "") === shiftIdQ);
    }

    // Ordenar desc por timestamp y limitar
    rows = rows.sort((a: any, b: any) => (b.timestamp || 0) - (a.timestamp || 0)).slice(0, limit);

    // Enriquecer registros (studentName, guard info, shift info) — opcional pero útil
    const enriched = await Promise.all(rows.map(async (r: any) => {
      // studentName
      if (r.id) {
        try {
          const s = await db.ref(`students/${r.id}`).once("value");
          if (s.exists()) r.studentName = s.val().name || null;
        } catch (_) { /* ignore */ }
      }
      // guardOverrideId -> agregar guardId/guardName
      if (r.guardOverrideId) {
        try {
          const ga = await db.ref(`guardAuthorizations/${r.guardOverrideId}`).once("value");
          if (ga.exists()) {
            const gav = ga.val();
            r.guardId = gav.guardId || r.guardId || null;
            const gSnap = await db.ref(`guards/${gav.guardId}`).once("value");
            if (gSnap.exists()) r.guardName = gSnap.val().name || null;
          }
        } catch (_) { /* ignore */ }
      }
      // shift info si existe shiftId
      if (r.shiftId) {
        try {
          const sSnap = await db.ref(`guardShifts/${r.shiftId}`).once("value");
          if (sSnap.exists()) r.shift = sSnap.val();
        } catch (_) { /* ignore */ }
      }
      return r;
    }));

    return res.json({ ok: true, count: enriched.length, data: enriched });
  } catch (err) {
    console.error("GET /history (improved) error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});


// GET /user/:id
app.get("/user/:id", requireAdminOrGuard, async (req, res) => {
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

    const dynamic = createDynamicQrToken(id);
    const qrDataUrl = await genDynamicQrDataUrl(dynamic.token);

    return res.json({
      ok: true,
      id,
      name,
      role,
      token: dynamic.token,
      qrDataUrl,
      qrVersion: dynamic.payload.v,
      expiresAt: dynamic.payload.exp
    });
  } catch (err) {
    console.error("GET /user/:id error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

/* --------------------
   Admin Users endpoints (students)
   -------------------- */

// GET /users
app.get("/users", requireFirebaseAdmin, async (req, res) => {
  try {
    const qRole = String(req.query.role || "").trim().toLowerCase();
    const studentsSnap = await db.ref("students").once("value");
    const studentsVal = studentsSnap.val() || {};
    const ids = Object.keys(studentsVal);

    const users = await Promise.all(ids.map(async (id) => {
      const s = studentsVal[id] || {};
      const dynamic = createDynamicQrToken(id);
      const qrDataUrl = await genDynamicQrDataUrl(dynamic.token);
      return {
        id,
        name: s.name || null,
        role: s.role || null,
        token: dynamic.token,
        qrDataUrl,
        qrVersion: dynamic.payload.v,
        expiresAt: dynamic.payload.exp
      };
    }));

    const filtered = qRole ? users.filter(u => (u.role || "").toLowerCase() === qRole) : users;
    return res.json({ ok:true, count: filtered.length, data: filtered });
  } catch (err) {
    console.error("GET /users error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// POST /users
app.post("/users",requireFirebaseAdmin, async (req, res) => {
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

    const dynamic = createDynamicQrToken(id);
    const qrDataUrl = await genDynamicQrDataUrl(dynamic.token);

    await logAdminAction(req, {
      action: tokenSnap.exists() ? "user.upsert" : "user.create",
      entityType: "user",
      entityId: id,
      metadata: { role, regeneratedToken: regenerate === true || !tokenSnap.exists() }
    });

    return res.json({
      ok: true,
      id,
      name,
      role,
      token: dynamic.token,
      qrDataUrl,
      qrVersion: dynamic.payload.v,
      expiresAt: dynamic.payload.exp
    });
  } catch (err) {
    console.error("POST /users error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// PUT /users/:id
app.put("/users/:id",requireFirebaseAdmin, async (req, res) => {
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

    const dynamic = createDynamicQrToken(id);
    const qrDataUrl = await genDynamicQrDataUrl(dynamic.token);

    await logAdminAction(req, {
      action: regenerate === true ? "user.regenerate_token" : "user.update",
      entityType: "user",
      entityId: id,
      metadata: { fields: Object.keys(updates) }
    });

    return res.json({
      ok: true,
      id,
      name: student.name || null,
      role: student.role || null,
      token: dynamic.token,
      qrDataUrl,
      qrVersion: dynamic.payload.v,
      expiresAt: dynamic.payload.exp
    });
  } catch (err) {
    console.error("PUT /users/:id error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// DELETE /users/:id
app.delete("/users/:id",requireFirebaseAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });

    await db.ref(`students/${id}`).remove();
    await db.ref(`accessTokens/${id}`).remove();

    await logAdminAction(req, {
      action: "user.delete",
      entityType: "user",
      entityId: id
    });

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
app.post('/guard/login', async (req, res) => {
  try {
    const guardId = String(req.body.guardId || req.body.id || '').trim();
    const pin = String(req.body.pin || '').trim();
    if (!guardId || !pin) 
      return res.status(400).json({ ok:false, error:'missing guardId or pin' });

    if (isGuardLoginLocked(req, guardId)) {
      await logSecurityEvent({
        type: "guard.login",
        subjectId: guardId,
        outcome: "blocked",
        reason: "too many failed attempts",
        ip: req.ip || null
      });
      return res.status(429).json({ ok:false, error:'too many attempts, try later' });
    }

    await migrateExpiredTempPins();

    const gSnap = await db.ref(`guards/${guardId}`).once('value');
    if (!gSnap.exists()) {
      recordGuardLoginFailure(req, guardId);
      await logSecurityEvent({
        type: "guard.login",
        subjectId: guardId,
        outcome: "failure",
        reason: "invalid credentials",
        ip: req.ip || null
      });
      return res.status(401).json({ ok:false, error: 'invalid credentials' });
    }
    const g: any = gSnap.val();

    // ----- validar PIN permanente -----
    if (g.pinHash) {
      const okPerm = await bcrypt.compare(pin, String(g.pinHash));
      if (okPerm) {
        const token = jwt.sign(
          { guardId, name: g.name || "" },
          JWT_SECRET,
          { expiresIn: "24h" }
        );
        clearGuardLoginFailures(req, guardId);
        await db.ref(`guards/${guardId}`).update({ lastLogin: Date.now() });
        await logSecurityEvent({
          type: "guard.login",
          subjectId: guardId,
          outcome: "success",
          reason: "permanent pin",
          ip: req.ip || null
        });
        return res.json({ ok:true, guardId, method:'permanent', token });
      }
    }

    // ----- validar PIN temporal -----
    if (g.tempPinHash) {
      const okTemp = await bcrypt.compare(pin, String(g.tempPinHash));
      if (okTemp) {
        const now = Date.now();
        const expiresAt = Number(g.tempPinExpiresAt || 0);

        let method = "temp-active";

        if (expiresAt !== 0 && now > expiresAt) {
          await db.ref(`guards/${guardId}`).update({
            tempPinHash: null,
            tempPinCreatedAt: null,
            tempPinExpiresAt: null,
            tempPinInvalidatedAt: now
          });
          recordGuardLoginFailure(req, guardId);
          await logSecurityEvent({
            type: "guard.login",
            subjectId: guardId,
            outcome: "failure",
            reason: "temporary pin expired",
            ip: req.ip || null
          });
          return res.status(401).json({ ok:false, error:'temporary pin expired' });
        }

        // temp vigente -> promover a permanente después de autenticación exitosa
        if (expiresAt !== 0) {
          const updates: any = {};
          updates[`guards/${guardId}/pinHash`] = g.tempPinHash;
          updates[`guards/${guardId}/pinCreatedAt`] = g.tempPinCreatedAt || now;
          updates[`guards/${guardId}/tempPinHash`] = null;
          updates[`guards/${guardId}/tempPinCreatedAt`] = null;
          updates[`guards/${guardId}/tempPinExpiresAt`] = null;
          await db.ref().update(updates);
          method = "temp-promoted";
        }

        const token = jwt.sign(
          { guardId, name: g.name || "" },
          JWT_SECRET,
          { expiresIn: "24h" }
        );

        clearGuardLoginFailures(req, guardId);
        await db.ref(`guards/${guardId}`).update({ lastLogin: Date.now() });
        await logSecurityEvent({
          type: "guard.login",
          subjectId: guardId,
          outcome: "success",
          reason: method,
          ip: req.ip || null
        });
        return res.json({ ok:true, guardId, method, token });
      }
    }

    // credenciales inválidas
    recordGuardLoginFailure(req, guardId);
    await logSecurityEvent({
      type: "guard.login",
      subjectId: guardId,
      outcome: "failure",
      reason: "invalid credentials",
      ip: req.ip || null
    });
    return res.status(401).json({ ok:false, error:'invalid credentials' });

  } catch (err) {
    console.error('/guard/login error', err);
    return res.status(500).json({ ok:false, error:'server error' });
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
// guard/authorize (requireGuard)  -- REEMPLAZAR EXISTENTE con esta versión
app.post("/guard/authorize", requireGuard, async (req, res) => {
  try {
    const guardId = (req as any).guard.id;
    const { studentId, token, sessionId = "default", note, shiftId, type = "auto" } = req.body || {};
    if (!studentId && !token) return res.status(400).json({ ok: false, error: "studentId or token required" });

    const now = Date.now();

    // ------------------------
    // 1) Verificar que el guardia esté en turno
    // ------------------------
    // Si se entrega shiftId, verificar que exista y pertenezca al guard y esté activo.
    // Si no se entrega, buscar cualquier shift activo del guard.
    let shiftValid = false;
    let foundShift: any = null;
    try {
      if (shiftId) {
        const sSnap = await db.ref(`guardShifts/${shiftId}`).once("value");
        if (sSnap.exists()) {
          const sVal = sSnap.val();
          if (String(sVal.guardId) === String(guardId) && !sVal.endTimestamp && sVal.active !== false) {
            shiftValid = true;
            foundShift = { id: shiftId, ...sVal };
          }
        }
      } else {
        const sSnap = await db.ref("guardShifts").orderByChild("guardId").equalTo(guardId).once("value");
        const val = sSnap.val() || {};
        const open = Object.keys(val)
          .map(k => ({ id: k, ...(val[k] || {}) }))
          .filter((s: any) => !s.endTimestamp && s.active !== false)
          .sort((a:any,b:any)=> (b.startTimestamp||0) - (a.startTimestamp||0));
        if (open.length) {
          shiftValid = true;
          foundShift = open[0];
        }
      }
    } catch (e) {
      console.warn("shift check failed:", e);
      shiftValid = false;
    }

    if (!shiftValid) {
      // registrar intento
      await logAccess({
        id: studentId || null,
        token: token || null,
        authorized: false,
        reason: "guard not on shift",
        sessionId
      });
      return res.status(403).json({ ok: false, error: "Guardia no está en turno" });
    }

    // ------------------------
    // 2) Verificar existencia del usuario (studentId o token)
    // ------------------------
    let resolvedStudentId: string | null = null;
    let studentName: string | null = null;

    // Si llega studentId -> comprobar existencia en /students
    if (studentId) {
      const sSnap = await db.ref(`students/${studentId}`).once("value");
      if (!sSnap.exists()) {
        await logAccess({
          id: studentId,
          token: token || null,
          authorized: false,
          reason: "student id not found",
          sessionId
        });
        return res.status(400).json({ error: "Este usuario no existe" });
      }
      resolvedStudentId = studentId;
      studentName = sSnap.val().name || null;
    }

    // Si llega token (y aún no resolvimos studentId) -> buscar token en accessTokens o tokens
    if (!resolvedStudentId && token) {
      let foundKey: string | null = null;
      let tokenData: any = null;

      const tSnap = await db.ref('accessTokens').orderByChild('token').equalTo(String(token)).once('value');
      if (tSnap.exists()) {
        const val = tSnap.val();
        const keys = Object.keys(val);
        foundKey = keys[0];
        tokenData = val[foundKey];
      } else {
        const altSnap = await db.ref('tokens').orderByChild('token').equalTo(String(token)).once('value');
        if (altSnap.exists()) {
          const v = altSnap.val();
          const keys2 = Object.keys(v);
          foundKey = keys2[0];
          tokenData = v[foundKey];
        }
      }

      if (!foundKey) {
        await logAccess({
          token,
          authorized: false,
          reason: "token not linked to any user",
          sessionId
        });
        return res.status(400).json({ error: "Este usuario no existe" });
      }

      // mark resolved
      resolvedStudentId = foundKey;
      try {
        const sSnap = await db.ref(`students/${foundKey}`).once("value");
        if (sSnap.exists()) studentName = sSnap.val().name || null;
      } catch (e) { /* ignore */ }
    }

    // --------------
    // 3) Resolver transición de presencia antes de registrar la autorización.
    // --------------
    if (!resolvedStudentId) {
      return res.status(400).json({ ok: false, error: "No se pudo resolver el usuario" });
    }

    const transition = await commitAccessTransition(resolvedStudentId, String(type).trim().toLowerCase(), sessionId);
    if (!transition.ok) {
      await logAccess({
        id: resolvedStudentId,
        name: studentName || undefined,
        token: token || null,
        authorized: false,
        reason: transition.reason,
        sessionId,
        validationMode: "manual"
      });
      return res.status(409).json({ ok: false, error: transition.reason });
    }

    // --------------
    // 4) Guard en turno y usuario existente: persistir evidencia completa.
    // --------------
    const authRef = db.ref("guardAuthorizations").push();
    const authId = authRef.key!;
    await authRef.set({
      guardId,
      shiftId: foundShift ? foundShift.id : (shiftId || null),
      studentId: resolvedStudentId || null,
      token: token || null,
      authorized: true,
      reason: "manual_override",
      note: note || null,
      timestamp: now,
      sessionId,
      accessType: transition.accessType,
      previousInside: transition.previousInside,
      newInside: transition.newInside,
      validationMode: "manual"
    });

    await db.ref(`students/${resolvedStudentId}`).update({
      lastAccessTimestamp: now,
      lastAccessType: transition.accessType
    });
    await db.ref(`attendance/${sessionId}/${resolvedStudentId}`).push({
      type: transition.accessType,
      accessType: transition.accessType,
      timestamp: now,
      guardId,
      authId,
      shiftId: foundShift ? foundShift.id : (shiftId || null),
      previousInside: transition.previousInside,
      newInside: transition.newInside,
      validationMode: "manual"
    });

    await db.ref("accessHistory").push({
      id: resolvedStudentId || null,
      token: token || null,
      authorized: true,
      reason: "manual_override",
      note: note || null,
      timestamp: now,
      guardOverrideId: authId,
      shiftId: foundShift ? foundShift.id : (shiftId || null),
      accessType: transition.accessType,
      previousInside: transition.previousInside,
      newInside: transition.newInside,
      validationMode: "manual",
      qrVersion: null,
      sessionId
    });

    return res.json({
      ok: true,
      authId,
      timestamp: now,
      accessType: transition.accessType,
      inside: transition.newInside
    });
  } catch (err) {
    console.error("guard/authorize", err);
    await logAccess({ token: req.body?.token || null, id: req.body?.studentId || null, authorized: false, reason: "server error" });
    return res.status(500).json({ ok: false, error: "server" });
  }
});


/* --------------------
   Admin read endpoints for shifts/authorizations/teachers/admins
   -------------------- */

// GET /guardShifts?active=true&guardId=xxx
app.get("/guardShifts", requireAdminOrGuard, async (req, res) => {
  try {
    const requesterGuardId = (req as any).guard?.id ? String((req as any).guard.id) : "";
    const isAdmin = !!(req as any).admin;
    const guardIdQ = requesterGuardId || String(req.query.guardId || "").trim();
    const activeQ = String(req.query.active || "").toLowerCase(); // "true"|"false"|""
    const snap = await db.ref("guardShifts").once("value");
    const val = snap.val() || {};
    let arr = Object.keys(val).map(k => ({ id: k, ...(val[k] || {}) }));
    if (guardIdQ) arr = arr.filter(s => String(s.guardId) === guardIdQ);
    if (!isAdmin && requesterGuardId) arr = arr.filter(s => String(s.guardId) === requesterGuardId);
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
app.get("/guardAuthorizations", requireAdminOrGuard, async (req, res) => {
  try {
    const requesterGuardId = (req as any).guard?.id ? String((req as any).guard.id) : "";
    const guardId = requesterGuardId || String(req.query.guardId || "").trim();
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
app.get('/guards',requireFirebaseAdmin, async (req, res) => {
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

const GUARDS_PATH = 'guards'; 

app.get('/api/guards/:id/pin', requireFirebaseAdmin, async (_req, res) => {
    return res.status(410).json({
      ok: false,
      error: "plain pin retrieval disabled",
      message: "Por seguridad, los PIN no se leen en texto plano. Use el flujo de reseteo para generar un PIN de un solo uso."
    });
});

/* --------------------
   Teachers endpoints
   -------------------- */

// GET /teachers
app.get("/teachers",requireFirebaseAdmin, async (req, res) => {
  try {
    const snap = await db.ref("teachers").once("value");
    const val = snap.val() || {};
    const ids = Object.keys(val);
    const out = await Promise.all(ids.map(async id => {
      const dynamic = createDynamicQrToken(id);
      const qrDataUrl = await genDynamicQrDataUrl(dynamic.token);
      return { id, name: val[id].name || null, createdAt: val[id].createdAt || null, token: dynamic.token, qrDataUrl, qrVersion: dynamic.payload.v, expiresAt: dynamic.payload.exp };
    }));
    return res.json({ ok:true, count: out.length, data: out });
  } catch (err) {
    console.error("GET /teachers", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// POST /teachers
app.post("/teachers",requireFirebaseAdmin, async (req, res) => {
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
    const dynamic = createDynamicQrToken(id);
    const qrDataUrl = await genDynamicQrDataUrl(dynamic.token);
    await logAdminAction(req, {
      action: "teacher.create",
      entityType: "teacher",
      entityId: id
    });
    return res.json({ ok:true, id, name, token: dynamic.token, qrDataUrl, qrVersion: dynamic.payload.v, expiresAt: dynamic.payload.exp });
  } catch (err) {
    console.error("POST /teachers", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// PUT /teachers/:id
app.put("/teachers/:id",requireFirebaseAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const { name } = req.body || {};
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });
    if (!name) return res.status(400).json({ ok:false, error:"name required" });
    await db.ref(`teachers/${id}`).update({ name });
    const dynamic = createDynamicQrToken(id);
    const qrDataUrl = await genDynamicQrDataUrl(dynamic.token);
    await logAdminAction(req, {
      action: "teacher.update",
      entityType: "teacher",
      entityId: id,
      metadata: { fields: ["name"] }
    });
    return res.json({ ok:true, id, name, token: dynamic.token, qrDataUrl, qrVersion: dynamic.payload.v, expiresAt: dynamic.payload.exp });
  } catch (err) {
    console.error("PUT /teachers/:id", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// DELETE /teachers/:id
app.delete("/teachers/:id",requireFirebaseAdmin , async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });
    await db.ref(`teachers/${id}`).remove();
    await db.ref(`accessTokens/${id}`).remove();
    await logAdminAction(req, {
      action: "teacher.delete",
      entityType: "teacher",
      entityId: id
    });
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
// GET /admins  (requireAdmin)  — reemplaza tu handler actual por este
app.get('/admins',requireFirebaseAdmin, async (req, res) => {
  try {
    // DEBUG: mostrar el header que vino en la petición
    console.log('DEBUG /admins -> x-admin-secret header:', req.headers['x-admin-secret'] ? '[present]' : '[missing]');

    const snap = await db.ref('admins').once('value');
    const val = snap.val() || {};

    // DEBUG: keys encontradas en la DB
    const keys = Object.keys(val || {});
    console.log('DEBUG /admins -> firebase keys count:', keys.length, 'keys:', keys.slice(0,20));

    // convertir a array uniforme [{ id, name, ... }]
    const out = keys.map(k => {
      const v = val[k] || {};
      return {
        id: String(v.id || k),
        name: v.name || v.fullName || v.nombre || null,
        email: v.email || null,
        role: v.role || null,
        createdAt: v.createdAt || null
      };
    });

    // Forzar no-cache en la respuesta (evita 304 en front)
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');

    return res.json({ ok: true, count: out.length, data: out });
  } catch (err) {
    console.error('/admins error:', err);
    return res.status(500).json({ ok: false, error: 'server error' });
  }
});



// DEBUG endpoint protegido y disponible solo en desarrollo.
app.get('/debug/admins', requireFirebaseAdmin, async (req, res) => {
  if (IS_PRODUCTION) return res.status(404).json({ ok: false, error: "not found" });
  try {
    const snap = await db.ref('admins').once('value');
    const val = snap.val() || {};
    const sanitized = Object.keys(val || {}).map(k => ({
      id: String(val[k]?.id || k),
      name: val[k]?.name || val[k]?.fullName || val[k]?.nombre || null,
      email: val[k]?.email || null,
      role: val[k]?.role || null,
      createdAt: val[k]?.createdAt || null
    }));
    return res.json({ ok: true, data: sanitized, keys: Object.keys(val || {}) });
  } catch (e) {
    console.error('debug/admins error', e);
    return res.status(500).json({ ok: false, error: 'server error' });
  }
});


// POST /admins
app.post("/admins",requireFirebaseAdmin, async (req, res) => {
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
    const dynamic = createDynamicQrToken(id);
    const qrDataUrl = await genDynamicQrDataUrl(dynamic.token);
    await logAdminAction(req, {
      action: "admin_profile.create",
      entityType: "admin",
      entityId: id
    });
    return res.json({ ok:true, id, name, token: dynamic.token, qrDataUrl, qrVersion: dynamic.payload.v, expiresAt: dynamic.payload.exp });
  } catch (err) {
    console.error("POST /admins", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});


// POST /admin/guard/shift/start  (requireAdmin)
app.post('/admin/guard/shift/start',requireFirebaseAdmin, async (req, res) => {
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

    await logAdminAction(req, {
      action: "guard_shift.start",
      entityType: "guardShift",
      entityId: shiftId,
      metadata: { guardId }
    });

    return res.json({ ok:true, shiftId, startTimestamp: now });
  } catch (err) {
    console.error('/admin/guard/shift/start error:', err);
    return res.status(500).json({ ok:false, error: 'server error' });
  }
});

app.post('/admin/guard/shift/end',requireFirebaseAdmin, async (req, res) => {
  try {
    const { guardId, shiftId, notes } = req.body || {};

    if (shiftId) {
      const sSnap = await db.ref(`guardShifts/${shiftId}`).once("value");
      if (!sSnap.exists()) return res.status(404).json({ ok:false, error: 'shift not found' });
      const shift = sSnap.val();
      if (shift.endTimestamp) return res.status(400).json({ ok:false, error: 'shift already ended' });
      const endTs = Date.now();
      await db.ref(`guardShifts/${shiftId}`).update({ endTimestamp: endTs, active: false, notes: notes || shift.notes || null });
      await logAdminAction(req, {
        action: "guard_shift.end",
        entityType: "guardShift",
        entityId: shiftId,
        metadata: { guardId: shift.guardId || null }
      });
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

    await logAdminAction(req, {
      action: "guard_shift.end",
      entityType: "guardShift",
      entityId: target.id,
      metadata: { guardId }
    });

    return res.json({ ok:true, shiftId: target.id, endTimestamp: endTs, message: 'closed latest active shift' });
  } catch (err) {
    console.error('/admin/guard/shift/end error:', err);
    return res.status(500).json({ ok:false, error: 'server error' });
  }
});

app.post("/admin/guards/:id/reset-pin", requireFirebaseAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });

    // Verificar que el guard exista
    const gSnap = await db.ref(`guards/${id}`).once("value");
    if (!gSnap.exists()) return res.status(404).json({ ok:false, error:"guard not found" });

    const clientSecret = req.headers['x-admin-secret'];
    if (!clientSecret || !safeCompareString(String(clientSecret), ADMIN_SECRET)) {
        return res.status(401).json({ error: 'Unauthorized. Invalid admin secret.' });
    }

    // Generar PIN temporal: 6 dígitos
    const tempPin = Math.floor(100000 + Math.random() * 900000).toString();
    const saltRounds = 10;
    const hash = await bcrypt.hash(tempPin, saltRounds);

    // Fechas
    const now = Date.now();
    const expiresMs = 10 * 60 * 1000; // 10 minutos
    const expiresAt = now + expiresMs;

    // Guardar el hash temporal. Se promoverá a permanente solo si se usa antes de expirar.
    await db.ref(`guards/${id}`).update({
      tempPinHash: hash,
      tempPinCreatedAt: now,
      tempPinExpiresAt: expiresAt,
      tempPinInvalidatedAt: null
    });

    await logAdminAction(req, {
      action: "guard.reset_pin",
      entityType: "guard",
      entityId: id,
      metadata: { expiresAt, note: req.body?.note || null }
    });

    // Devolver el PIN temporal SOLO en la respuesta (mostrar una vez en UI)
    return res.json({
      ok: true,
      message: "PIN temporal generado (mostrar sólo una vez).",
      tempPin,
      expiresAt
    });
  } catch (err) {
    console.error("POST /admin/guards/:id/reset-pin error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

// GET /admin/guards  (mejorado) - requiere requireAdmin
app.get("/admin/guards",requireFirebaseAdmin, async (req, res) => {
  try {
    const snap = await db.ref('guards').once('value');
    const val = snap.val() || {};
    const ids = Object.keys(val);
    const out = await Promise.all(ids.map(async id => {
      const g = val[id] || {};
      // opcional: leer últimos datos relevantes
      const lastLogin = g.lastLogin || null;
      const createdAt = g.createdAt || null;
      // no entregar pinHash
      return { id, name: g.name || null, lastLogin, createdAt };
    }));
    return res.json({ ok: true, count: out.length, data: out });
  } catch (err) {
    console.error("/admin/guards error:", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});


// PUT /admins/:id
app.put("/admins/:id",requireFirebaseAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const { name } = req.body || {};
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });
    if (!name) return res.status(400).json({ ok:false, error:"name required" });
    await db.ref(`admins/${id}`).update({ name });
    const dynamic = createDynamicQrToken(id);
    const qrDataUrl = await genDynamicQrDataUrl(dynamic.token);
    await logAdminAction(req, {
      action: "admin_profile.update",
      entityType: "admin",
      entityId: id,
      metadata: { fields: ["name"] }
    });
    return res.json({ ok:true, id, name, token: dynamic.token, qrDataUrl, qrVersion: dynamic.payload.v, expiresAt: dynamic.payload.exp });
  } catch (err) {
    console.error("PUT /admins/:id", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

const rtdb = admin.database();

app.put('/api/admins/:id', requireFirebaseAdmin, async (req, res) => {
    // 1. Obtener el ID del administrador de la URL (ruta param)
    const adminId = req.params.id; 
    
    // 2. Obtener los datos a actualizar del cuerpo de la solicitud
    const newData = req.body; // Contiene username, rol, etc.

    // Opcional: Quitar campos de control si existen (como el ID si se envió doblemente)
    delete newData.id; 

    try {
        // 3. Crear la referencia al nodo específico del administrador
        // Asumiendo que tus admins se guardan en el path "admins/[adminId]"
        const adminRef = rtdb.ref(`admins/${adminId}`); 
        
        // 4. Usar el método .update() de Firebase para actualizar (mergear) los campos
        await adminRef.update(newData); 

        await logAdminAction(req, {
          action: "admin_profile.update",
          entityType: "admin",
          entityId: adminId,
          metadata: { fields: Object.keys(newData) }
        });

        return res.status(200).json({ message: 'Administrador actualizado con éxito.' });
    } catch (error) {
        console.error("Error al actualizar admin en Firebase:", error);
        return res.status(500).json({ error: 'Error interno al actualizar el administrador.' });
    }
});


// DELETE /admins/:id
app.delete("/admins/:id",requireFirebaseAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ ok:false, error:"missing id" });
    await db.ref(`admins/${id}`).remove();
    await db.ref(`accessTokens/${id}`).remove();
    await logAdminAction(req, {
      action: "admin_profile.delete",
      entityType: "admin",
      entityId: id
    });
    return res.json({ ok:true, id, message:"deleted" });
  } catch (err) {
    console.error("DELETE /admins/:id", err);
    return res.status(500).json({ ok:false, error:"server error" });
  }
});

/* --------------------
   Shift history by shiftId (admin)
   -------------------- */
app.get("/shift/:shiftId/history",requireFirebaseAdmin, async (req, res) => {
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

app.post('/guards/create', requireFirebaseAdmin, async (req, res) => {
  try {
    const { id, name, pin } = req.body;
    if (!id || !name || !pin) return res.status(400).json({ ok: false, error: 'missing fields' });

    const hash = await bcrypt.hash(pin, 10);
    await db.ref(`guards/${id}`).set({
      name,
      pinHash: hash,
      createdAt: Date.now()
    });

    await logAdminAction(req, {
      action: "guard.create",
      entityType: "guard",
      entityId: id
    });

    res.json({ ok: true, id, name });
  } catch (err) {
    console.error('Error creando guard:', err);
    res.status(500).json({ ok: false, error: 'server' });
  }
});

const frontendPath = path.resolve(__dirname, "../..", "frontend");
// Serve static files (css, js, images, html)
app.use(express.static(frontendPath));

// Root -> index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// Optional: fallback for other non-API routes (helps SPA links) — only if you want it
app.get(/^\/(?!guard|admin|history|verify|validate|users|api).*/, (req, res) => {
  // if route doesn't start with an API prefix, send index.html so client-side routes work
  res.sendFile(path.join(frontendPath, "index.html"));
});


/* --------------------
   Inicio servidor
   -------------------- */
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
