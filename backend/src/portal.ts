import { Router, Request, Response, NextFunction } from 'express';
import admin from 'firebase-admin';
import crypto from 'crypto';
import axios from 'axios';
import PDFDocument from 'pdfkit';
import { startShift } from './shifts';

type Profile = { uid: string; id: string; role: 'admin' | 'guard' | 'member'; name: string };
const cookieName = 'control_session';
const digest = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
const sessionKey = (req: Request) => {
  const raw = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
  return raw && /^[a-f0-9]{64}$/.test(raw) ? digest(raw) : null;
};

export function installPortal(app: Router, db: admin.database.Database, qr: (id: string) => Promise<any>, qrStatus: (id: string, token: string) => Promise<{ renew: boolean }>) {
  const router = Router();
  const cookieOptions = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' as const, path: '/' };
  const attempts = new Map<string, { count: number; until: number }>();
  const RESET_WINDOW_MS = 15 * 60_000;
  const SESSION_MAX_AGE_MS = 6 * 60 * 60_000;

  function requestKey(req: Request, email = '') {
    return `${req.ip || 'unknown'}:${email.toLowerCase()}`;
  }

  function registerAttempt(key: string, max = 10) {
    const now = Date.now();
    for (const [storedKey, value] of attempts) if (value.until <= now) attempts.delete(storedKey);
    const current = attempts.get(key) || { count: 0, until: now + RESET_WINDOW_MS };
    if (current.count >= max || attempts.size > 10000) return false;
    current.count += 1;
    attempts.set(key, current);
    return true;
  }

  const sessionCleanupTimer = setInterval(() => {
    void db.ref('portalSessions').get()
      .then(snapshot => {
        const updates: Record<string, null> = {};
        const now = Date.now();
        for (const [key, value] of Object.entries(snapshot.val() || {})) {
          if (Number((value as any)?.expiresAt || 0) <= now) updates[`portalSessions/${key}`] = null;
        }
        if (Object.keys(updates).length) return db.ref().update(updates);
      })
      .catch(error => console.error('portal session cleanup error:', error));
  }, 5 * 60_000);
  sessionCleanupTimer.unref?.();

  async function profile(uid: string): Promise<Profile | null> {
    try {
      if ((await admin.auth().getUser(uid)).disabled) return null;
    } catch (error: any) {
      if (error.code === 'auth/user-not-found') return null;
      throw error;
    }
    // Existing accounts use their Auth UID as the database key. Migrations can supply an explicit mapping.
    const mapping = (await db.ref(`portalProfiles/${uid}`).get()).val();
    if (mapping?.active === false) return null;
    const candidates = mapping ? [[mapping.role, mapping.id]] : [['admin', uid], ['guard', uid], ['member', uid]];
    for (const [role, id] of candidates) {
      if (!['admin', 'guard', 'member'].includes(role) || typeof id !== 'string' || /[.#$\[\]/]/.test(id) || !id) continue;
      const collection = role === 'admin' ? 'admins' : role === 'guard' ? 'guards' : 'students';
      const value = (await db.ref(`${collection}/${id}`).get()).val();
      if (value && value.active !== false && (role !== 'admin' || value.role === 'admin')) {
        return { uid, id, role: role as Profile['role'], name: String(value.name || id) };
      }
    }
    return null;
  }

  app.use(async (req: Request, res: Response, next: NextFunction) => {
    const key = sessionKey(req);
    if (!key) return next();
    res.setHeader('Cache-Control', 'no-store');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.headers['x-portal-request'] !== '1') {
      return res.status(403).json({ ok: false, error: 'Solicitud no autorizada.' });
    }
    try {
      const session = (await db.ref(`portalSessions/${key}`).get()).val();
      if (session?.expiresAt > Date.now()) {
        const current = await profile(session.uid);
        if (current && current.id === session.id && current.role === session.role) {
          (req as any).portal = current;
          if (current.role === 'admin') (req as any).admin = { uid: current.uid, name: current.name };
          if (current.role === 'guard') (req as any).guard = { id: current.id, name: current.name };
        }
      } else if (session) await db.ref(`portalSessions/${key}`).remove();
      next();
    } catch { res.status(503).json({ ok: false, error: 'No se pudo verificar la sesion. Intenta nuevamente.' }); }
  });

  router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
  router.post('/login', async (req, res) => {
    if (req.headers['x-portal-request'] !== '1') return res.status(403).json({ ok: false, error: 'Solicitud no autorizada.' });
    const email = String(req.body?.email || '').trim();
    const password = req.body?.password;
    if (!email.includes('@') || email.length > 254 || typeof password !== 'string' || !password || password.length > 1024) {
      return res.status(400).json({ ok: false, error: 'Completa el correo y la contrasena.' });
    }
    const now = Date.now();
    const attemptKey = requestKey(req, email);
    if (!registerAttempt(attemptKey)) return res.status(429).json({ ok: false, error: 'Demasiados intentos. Espera 15 minutos.' });
    const emulator = process.env.FIREBASE_AUTH_EMULATOR_HOST;
    if (emulator && process.env.NODE_ENV === 'production') return res.status(503).json({ ok: false, error: 'Configuracion de autenticacion invalida.' });
    const apiKey = process.env.FIREBASE_WEB_API_KEY;
    if (!apiKey && !emulator) return res.status(503).json({ ok: false, error: 'El administrador debe configurar Firebase Authentication.' });
    try {
      const base = emulator ? `http://${emulator}/identitytoolkit.googleapis.com` : 'https://identitytoolkit.googleapis.com';
      const result = await axios.post(`${base}/v1/accounts:signInWithPassword?key=${encodeURIComponent(apiKey || 'emulator')}`, { email, password, returnSecureToken: true }, { timeout: 10000 });
      const identity = await admin.auth().verifyIdToken(result.data.idToken, true);
      const current = await profile(identity.uid);
      if (!current) return res.status(403).json({ ok: false, error: 'Tu cuenta no tiene un perfil habilitado. Contacta al administrador.' });
      const value = crypto.randomBytes(32).toString('hex');
      const maxAge = SESSION_MAX_AGE_MS;
      await db.ref(`portalSessions/${digest(value)}`).set({ ...current, expiresAt: now + maxAge });
      const oldKey = sessionKey(req);
      if (oldKey) await db.ref(`portalSessions/${oldKey}`).remove();
      res.cookie(cookieName, value, { ...cookieOptions, maxAge });
      attempts.delete(attemptKey);
      return res.json({ ok: true, user: current });
    } catch (error: any) {
      const code = error.response?.data?.error?.message || '';
      if (['INVALID_LOGIN_CREDENTIALS', 'EMAIL_NOT_FOUND', 'INVALID_PASSWORD', 'USER_DISABLED'].includes(code)) {
        return res.status(401).json({ ok: false, error: 'Correo o contrasena incorrectos, o cuenta deshabilitada.' });
      }
      return res.status(503).json({ ok: false, error: 'No fue posible iniciar sesion. Intenta nuevamente.' });
    }
  });

  router.post('/password-reset', async (req, res) => {
    if (req.headers['x-portal-request'] !== '1') return res.status(403).json({ ok: false, error: 'Solicitud no autorizada.' });
    const email = String(req.body?.email || '').trim().toLowerCase();
    const generic = { ok: true, message: 'Si la cuenta existe, recibiras instrucciones para recuperar el acceso.' };
    if (!email || email.length > 254 || !registerAttempt(requestKey(req, `reset:${email}`), 3)) return res.json(generic);
    const apiKey = process.env.FIREBASE_WEB_API_KEY;
    const emulator = process.env.FIREBASE_AUTH_EMULATOR_HOST;
    if (!apiKey && !emulator) return res.json(generic);
    try {
      const base = emulator ? `http://${emulator}/identitytoolkit.googleapis.com` : 'https://identitytoolkit.googleapis.com';
      await axios.post(`${base}/v1/accounts:sendOobCode?key=${encodeURIComponent(apiKey || 'emulator')}`, { requestType: 'PASSWORD_RESET', email }, { timeout: 10000 });
    } catch (_) {
      // Respuesta generica para no revelar si el correo esta registrado.
    }
    return res.json(generic);
  });
  router.post('/logout', async (req, res) => {
    if (req.headers['x-portal-request'] !== '1') return res.sendStatus(403);
    try {
      const key = sessionKey(req);
      if (key) await db.ref(`portalSessions/${key}`).remove();
      res.clearCookie(cookieName, cookieOptions);
      res.json({ ok: true });
    } catch { res.status(503).json({ ok: false, error: 'No se pudo cerrar la sesion. Reintenta.' }); }
  });
  router.use((req, res, next) => (req as any).portal ? next() : res.status(401).json({ ok: false, error: 'Inicia sesion para continuar.' }));
  router.get('/me', (req, res) => res.json({ ok: true, user: (req as any).portal }));

  router.use('/users', (req, res, next) => {
    if ((req as any).portal?.role !== 'admin') return res.status(403).json({ ok: false, error: 'Solo administradores pueden gestionar usuarios.' });
    next();
  });

  router.get('/users', async (_req, res) => {
    try {
      const [students, guards, admins] = await Promise.all([
        db.ref('students').get(), db.ref('guards').get(), db.ref('admins').get()
      ]);
      const authEmail = async (uid: string | null | undefined, fallback: any = null) => {
        if (fallback) return String(fallback);
        if (!uid) return null;
        try { return (await admin.auth().getUser(uid)).email || null; } catch { return null; }
      };
      const data: any[] = [];
      for (const [id, value] of Object.entries(students.val() || {})) {
        const row: any = value || {};
        data.push({ id, name: row.name || id, sede: row.sede || '', tipoUsuario: row.tipoUsuario || row.role || '', email: await authEmail(row.authUid, row.email), role: 'member', active: row.active !== false, uid: row.authUid || null });
      }
      for (const [id, value] of Object.entries(guards.val() || {})) {
        const row: any = value || {};
        data.push({ id, name: row.name || id, sede: row.sede || '', tipoUsuario: row.tipoUsuario || row.role || '', email: await authEmail(row.authUid, row.email), role: 'guard', active: row.active !== false, uid: row.authUid || null });
      }
      for (const [id, value] of Object.entries(admins.val() || {})) {
        const row: any = value || {};
        data.push({ id, name: row.name || id, sede: row.sede || '', tipoUsuario: row.tipoUsuario || row.role || '', email: await authEmail(id, row.email), role: 'admin', active: row.active !== false, uid: id });
      }
      return res.json({ ok: true, count: data.length, data });
    } catch { return res.status(503).json({ ok: false, error: 'No se pudo cargar la lista de usuarios.' }); }
  });

  router.get('/guards', async (req, res) => {
    if ((req as any).portal?.role !== 'admin') return res.status(403).json({ ok: false, error: 'Solo administradores pueden consultar guardias.' });
    try {
      const [guardsSnap, shiftsSnap] = await Promise.all([db.ref('guards').get(), db.ref('guardShifts').get()]);
      const shifts = Object.values(shiftsSnap.val() || {}) as any[];
      const data = await Promise.all(Object.entries(guardsSnap.val() || {}).map(async ([id, value]: [string, any]) => {
        const uid = value?.authUid || null;
        let email = value?.email || null;
        if (!email && uid) { try { email = (await admin.auth().getUser(uid)).email || null; } catch {} }
        const activeShift = shifts.filter(shift => shift.guardId === id && shift.active !== false && !shift.endTimestamp)
          .sort((a, b) => Number(b.startTimestamp || 0) - Number(a.startTimestamp || 0))[0] || null;
        return { id, name: value?.name || id, email, active: value?.active !== false, lastLogin: value?.lastLogin || null, activeShift: activeShift ? { id: activeShift.id || null, startTimestamp: activeShift.startTimestamp || null } : null };
      }));
      return res.json({ ok: true, count: data.length, data });
    } catch { return res.status(503).json({ ok: false, error: 'No se pudo cargar el panel de guardias.' }); }
  });

  router.get('/guard-report', async (req, res) => {
    if ((req as any).portal?.role !== 'admin') return res.status(403).json({ ok: false, error: 'Solo administradores pueden consultar el historial de guardias.' });
    try {
      const [guardsSnap, shiftsSnap, historySnap] = await Promise.all([db.ref('guards').get(), db.ref('guardShifts').get(), db.ref('accessHistory').get()]);
      const historyRows = Object.values(historySnap.val() || {}) as any[];
      const shifts = Object.entries(shiftsSnap.val() || {}).map(([id, value]: [string, any]) => ({ id, ...(value || {}) }));
      const data = Object.entries(guardsSnap.val() || {}).flatMap(([id, value]: [string, any]) => {
        const guard = value || {};
        const guardShifts = shifts.filter(shift => shift.guardId === id).sort((a, b) => Number(b.startTimestamp || 0) - Number(a.startTimestamp || 0));
        const sourceRows = historyRows.filter(row => row.validatedById === guard.authUid || row.guardId === id);
        const rows = guardShifts.length ? guardShifts : [{ id: null, startTimestamp: null, endTimestamp: null, active: false }];
        return rows.map(shift => {
          const start = Number(shift.startTimestamp || 0);
          const end = Number(shift.endTimestamp || Date.now());
          const accessRows = sourceRows.filter(row => Number(row.timestamp || 0) >= start && (!start || Number(row.timestamp || 0) <= end));
          const approvedAccesses = accessRows.filter(row => row.authorized === true).length;
          const rejectedAccesses = accessRows.filter(row => row.authorized === false).length;
          return { id, name: guard.name || id, email: guard.email || null, active: guard.active !== false, shiftId: shift.id, startTimestamp: shift.startTimestamp || null, endTimestamp: shift.endTimestamp || null, shiftActive: shift.active !== false && !shift.endTimestamp, approvedAccesses, rejectedAccesses, totalAccesses: approvedAccesses + rejectedAccesses };
        });
      });
      return res.json({ ok: true, generatedAt: Date.now(), data });
    } catch { return res.status(503).json({ ok: false, error: 'No se pudo cargar el historial de guardias.' }); }
  });

  router.post('/users', async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const name = String(req.body?.name || '').trim();
    const role = String(req.body?.role || 'member').trim().toLowerCase();
    const password = req.body?.password;
    if (!email || !email.includes('@') || !name || !['admin', 'guard', 'member'].includes(role) || typeof password !== 'string' || password.length < 12) {
      return res.status(400).json({ ok: false, error: 'Correo, nombre, rol y una contraseña de al menos 12 caracteres son obligatorios.' });
    }
    if (req.body?.id) return res.status(400).json({ ok: false, error: 'El identificador se genera automaticamente.' });
    try {
      const authUser = await admin.auth().createUser({ email, password, displayName: name, disabled: false });
      const id = authUser.uid;
      const collection = role === 'admin' ? 'admins' : role === 'guard' ? 'guards' : 'students';
      await db.ref(`${collection}/${id}`).set({ name, email, role: role === 'member' ? 'estudiante' : role, active: true, authUid: authUser.uid, createdAt: Date.now() });
      await db.ref(`portalProfiles/${authUser.uid}`).set({ id, role, active: true });
      await db.ref(`adminAuditLog`).push({ actorId: (req as any).portal.uid, action: 'portal.user.create', entityType: role, entityId: id, timestamp: Date.now(), ip: req.ip || null });
      return res.status(201).json({ ok: true, user: { id, uid: authUser.uid, email, name, role, active: true } });
    } catch (error: any) {
      if (error?.code === 'auth/email-already-exists') return res.status(409).json({ ok: false, error: 'El correo ya esta registrado.' });
      console.error('portal user create error:', error);
      return res.status(503).json({ ok: false, error: 'No se pudo crear el usuario.' });
    }
  });

  router.patch('/users/:role/:id/profile', async (req, res) => {
    const { role, id } = req.params;
    const collections: Record<string, string> = { member: 'students', guard: 'guards', admin: 'admins' };
    const { name, sede, tipoUsuario } = req.body || {};
    if (!collections[role] || !id || /[.#$\[\]/]/.test(id) ||
        typeof name !== 'string' || !name.trim() || name.length > 120 ||
        typeof sede !== 'string' || sede.length > 120 ||
        typeof tipoUsuario !== 'string' || tipoUsuario.length > 60) {
      return res.status(400).json({ ok: false, error: 'Datos del perfil invalidos.' });
    }
    try {
      const ref = db.ref(`${collections[role]}/${id}`);
      if (!(await ref.get()).exists()) return res.status(404).json({ ok: false, error: 'Perfil no encontrado.' });
      const auditKey = db.ref('adminAuditLog').push().key!;
      await db.ref().update({
        [`${collections[role]}/${id}/name`]: name.trim(),
        [`${collections[role]}/${id}/sede`]: sede.trim(),
        [`${collections[role]}/${id}/tipoUsuario`]: tipoUsuario.trim(),
        [`adminAuditLog/${auditKey}`]: { actorId: (req as any).portal.uid, action: 'portal.profile.update', entityId: id, entityType: role, timestamp: Date.now() }
      });
      return res.json({ ok: true });
    } catch { return res.status(503).json({ ok: false, error: 'No se pudo editar el perfil.' }); }
  });

  router.patch('/users/:uid', async (req, res) => {
    const uid = String(req.params.uid || '').trim();
    if (!uid || !/^[A-Za-z0-9_-]{1,128}$/.test(uid)) return res.status(400).json({ ok: false, error: 'Identificador invalido.' });
    const active = req.body?.active;
    if (typeof active !== 'boolean') return res.status(400).json({ ok: false, error: 'El estado active debe ser booleano.' });
    if (uid === (req as any).portal.uid && !active) return res.status(409).json({ ok: false, error: 'No puedes desactivar tu propia cuenta.' });
    try {
      let mapping = (await db.ref(`portalProfiles/${uid}`).get()).val();
      if (!mapping) {
        for (const [role, collection] of [['admin', 'admins'], ['guard', 'guards'], ['member', 'students']]) {
          if ((await db.ref(`${collection}/${uid}`).get()).exists()) { mapping = { role, id: uid }; break; }
        }
      }
      if (!mapping?.id || !['admin', 'guard', 'member'].includes(mapping.role)) return res.status(409).json({ ok: false, error: 'Perfil no vinculado.' });
      const authUser = await admin.auth().updateUser(uid, { disabled: !active });
      if (mapping) {
        await db.ref(`portalProfiles/${uid}`).set({ id: mapping.id, role: mapping.role, active });
        const collection = mapping.role === 'admin' ? 'admins' : mapping.role === 'guard' ? 'guards' : 'students';
        await db.ref(`${collection}/${mapping.id}`).update({ active });
      }
      await db.ref('adminAuditLog').push({ actorId: (req as any).portal.uid, action: active ? 'portal.user.activate' : 'portal.user.deactivate', entityType: 'user', entityId: uid, timestamp: Date.now(), ip: req.ip || null });
      return res.json({ ok: true, uid: authUser.uid, active });
    } catch (error: any) {
      if (error?.code === 'auth/user-not-found') return res.status(404).json({ ok: false, error: 'Usuario no encontrado.' });
      return res.status(503).json({ ok: false, error: 'No se pudo actualizar el usuario.' });
    }
  });

  async function history(user: Profile) {
    const ref = db.ref('accessHistory');
    // La base remota puede no tener aun los indices versionados localmente.
    // Leemos el conjunto protegido por backend y aplicamos filtro/orden aqui.
    const snapshot = await ref.get();
    const [students, guards, admins] = await Promise.all([db.ref('students').get(), db.ref('guards').get(), db.ref('admins').get()]);
    const people: Record<string, any> = { ...(students.val() || {}), ...(guards.val() || {}), ...(admins.val() || {}) };
    const rows = Object.entries(snapshot.val() || {}).filter(([, row]: [string, any]) => {
      if (user.role === 'member') return String(row.studentUid || row.id || '') === user.id;
      if (user.role === 'guard') return row.validatedById === user.uid || row.guardId === user.id;
      return true;
    });
    return rows.map(([key, row]: [string, any]) => {
      const person = people[row.studentUid || row.id] || {};
      return {
        key, id: String(row.studentUid || row.id || ''), name: String(row.name || row.studentName || person.name || row.studentUid || row.id || 'Sin identificar'),
        timestamp: Number(row.timestamp || 0), accessType: row.accessType || null,
        authorized: row.authorized === true, reason: String(row.reason || (row.authorized === true ? 'ok' : 'Sin motivo registrado')),
        sede: String(row.sede || row.campus || person.sede || person.campus || 'Sin sede'), tipoUsuario: String(row.tipoUsuario || row.role || person.tipoUsuario || person.role || 'Sin tipo'),
        validatedBy: String(row.validatedByName || row.validatedById || 'Sin registrar'), validatedByRole: String(row.validatedByRole || '')
      };
    }).sort((a, b) => b.timestamp - a.timestamp).slice(0, 500);
  }
  router.get('/history', async (req, res) => {
    try { res.json({ ok: true, data: await history((req as any).portal) }); }
    catch (error) { console.error('portal history error:', error); res.status(503).json({ ok: false, error: 'No se pudo cargar el historial.' }); }
  });
  router.get('/history.pdf', async (req, res) => {
    try {
      const rows = await history((req as any).portal);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename="historial-accesos.pdf"');
      const document = new PDFDocument({ size: 'A4', margin: 36 });
      document.pipe(res);
      document.fontSize(16).text('Historial de control de accesos');
      document.fontSize(9).text(`Generado: ${new Date().toLocaleString('es-CL')} | Registros: ${rows.length}`);
      document.moveDown();
      rows.forEach((row, index) => {
        if (document.y > 760) document.addPage();
        document.fontSize(8).text(`${index + 1}. ${new Date(row.timestamp).toLocaleString('es-CL')} | ${row.name} (${row.id}) | ${row.accessType || '-'} | ${row.authorized ? 'AUTORIZADO' : 'RECHAZADO'} | ${row.reason} | Valido: ${row.validatedBy}`);
      });
      document.end();
    } catch (error) { console.error('portal history PDF error:', error); res.status(503).json({ ok: false, error: 'No se pudo exportar el historial.' }); }
  });
  router.get('/summary', async (req, res) => {
    try {
      const user: Profile = (req as any).portal;
      if (user.role === 'guard') return res.json({ ok: true });
      if (user.role === 'member') {
        const state = (await db.ref(`accessState/${user.id}`).get()).val();
        return res.json({ ok: true, inside: state?.inside === true, lastTimestamp: state?.lastTimestamp || null });
      }
      const snapshot = (await db.ref('accessState').get()).val() || {};
      res.json({ ok: true, insideCount: Object.values(snapshot).filter((v: any) => v.inside === true).length });
    } catch { res.status(503).json({ ok: false, error: 'No se pudo cargar el resumen.' }); }
  });
  router.get('/guard/shift', async (req, res) => {
    const user: Profile = (req as any).portal;
    if (user.role !== 'guard') return res.status(403).json({ ok: false, error: 'Solo guardias pueden consultar su turno.' });
    try {
      const snapshot = await db.ref('guardShifts').get();
      const active = Object.entries(snapshot.val() || {})
        .map(([id, value]: [string, any]) => ({ id, ...(value || {}) }))
        .filter(value => value.guardId === user.id && value.active !== false && !value.endTimestamp)
        .sort((a, b) => Number(b.startTimestamp || 0) - Number(a.startTimestamp || 0))[0] || null;
      res.json({ ok: true, active: Boolean(active), shift: active });
    } catch { res.status(503).json({ ok: false, error: 'No se pudo consultar el turno.' }); }
  });
  router.post('/guard/shift/start', async (req, res) => {
    const user: Profile = (req as any).portal;
    if (user.role !== 'guard') return res.status(403).json({ ok: false, error: 'Solo guardias pueden iniciar turno.' });
    try {
      const shift = await startShift(db, user.id, user.uid, String(req.body?.notes || ''));
      if (!shift) return res.status(409).json({ ok: false, error: 'Ya tienes un turno activo.' });
      res.status(201).json({ ok: true, active: true, shift });
    } catch { res.status(503).json({ ok: false, error: 'No se pudo iniciar el turno.' }); }
  });
  router.post('/guard/shift/end', async (req, res) => {
    const user: Profile = (req as any).portal;
    if (user.role !== 'guard') return res.status(403).json({ ok: false, error: 'Solo guardias pueden finalizar turno.' });
    try {
      const snapshot = await db.ref('guardShifts').get();
      const active = Object.entries(snapshot.val() || {})
        .map(([id, value]: [string, any]) => ({ id, ...(value || {}) }))
        .filter(value => value.guardId === user.id && value.active !== false && !value.endTimestamp)
        .sort((a, b) => Number(b.startTimestamp || 0) - Number(a.startTimestamp || 0))[0];
      if (!active) return res.status(404).json({ ok: false, error: 'No tienes un turno activo.' });
      const endTimestamp = Date.now();
      await db.ref(`guardShifts/${active.id}`).update({ endTimestamp, active: false, endedBy: user.uid, notes: String(req.body?.notes || active.notes || '').slice(0, 500) || null });
      res.json({ ok: true, active: false, shift: { ...active, endTimestamp, active: false } });
    } catch { res.status(503).json({ ok: false, error: 'No se pudo finalizar el turno.' }); }
  });
  router.get('/qr', async (req, res) => {
    const user: Profile = (req as any).portal;
    if (user.role !== 'member') return res.status(403).json({ ok: false, error: 'Esta opcion corresponde a usuarios con credencial.' });
    try { res.json({ ok: true, ...await qr(user.id) }); }
    catch { res.status(503).json({ ok: false, error: 'No se pudo generar el QR.' }); }
  });
  router.get('/student-qr/:id', async (req, res) => {
    const user: Profile = (req as any).portal;
    if (user.role !== 'admin') return res.status(403).json({ ok: false, error: 'Solo administradores pueden consultar credenciales.' });
    const id = String(req.params.id || '').trim();
    if (!id || /[.#$\[\]/]/.test(id)) return res.status(400).json({ ok: false, error: 'Identificador invalido.' });
    try {
      const student = (await db.ref(`students/${id}`).get()).val();
      if (!student) return res.status(404).json({ ok: false, error: 'Estudiante no encontrado.' });
      res.json({ ok: true, id, name: student.name || id, ...await qr(id) });
    } catch { res.status(503).json({ ok: false, error: 'No se pudo generar el QR.' }); }
  });
  router.post('/qr/status', async (req, res) => {
    const user: Profile = (req as any).portal;
    if (user.role !== 'member') return res.sendStatus(403);
    const token = req.body?.token;
    if (typeof token !== 'string' || token.length > 4096) return res.status(400).json({ ok: false, error: 'QR invalido' });
    try { res.json({ ok: true, ...await qrStatus(user.id, token) }); }
    catch { res.status(503).json({ ok: false, error: 'No se pudo consultar el QR.' }); }
  });
  app.use('/portal', router);
}
