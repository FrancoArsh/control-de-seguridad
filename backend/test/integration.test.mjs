import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import bcrypt from "bcrypt";
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { initializeApp, deleteApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getDatabase } from "firebase-admin/database";

const root = path.resolve(import.meta.dirname, "..");
const projectId = process.env.GCLOUD_PROJECT || "control-de-seguridad-test";
const emulatorHost = process.env.FIREBASE_DATABASE_EMULATOR_HOST || "127.0.0.1:9000";
const databaseUrl = `http://${emulatorHost}?ns=${projectId}`;
const port = Number(process.env.INTEGRATION_PORT || 3101);
const baseUrl = `http://127.0.0.1:${port}`;
let server;
let serverErrors = '';
let seedApp;
let portalCookie = "";

async function waitForHealth() {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(2000) });
      if (response.ok) return;
    } catch (_) {
      // El proceso todavía puede estar iniciando.
    }
    await delay(250);
  }
  throw new Error("El backend no respondió /health. ¿Está activo Firebase Emulator?");
}

async function request(pathname, options = {}) {
  const response = await fetch(`${baseUrl}${pathname}`, {
    signal: AbortSignal.timeout(15000),
    ...options,
    headers: { "content-type": "application/json", ...(options.headers || {}) }
  });
  const body = await response.json();
  if (response.status >= 500) console.error('Emulator backend diagnostic:', serverErrors);
  return { response, body };
}

async function portalRequest(pathname, options = {}) {
  const result = await request(pathname, {
    ...options,
    headers: { ...(options.headers || {}), "x-portal-request": "1", ...(portalCookie ? { cookie: portalCookie } : {}) }
  });
  const setCookie = result.response.headers.get("set-cookie");
  if (setCookie) portalCookie = setCookie.split(";")[0];
  return result;
}

before(async () => {
  assert.match(projectId, /^demo-/, 'Integration tests require a demo project, never a live project');
  assert.match(emulatorHost, /^(127\.0\.0\.1|localhost):\d+$/);
  if (!process.env.FIREBASE_DATABASE_EMULATOR_HOST) {
    process.env.FIREBASE_DATABASE_EMULATOR_HOST = emulatorHost;
  }
  process.env.FIREBASE_AUTH_EMULATOR_HOST = process.env.FIREBASE_AUTH_EMULATOR_HOST || "127.0.0.1:9099";
  assert.match(process.env.FIREBASE_AUTH_EMULATOR_HOST, /^(127\.0\.0\.1|localhost):\d+$/);

  const rules = await fetch(`http://${emulatorHost}/.settings/rules.json?ns=${projectId}`, {
    method: 'PUT', headers: { Authorization: 'Bearer owner', 'Content-Type': 'application/json' },
    body: await fs.readFile(path.join(root, 'database.rules.json'), 'utf8')
  });
  assert.equal(rules.status, 200);

  seedApp = initializeApp({ projectId, databaseURL: databaseUrl }, "integration-seed");
  const seedDb = getDatabase(seedApp);
  const seedAuth = getAuth(seedApp);
  const guardAuth = await seedAuth.createUser({ email: "guard.integration@example.test", password: "IntegrationPass123!" });
  const adminAuth = await seedAuth.createUser({ email: "admin.integration@example.test", password: "IntegrationPass123!" });
  const guardPinHash = await bcrypt.hash("1234", 4);
  await seedDb.ref().set({
    students: {
      "stu-001": { name: "Estudiante de Integración", role: "estudiante" }
    },
    accessTokens: {
      "stu-001": { token: "integration-static-token", createdAt: Date.now() }
    },
    guards: {
      "guard-001": { name: "Guardia de Integración", pinHash: guardPinHash, authUid: guardAuth.uid, active: true }
    },
    admins: {
      [adminAuth.uid]: { name: "Administrador de Integración", email: "admin.integration@example.test", role: "admin", active: true }
    },
    portalProfiles: {
      [guardAuth.uid]: { id: "guard-001", role: "guard", active: true }
    }
  });

  server = spawn(process.execPath, [path.join(root, "dist", "server.js")], {
    cwd: root,
    env: {
      ...process.env,
      ENV_FILE: path.join(root, 'test', 'nonexistent-test.env'),
      FIREBASE_SERVICE_ACCOUNT: '', SERVICE_ACCOUNT_JSON: '', SERVICE_ACCOUNT_JSON_BASE64: '',
      APP_ENV: 'test',
      NODE_ENV: "test",
      ALLOW_LEGACY_STATIC_QR: 'true',
      PORT: String(port),
      ADMIN_SECRET: "integration-admin-secret",
      JWT_SECRET: "integration-jwt-secret",
      QR_SECRET: "integration-qr-secret",
      FIREBASE_DATABASE_URL: databaseUrl,
      FIREBASE_DATABASE_EMULATOR_HOST: emulatorHost,
      FIREBASE_AUTH_EMULATOR_HOST: process.env.FIREBASE_AUTH_EMULATOR_HOST,
      GCLOUD_PROJECT: projectId,
      GOOGLE_CLOUD_PROJECT: projectId
    },
    stdio: "pipe"
  });
  server.stderr.on('data', chunk => { serverErrors = (serverErrors + chunk.toString()).slice(-8000); });
  server.stdout.resume();
  await waitForHealth();
});

after(async () => {
  if (server) server.kill();
  if (seedApp) await deleteApp(seedApp);
});

async function loginAs(email) {
  const result = await request('/portal/login', { method: 'POST', headers: { 'x-portal-request': '1' }, body: JSON.stringify({ email, password: 'IntegrationPass123!' }) });
  assert.equal(result.response.status, 200, JSON.stringify(result.body));
  return { cookie: result.response.headers.get('set-cookie').split(';')[0], 'x-portal-request': '1' };
}

function signedQr(id, options = {}) {
  const issuedAt = Date.now();
  const payload = { v: 2, purpose: 'access', sub: id, iat: issuedAt, exp: issuedAt + 60000, nonce: crypto.randomBytes(16).toString('hex'), ...options };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${encoded}.${crypto.createHmac('sha256', 'integration-qr-secret').update(encoded).digest('base64url')}`;
}

async function validate(headers, qr, type = 'entry') {
  return request('/validate', { method: 'POST', headers, body: JSON.stringify({ qr, type }) });
}

test('QR dinamico: concurrencia, replay, salida y auditoria', async () => {
  const db = getDatabase(seedApp);
  await db.ref('students/dynamic-person').set({ name: 'Persona QR', active: true });
  const headers = await loginAs('guard.integration@example.test');
  await request('/portal/guard/shift/start', { method: 'POST', headers, body: '{}' });
  const qr = signedQr('dynamic-person');
  const results = await Promise.all(Array.from({ length: 6 }, () => validate(headers, qr)));
  assert.equal(results.filter(r => r.body.ok === true).length, 1);
  assert.equal(results.filter(r => r.body.reason === 'qr already used').length, 5, JSON.stringify(results.map(r => r.body)));
  assert.equal((await db.ref('accessState/dynamic-person').get()).val().inside, true);
  const replay = await validate(headers, qr);
  assert.equal(replay.response.status, 409);
  for (let attempt = 0; attempt < 10; attempt++) {
    assert.equal((await validate(headers, qr)).response.status, 409, serverErrors);
  }
  await db.ref('accessState/dynamic-person/lastTimestamp').set(0);
  await db.ref('students/dynamic-person/lastAccessTimestamp').set(0);
  const exits = await Promise.all(Array.from({ length: 6 }, () => validate(headers, signedQr('dynamic-person'), 'exit')));
  assert.ok(exits.every(r => r.response.status === 400));
  assert.equal((await validate(headers, signedQr('dynamic-person'), 'auto')).body.accessType, 'entry');
  assert.equal((await db.ref('accessState/dynamic-person').get()).val().inside, true);
  const history = Object.values((await db.ref('accessHistory').get()).val() || {}).filter(row => row.id === 'dynamic-person');
  assert.equal(history.filter(row => row.authorized).length, 2);
  for (const row of history) {
    assert.ok(row.validatedById);
    assert.equal(row.validatedByRole, 'guard');
    assert.ok(row.timestamp && row.reason);
    assert.equal(row.token, undefined);
  }
});

test('rechaza QR vencido, adulterado, futuro, desactivado y peticion sin token', async () => {
  const headers = await loginAs('guard.integration@example.test');
  const now = Date.now();
  const expired = signedQr('dynamic-person', { iat: now - 60001, exp: now - 1 });
  assert.equal((await validate(headers, expired)).body.reason, 'qr expired');
  assert.equal((await validate(headers, signedQr('dynamic-person') + 'x')).body.reason, 'invalid qr signature');
  assert.equal((await validate(headers, signedQr('dynamic-person', { iat: now + 30000, exp: now + 60000 }))).body.reason, 'invalid qr lifetime');
  assert.equal((await validate(headers, '')).response.status, 400);
  const db = getDatabase(seedApp);
  await db.ref('students/dynamic-person/active').set(false);
  assert.equal((await validate(headers, signedQr('dynamic-person'))).response.status, 403, serverErrors);
  await db.ref('students/dynamic-person/active').set(true);
  const rows = Object.values((await db.ref('accessHistory').get()).val() || {});
  for (const reason of ['qr expired', 'invalid qr signature', 'invalid qr lifetime', 'token required', 'user disabled']) {
    const row = rows.find(r => r.reason === reason);
    assert.ok(row, reason);
    assert.ok(row.validatedById, reason);
    assert.equal(row.authorized, false);
  }
});

test('inicio de turno unico incluso mezclando portal y JWT; fuera de turno y desactivacion', async () => {
  const db = getDatabase(seedApp);
  const headers = await loginAs('guard.integration@example.test');
  const jwtLogin = await request('/guard/login', { method: 'POST', body: JSON.stringify({ guardId: 'guard-001', pin: '1234' }) });
  assert.equal(jwtLogin.body.ok, true);
  const bearer = { authorization: `Bearer ${jwtLogin.body.token}` };
  await request('/portal/guard/shift/end', { method: 'POST', headers, body: '{}' });
  for (const h of [headers, bearer]) assert.equal((await validate(h, signedQr('dynamic-person'))).body.reason, 'GUARD_NOT_ON_SHIFT');
  const results = await Promise.all(Array.from({ length: 8 }, (_, i) => request(i % 2 ? '/portal/guard/shift/start' : '/guard/shift/start', { method: 'POST', headers: i % 2 ? headers : bearer, body: '{}' })));
  assert.equal(results.filter(r => r.body.ok === true).length, 1);
  const shifts = Object.values((await db.ref('guardShifts').get()).val() || {});
  assert.equal(shifts.filter(s => s.guardId === 'guard-001' && s.active !== false && !s.endTimestamp).length, 1);
  assert.equal((await request('/guard/authorize', { method: 'POST', headers: bearer, body: '{}' })).response.status, 410);
  await db.ref('guards/guard-001/active').set(false);
  for (const h of [headers, bearer]) assert.ok([401, 403].includes((await validate(h, signedQr('dynamic-person'))).response.status));
  assert.equal((await request('/guard/login', { method: 'POST', body: JSON.stringify({ guardId: 'guard-001', pin: '1234' }) })).response.status, 403);
  await db.ref('guards/guard-001/active').set(true);
  const uid = (await db.ref('guards/guard-001/authUid').get()).val();
  await getAuth(seedApp).updateUser(uid, { disabled: true });
  assert.equal((await validate(bearer, signedQr('dynamic-person'))).response.status, 403);
  await getAuth(seedApp).updateUser(uid, { disabled: false });
});

test('estudiante y profesor: aislamiento de QR, historial, administracion y renovacion', async () => {
  const db = getDatabase(seedApp);
  for (const kind of ['student', 'teacher']) {
    const email = `${kind}.roles@example.test`;
    const user = await getAuth(seedApp).createUser({ email, password: 'IntegrationPass123!' });
    await db.ref(`students/${user.uid}`).set({ name: kind, active: true, tipoUsuario: kind });
    const headers = await loginAs(email);
    for (const route of ['/portal/users', '/portal/guards', '/presence', '/portal/student-qr/stu-001']) {
      assert.equal((await request(route, { headers })).response.status, 403, route);
    }
    assert.equal((await request(`/portal/users/member/${user.uid}/profile`, { method: 'PATCH', headers, body: JSON.stringify({ name: 'Forbidden' }) })).response.status, 403);
    assert.equal((await validate(headers, signedQr(user.uid))).response.status, 403);
    const qr = await request('/portal/qr', { headers });
    assert.equal(qr.response.status, 200);
    assert.equal(JSON.parse(Buffer.from(qr.body.token.split('.')[0], 'base64url')).sub, user.uid);
    const guard = await loginAs('guard.integration@example.test');
    assert.equal((await validate(guard, qr.body.token)).response.status, 200);
    const status = await request('/portal/qr/status', { method: 'POST', headers, body: JSON.stringify({ token: qr.body.token }) });
    assert.equal(status.body.renew, true);
    const renewed = await request('/portal/qr', { headers });
    assert.notEqual(renewed.body.token, qr.body.token);
    const history = await request('/portal/history', { headers });
    assert.equal(history.response.status, 403);
    await getAuth(seedApp).updateUser(user.uid, { disabled: true });
    assert.equal((await request('/portal/qr', { headers })).response.status, 401);
  }
});

test("valida concurrencia y deja una sola persona dentro", async () => {
  const login = await request("/guard/login", {
    method: "POST",
    body: JSON.stringify({ guardId: "guard-001", pin: "1234" })
  });
  assert.equal(login.body.ok, true);
  await request('/guard/shift/start', { method: 'POST', headers: { authorization: `Bearer ${login.body.token}` }, body: '{}' });
  const authorization = { authorization: `Bearer ${login.body.token}` };
  const results = await Promise.all([
    request("/validate", {
      method: "POST",
      headers: authorization,
      body: JSON.stringify({ qr: "integration-static-token", type: "auto", sessionId: "integration" })
    }),
    request("/validate", {
      method: "POST",
      headers: authorization,
      body: JSON.stringify({ qr: "integration-static-token", type: "auto", sessionId: "integration" })
    })
  ]);

  assert.equal(results.filter(({ body }) => body.ok === true).length, 1);
  assert.equal(results.filter(({ body }) => body.ok !== true).length, 1);
  assert.ok(results.some(({ response }) => [403, 409].includes(response.status)));

  const seedDb = getDatabase(seedApp);
  const state = (await seedDb.ref("accessState/stu-001").once("value")).val();
  assert.equal(state.inside, true);
  assert.equal(state.lastAccessType, "entry");
});

test('serializa entrada y salida simultaneas con nonces distintos', async () => {
  const db = getDatabase(seedApp);
  await db.ref('accessState/stu-001').set({ inside: false, lastTimestamp: 0, lastAccessType: null });
  await db.ref('students/stu-001/lastAccessTimestamp').set(0);
  const headers = await loginAs('guard.integration@example.test');
  const startedAt = Date.now();
  const [entry, exit] = await Promise.all([
    validate(headers, signedQr('stu-001'), 'entry'),
    validate(headers, signedQr('stu-001'), 'exit')
  ]);
  assert.equal([entry, exit].filter(result => result.body.ok === true).length, 1);
  assert.equal([entry, exit].filter(result => result.body.ok !== true).length, 1);
  assert.equal((await db.ref('accessState/stu-001/inside').get()).val(), true);
  const events = Object.values((await db.ref('accessHistory').get()).val() || {})
    .filter(row => row.studentUid === 'stu-001' && row.authorized === true && row.timestamp >= startedAt);
  assert.equal(events.length, 1);
});

test("impide consultar presencia a un guardia autenticado", async () => {
  const login = await request("/guard/login", {
    method: "POST",
    body: JSON.stringify({ guardId: "guard-001", pin: "1234" })
  });
  assert.equal(login.body.ok, true);

  const presence = await request("/presence", {
    headers: { authorization: `Bearer ${login.body.token}` }
  });
  assert.ok([401, 403].includes(presence.response.status));
});

test('aísla las operaciones del portal por rol y revoca una sesión desactivada', async () => {
  const db = getDatabase(seedApp);
  const auth = getAuth(seedApp);
  const member = await auth.createUser({ email: 'member.permissions@example.test', password: 'IntegrationPass123!' });
  await db.ref(`students/${member.uid}`).set({ name: 'Miembro de permisos', active: true, tipoUsuario: 'estudiante' });

  const guard = await loginAs('guard.integration@example.test');
  const memberHeaders = await loginAs('member.permissions@example.test');
  const guardDenied = ['/portal/users', '/portal/guards', '/portal/guard-report', '/portal/student-qr/stu-001', '/presence'];
  for (const route of guardDenied) assert.equal((await request(route, { headers: guard })).response.status, 403, `guard denied ${route}`);
  for (const route of ['/portal/summary', '/portal/history', '/portal/guard/shift']) {
    assert.equal((await request(route, { headers: guard })).response.status, 200, `guard allowed ${route}`);
  }

  const memberDenied = ['/portal/users', '/portal/guards', '/portal/guard-report', '/portal/student-qr/stu-001', '/presence', '/portal/guard/shift'];
  for (const route of memberDenied) assert.equal((await request(route, { headers: memberHeaders })).response.status, 403, `member denied ${route}`);
  for (const route of ['/portal/summary', '/portal/qr']) {
    assert.equal((await request(route, { headers: memberHeaders })).response.status, 200, `member allowed ${route}`);
  }
  assert.equal((await request('/portal/history', { headers: memberHeaders })).response.status, 403, 'member history denied');

  const guardUid = (await db.ref('guards/guard-001/authUid').get()).val();
  await auth.updateUser(guardUid, { disabled: true });
  assert.equal((await request('/portal/me', { headers: guard })).response.status, 401);
  await auth.updateUser(guardUid, { disabled: false });
});

test('mantiene sesiones independientes entre pestañas del portal', async () => {
  const adminLogin = await request('/portal/login', {
    method: 'POST', headers: { 'x-portal-request': '1', 'x-portal-tab': 'tab-admin' },
    body: JSON.stringify({ email: 'admin.integration@example.test', password: 'IntegrationPass123!' })
  });
  const guardLogin = await request('/portal/login', {
    method: 'POST', headers: { 'x-portal-request': '1', 'x-portal-tab': 'tab-guard' },
    body: JSON.stringify({ email: 'guard.integration@example.test', password: 'IntegrationPass123!' })
  });
  assert.equal(adminLogin.response.status, 200);
  assert.equal(guardLogin.response.status, 200);
  const student = await getAuth(seedApp).createUser({ email: 'student.tabs@example.test', password: 'IntegrationPass123!' });
  await getDatabase(seedApp).ref('students/' + student.uid).set({ name: 'Estudiante de prueba', active: true, tipoUsuario: 'estudiante' });
  const studentLogin = await request('/portal/login', {
    method: 'POST', headers: { 'x-portal-request': '1', 'x-portal-tab': 'tab-student' },
    body: JSON.stringify({ email: student.email, password: 'IntegrationPass123!' })
  });
  assert.equal(studentLogin.response.status, 200);
  const cookies = [adminLogin, guardLogin, studentLogin].map(login => {
    const cookie = login.response.headers.get('set-cookie');
    assert.match(cookie, /; HttpOnly/i);
    assert.equal(login.body.sessionToken, undefined);
    return cookie.split(';')[0];
  }).join('; ');
  const adminHeaders = { cookie: cookies, 'x-portal-request': '1', 'x-portal-tab': 'tab-admin' };
  const guardHeaders = { ...adminHeaders, 'x-portal-tab': 'tab-guard' };
  assert.equal((await request('/portal/me', { headers: { ...guardHeaders, 'x-portal-tab': 'tab-new' } })).response.status, 401);
  assert.equal((await request('/portal/me', { headers: adminHeaders })).body.user.role, 'admin');
  assert.equal((await request('/portal/me', { headers: guardHeaders })).body.user.role, 'guard');
  assert.equal((await request('/portal/users', { headers: adminHeaders })).response.status, 200);
  assert.equal((await request('/portal/users', { headers: guardHeaders })).response.status, 403);
  const studentHeaders = { ...adminHeaders, 'x-portal-tab': 'tab-student' };
  assert.equal((await request('/portal/users', { headers: studentHeaders })).response.status, 403);
  const logout = await request('/portal/logout', { method: 'POST', headers: guardHeaders, body: '{}' });
  assert.equal(logout.response.status, 200);
  assert.match(logout.response.headers.get('set-cookie'), /^control_session_tab-guard=;/);
  assert.equal((await request('/portal/me', { headers: guardHeaders })).response.status, 401);
  const qr = await request('/portal/qr', { headers: studentHeaders });
  assert.equal(qr.response.status, 200);
  assert.equal(JSON.parse(Buffer.from(qr.body.token.split('.')[0], 'base64url')).sub, student.uid);
  assert.equal((await request('/portal/users', { headers: adminHeaders })).response.status, 200);
});

test('registra excepciones manuales solo en turno y deja auditoria', async () => {
  const db = getDatabase(seedApp);
  const guard = await loginAs('guard.integration@example.test');
  const id = `manual-person-${Date.now()}`;
  await db.ref(`students/${id}`).set({ name: 'Persona manual', active: true, tipoUsuario: 'visitante' });
  await db.ref('guardShifts/manual-exception-shift').set({ guardId: 'guard-001', active: true, startTimestamp: Date.now() });

  const invalid = await request('/portal/guard/exception', {
    method: 'POST', headers: guard, body: JSON.stringify({ userId: id, type: 'entry', reason: '' })
  });
  assert.equal(invalid.response.status, 400);

  const entry = await request('/portal/guard/exception', {
    method: 'POST', headers: guard, body: JSON.stringify({ userId: id, type: 'entry', reason: 'Visitante sin QR vigente' })
  });
  assert.equal(entry.response.status, 201, JSON.stringify(entry.body));
  assert.equal(entry.body.accessType, 'entry');
  assert.equal((await db.ref(`accessState/${id}/inside`).get()).val(), true);
  const history = Object.values((await db.ref('accessHistory').get()).val() || {}).find(row => row.studentUid === id);
  assert.equal(history.validationMode, 'manual');
  assert.equal(history.reason, 'Visitante sin QR vigente');
  assert.equal(history.token, undefined);
  assert.equal(history.guardId, 'guard-001');
  const audit = Object.values((await db.ref('adminAuditLog').get()).val() || {}).find(row => row.entityId === id);
  assert.equal(audit.action, 'guard.manual_exception');

  const duplicate = await request('/portal/guard/exception', {
    method: 'POST', headers: guard, body: JSON.stringify({ userId: id, type: 'entry', reason: 'Segundo intento' })
  });
  assert.equal(duplicate.response.status, 409);
});

test("valida concurrencia de salida y conserva un unico estado final", async () => {
  const seedDb = getDatabase(seedApp);
  await seedDb.ref("accessState/stu-001").set({ inside: true, lastTimestamp: 0, lastAccessType: "entry" });
  await seedDb.ref("students/stu-001").update({ lastAccessTimestamp: 0 });
  const login = await request("/guard/login", { method: "POST", body: JSON.stringify({ guardId: "guard-001", pin: "1234" }) });
  const authorization = { authorization: `Bearer ${login.body.token}` };
  const results = await Promise.all([1, 2].map(() => request("/validate", {
    method: "POST", headers: authorization,
    body: JSON.stringify({ qr: "integration-static-token", type: "exit", sessionId: "integration-exit" })
  })));
  assert.ok(results.every(r => r.response.status === 400));
  const state = (await seedDb.ref("accessState/stu-001").once("value")).val();
  assert.equal(state.inside, true);
});

test("autentica el portal y aplica la sesion y el rol de administrador", async () => {
  const login = await portalRequest("/portal/login", {
    method: "POST",
    body: JSON.stringify({ email: "admin.integration@example.test", password: "IntegrationPass123!" })
  });
  assert.equal(login.response.status, 200);
  assert.equal(login.body.user.role, "admin");

  const me = await portalRequest("/portal/me");
  assert.equal(me.response.status, 200);
  assert.equal(me.body.user.role, "admin");
  const presence = await portalRequest('/presence');
  assert.equal(presence.response.status, 410);

  const users = await portalRequest("/portal/users");
  assert.equal(users.response.status, 200);
  assert.ok(users.body.data.some(user => user.role === "guard"));

  const created = await portalRequest("/portal/users", {
    method: "POST",
    body: JSON.stringify({ name: "Miembro de Integración", email: "member.integration@example.test", password: "IntegrationPass123!", role: "member" })
  });
  assert.equal(created.response.status, 201);
  assert.equal(created.body.user.role, "member");
  const newStudent = await loginAs('member.integration@example.test');
  const credential = await request('/portal/qr', { headers: newStudent });
  assert.equal(credential.response.status, 200);
  const payload = JSON.parse(Buffer.from(credential.body.token.split('.')[0], 'base64url'));
  assert.equal(payload.sub, created.body.user.id);
  const auditRows = (await getDatabase(seedApp).ref('adminAuditLog').get()).val() || {};
  const creation = Object.values(auditRows).filter(row => row.entityId === payload.sub && row.action === 'portal.user.create');
  assert.equal(creation.length, 1);
  assert.equal(creation[0].actorId, me.body.user.uid);


  const disabled = await portalRequest(`/portal/users/${created.body.user.uid}`, {
    method: "PATCH",
    body: JSON.stringify({ active: false })
  });
  assert.equal(disabled.response.status, 200);
  assert.equal(disabled.body.active, false);

  const db = getDatabase(seedApp);
  const stateRef = db.ref(`accessState/${created.body.user.id}/accessDisabled`);
  assert.equal((await stateRef.get()).val(), true);
  const enabled = await portalRequest(`/portal/users/${created.body.user.uid}`, {
    method: 'PATCH', body: JSON.stringify({ active: true })
  });
  assert.equal(enabled.response.status, 200);
  assert.equal((await stateRef.get()).val(), false);
  await db.ref('guardShifts/admin-race').set({ guardId: 'guard-001', active: true, startTimestamp: Date.now() });
  const closures = await Promise.all(Array.from({ length: 6 }, (_, i) => portalRequest('/admin/guard/shift/end', {
    method: 'POST', body: JSON.stringify({ shiftId: 'admin-race', notes: `winner-${i}` })
  })));
  assert.equal(closures.filter(r => r.response.status === 200).length, 1);
  const closedShift = (await db.ref('guardShifts/admin-race').get()).val();
  assert.equal(closedShift.endedBy, login.body.user.uid);
  const winner = closures.findIndex(r => r.response.status === 200);
  assert.equal(closedShift.notes, `winner-${winner}`);
  const originalGuard = (await db.ref('guards/guard-001').get()).val();
  const overwrite = await portalRequest('/guards/create', {
    method: 'POST', body: JSON.stringify({ id: 'guard-001', name: 'Must not replace', pin: '987654' })
  });
  assert.equal(overwrite.response.status, 409);
  assert.deepEqual((await db.ref('guards/guard-001').get()).val(), originalGuard);

  const logout = await portalRequest("/portal/logout", { method: "POST", body: "{}" });
  assert.equal(logout.response.status, 200);
  const afterLogout = await portalRequest("/portal/me");
  assert.equal(afterLogout.response.status, 401);
});
test('KPI de decisión HTTP en portería con credenciales sintéticas', async () => {
  const db = getDatabase(seedApp);
  const headers = await loginAs('guard.integration@example.test');
  await db.ref('guardShifts/kpi').set({ guardId: 'guard-001', active: true, startTimestamp: Date.now() });
  const ids = Array.from({ length: 30 }, (_, i) => 'kpi-student-' + i);
  await db.ref().update(Object.fromEntries(ids.map(id => ['students/' + id, { active: true, role: 'estudiante' }])));
  const samples = { aprobado: [], rechazado: [] };
  for (const id of ids) {
    const qr = signedQr(id);
    for (const [outcome, expected] of [['aprobado', 200], ['rechazado', 409]]) {
      const start = performance.now();
      const result = await validate(headers, qr);
      samples[outcome].push(performance.now() - start);
      assert.equal(result.response.status, expected);
    }
  }
  for (const [outcome, values] of Object.entries(samples)) {
    values.sort((a, b) => a - b);
    console.log('KPI', outcome, JSON.stringify({ n: values.length, p95Ms: Math.ceil(values[Math.ceil(values.length * .95) - 1]), maxMs: Math.ceil(values.at(-1)), bajoUnSegundo: values.filter(v => v < 1000).length }));
  }
});
