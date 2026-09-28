import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import bcrypt from "bcrypt";
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
let seedApp;
let portalCookie = "";

async function waitForHealth() {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/health`);
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
    ...options,
    headers: { "content-type": "application/json", ...(options.headers || {}) }
  });
  return { response, body: await response.json() };
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
  if (!process.env.FIREBASE_DATABASE_EMULATOR_HOST) {
    process.env.FIREBASE_DATABASE_EMULATOR_HOST = emulatorHost;
  }
  process.env.FIREBASE_AUTH_EMULATOR_HOST = process.env.FIREBASE_AUTH_EMULATOR_HOST || "127.0.0.1:9099";

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
      NODE_ENV: "test",
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
  await waitForHealth();
});

after(async () => {
  if (server) server.kill();
  if (seedApp) await deleteApp(seedApp);
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
  assert.equal(results.filter(({ body }) => body.ok === true).length, 1);
  assert.equal(results.filter(({ body }) => body.ok !== true).length, 1);
  const state = (await seedDb.ref("accessState/stu-001").once("value")).val();
  assert.equal(state.inside, false);
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
  assert.equal(presence.response.status, 200);

  const users = await portalRequest("/portal/users");
  assert.equal(users.response.status, 200);
  assert.ok(users.body.data.some(user => user.role === "guard"));

  const created = await portalRequest("/portal/users", {
    method: "POST",
    body: JSON.stringify({ name: "Miembro de Integración", email: "member.integration@example.test", password: "IntegrationPass123!", role: "member" })
  });
  assert.equal(created.response.status, 201);
  assert.equal(created.body.user.role, "member");

  const disabled = await portalRequest(`/portal/users/${created.body.user.uid}`, {
    method: "PATCH",
    body: JSON.stringify({ active: false })
  });
  assert.equal(disabled.response.status, 200);
  assert.equal(disabled.body.active, false);

  const logout = await portalRequest("/portal/logout", { method: "POST", body: "{}" });
  assert.equal(logout.response.status, 200);
  const afterLogout = await portalRequest("/portal/me");
  assert.equal(afterLogout.response.status, 401);
});
