import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import bcrypt from "bcrypt";
import { initializeApp, deleteApp } from "firebase-admin/app";
import { getDatabase } from "firebase-admin/database";

const root = path.resolve(import.meta.dirname, "..");
const projectId = process.env.GCLOUD_PROJECT || "control-de-seguridad-test";
const emulatorHost = process.env.FIREBASE_DATABASE_EMULATOR_HOST || "127.0.0.1:9000";
const databaseUrl = `http://${emulatorHost}?ns=${projectId}`;
const port = Number(process.env.INTEGRATION_PORT || 3101);
const baseUrl = `http://127.0.0.1:${port}`;
let server;
let seedApp;

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

before(async () => {
  if (!process.env.FIREBASE_DATABASE_EMULATOR_HOST) {
    process.env.FIREBASE_DATABASE_EMULATOR_HOST = emulatorHost;
  }

  seedApp = initializeApp({ projectId, databaseURL: databaseUrl }, "integration-seed");
  const seedDb = getDatabase(seedApp);
  const guardPinHash = await bcrypt.hash("1234", 4);
  await seedDb.ref().set({
    students: {
      "stu-001": { name: "Estudiante de Integración", role: "estudiante" }
    },
    accessTokens: {
      "stu-001": { token: "integration-static-token", createdAt: Date.now() }
    },
    guards: {
      "guard-001": { name: "Guardia de Integración", pinHash: guardPinHash }
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
  const results = await Promise.all([
    request("/validate", {
      method: "POST",
      body: JSON.stringify({ qr: "integration-static-token", type: "auto", sessionId: "integration" })
    }),
    request("/validate", {
      method: "POST",
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

test("expone presencia protegida y permite consultarla a un guardia autenticado", async () => {
  const login = await request("/guard/login", {
    method: "POST",
    body: JSON.stringify({ guardId: "guard-001", pin: "1234" })
  });
  assert.equal(login.body.ok, true);

  const presence = await request("/presence", {
    headers: { authorization: `Bearer ${login.body.token}` }
  });
  assert.equal(presence.response.status, 200);
  assert.equal(presence.body.count, 1);
  assert.equal(presence.body.data[0].id, "stu-001");
});
