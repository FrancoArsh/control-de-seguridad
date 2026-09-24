import admin from 'firebase-admin';
import dotenv from 'dotenv';
import fs from 'node:fs';
import assert from 'node:assert/strict';
import bcrypt from 'bcrypt';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

dotenv.config();
const password = process.env.QA_PASSWORD;
const pin = process.env.QA_GUARD_PIN;
if (!password || !pin) throw new Error('Configura QA_PASSWORD y QA_GUARD_PIN para las cuentas QA existentes.');
const port = process.env.QA_PORT || '3127';
const baseUrl = `http://127.0.0.1:${port}`;
const serviceAccount = JSON.parse(fs.readFileSync(new URL('../serviceAccountKey.json', import.meta.url), 'utf8'));
admin.initializeApp({ credential: admin.credential.cert(serviceAccount), databaseURL: process.env.FIREBASE_DATABASE_URL });
const db = admin.database();
const server = spawn(process.execPath, ['dist/server.js'], { env: { ...process.env, PORT: port }, stdio: 'ignore' });
const closed = new Promise(resolve => server.once('exit', resolve));
const cookies = [];
const evidence = [];

async function prepareQaAccounts() {
  await db.ref('guards/qa-guard-qr').set({ name: 'Guard de QA QR', pinHash: await bcrypt.hash(pin, 10), active: true, createdAt: Date.now() });
  for (let i = 1; i <= 5; i++) {
    const suffix = String(i).padStart(3, '0');
    const id = `demo-qr-${suffix}`;
    const email = `qr.demo.${suffix}@controlseguridad.test`;
    let record;
    try { record = await admin.auth().getUserByEmail(email); }
    catch { record = await admin.auth().createUser({ email, password, displayName: `Usuario QA QR ${i}` }); }
    await admin.auth().updateUser(record.uid, { password, displayName: `Usuario QA QR ${i}`, disabled: false });
    await db.ref(`students/${id}`).set({ name: `Usuario QA QR ${i}`, role: 'estudiante', email, authUid: record.uid, active: true, createdAt: Date.now() });
    await db.ref(`portalProfiles/${record.uid}`).set({ id, role: 'member', active: true });
  }
}

async function request(path, body, headers = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'content-type': 'application/json', 'x-portal-request': '1', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000)
  });
  return { status: response.status, body: await response.json(), cookie: response.headers.get('set-cookie')?.split(';')[0] };
}
try {
  await prepareQaAccounts();
  for (let i = 0; i < 40; i++) {
    try { if ((await request('/health')).status === 200) break; } catch {}
    if (i === 39) throw new Error('El servidor de QA no inicio.');
    await delay(250);
  }
  const guard = await request('/guard/login', { guardId: 'qa-guard-qr', pin });
  assert.equal(guard.status, 200, 'Login guardia QA');
  const authorization = { authorization: `Bearer ${guard.body.token}` };
  for (let i = 1; i <= 5; i++) {
    const suffix = String(i).padStart(3, '0');
    const id = `demo-qr-${suffix}`;
    const email = `qr.demo.${suffix}@controlseguridad.test`;
    const login = await request('/portal/login', { email, password });
    assert.equal(login.status, 200, `Login de ${id}`);
    assert.equal(login.body.user.id, id);
    const headers = { cookie: login.cookie };
    cookies.push(headers);
    const generate = async () => {
      const value = await request('/portal/qr', undefined, headers);
      assert.equal(value.status, 200);
      assert.match(value.body.qrDataUrl, /^data:image\/png;base64,/);
      return value.body;
    };
    const validate = (qr, type) => request('/validate', { qr: qr.token, type, sessionId: 'qa-qr-single-use' }, authorization);
    const status = qr => request('/portal/qr/status', { token: qr.token }, headers);
    let state = (await db.ref(`accessState/${id}`).get()).val();
    const cooldown = Math.max(0, Number(state?.lastTimestamp || 0) + 16000 - Date.now());
    if (cooldown) await delay(cooldown);
    if (state?.inside) {
      assert.equal((await validate(await generate(), 'exit')).status, 200, 'Salida de recuperacion');
      await delay(16000);
    }
    const first = await generate();
    assert.equal((await status(first)).body.renew, false);
    const accepted = await validate(first, 'entry');
    assert.equal(accepted.status, 200);
    assert.equal(accepted.body.inside, true);
    assert.equal((await db.ref(`accessState/${id}/inside`).get()).val(), true);
    const replay = await validate(first, 'entry');
    assert.equal(replay.status, 409);
    assert.equal(replay.body.reason, 'qr already used');
    assert.equal((await status(first)).body.renew, true);
    const second = await generate();
    assert.notEqual(first.token, second.token);
    assert.notEqual(first.qrDataUrl, second.qrDataUrl);
    await delay(16000);
    const lateReplay = await validate(first, 'exit');
    assert.equal(lateReplay.status, 409);
    assert.equal(lateReplay.body.reason, 'qr already used');
    assert.equal((await db.ref(`accessState/${id}/inside`).get()).val(), true);
    const exit = await validate(second, 'exit');
    assert.equal(exit.status, 200, `Salida explicita de ${id}: ${exit.body.error || ''}`);
    assert.equal(exit.body.inside, false);
    assert.equal((await db.ref(`accessState/${id}/inside`).get()).val(), false);
    assert.equal((await status(second)).body.renew, true);
    const exitReplay = await validate(second, 'exit');
    assert.equal(exitReplay.status, 409);
    const fresh = await generate();
    assert.notEqual(fresh.token, second.token);
    assert.equal((await status(fresh)).body.renew, false);
    evidence.push({ id, email, login: 200, entry: 200, replay: 409, replayAfterCooldown: 409, renewedExit: 200, exitReplay: 409, finalInside: false, freshQr: true });
    console.log(`${id}: login, entrada, rechazo de reutilizacion, renovacion y salida OK`);
  }
  const report = { ok: true, project: serviceAccount.project_id, completedAt: new Date().toISOString(), evidence };
  fs.writeFileSync(new URL('../docs/qa-qr-evidence.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
} finally {
  for (const headers of cookies) await request('/portal/logout', {}, headers).catch(() => {});
  server.kill();
  await closed;
  await admin.app().delete();
}
