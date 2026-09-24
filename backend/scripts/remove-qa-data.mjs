import admin from 'firebase-admin';
import dotenv from 'dotenv';
import fs from 'node:fs';

dotenv.config();
const serviceAccount = JSON.parse(fs.readFileSync(new URL('../serviceAccountKey.json', import.meta.url), 'utf8'));
admin.initializeApp({ credential: admin.credential.cert(serviceAccount), databaseURL: process.env.FIREBASE_DATABASE_URL });
const db = admin.database();
const ids = new Set(['demo-qr-001', 'demo-qr-002', 'demo-qr-003', 'demo-qr-004', 'demo-qr-005']);
const emails = new Set(['qr.demo.001@controlseguridad.test', 'qr.demo.002@controlseguridad.test', 'qr.demo.003@controlseguridad.test', 'qr.demo.004@controlseguridad.test', 'qr.demo.005@controlseguridad.test']);
const authUsers = [];
let page;
do {
  page = await admin.auth().listUsers(1000, page?.pageToken);
  for (const user of page.users) if (emails.has(user.email || '')) authUsers.push(user);
} while (page.pageToken);
for (const user of authUsers) await admin.auth().deleteUser(user.uid);

const root = await db.ref().get();
const data = root.val() || {};
const updates = {};
for (const key of ids) {
  for (const collection of ['students', 'accessTokens', 'accessState']) updates[`${collection}/${key}`] = null;
}
updates['guards/qa-guard-qr'] = null;
for (const [uid, value] of Object.entries(data.portalProfiles || {})) {
  if (value?.id && ids.has(value.id)) updates[`portalProfiles/${uid}`] = null;
}
for (const [key, value] of Object.entries(data.accessHistory || {})) {
  if (ids.has(value?.id) || value?.sessionId === 'qa-qr-single-use') updates[`accessHistory/${key}`] = null;
}
for (const [key, value] of Object.entries(data.attendance || {})) {
  if (key === 'qa-qr-single-use') updates[`attendance/${key}`] = null;
}
for (const [key, value] of Object.entries(data.dynamicQrNonces || {})) {
  if (ids.has(value?.userId)) updates[`dynamicQrNonces/${key}`] = null;
}
for (const [key, value] of Object.entries(data.portalSessions || {})) {
  if (ids.has(value?.id) || value?.role === 'member' && !value?.id) updates[`portalSessions/${key}`] = null;
}
await db.ref().update(updates);
console.log(JSON.stringify({ ok: true, deletedAuthUsers: authUsers.map(user => user.email), removedDatabasePaths: Object.keys(updates).length }, null, 2));
await admin.app().delete();
