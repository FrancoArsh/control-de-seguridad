const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

const SERVICE_ACCOUNT = path.resolve(__dirname, '../serviceAccountKey.json');
let serviceAccount = null;
try {
  serviceAccount = JSON.parse(fs.readFileSync(SERVICE_ACCOUNT, 'utf8'));
} catch (e) {
  console.error('No se encontró serviceAccountKey.json. Colócalo en backend/ para usar este script.');
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL || 'https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/'
});

const db = admin.database();
async function createToken(tokenId = 'test-token', studentUid = 'estudiante-001', ttlMs = 1000*60*60*24*365) {
  const now = Date.now();
  const payload = {
    studentUid,
    createdAt: now,
    expiresAt: now + ttlMs,
    used: false,
    deviceId: 'door-1'
  };
  await db.ref(`tokens/${tokenId}`).set(payload);
  console.log('Token creado:', tokenId);
  process.exit(0);
}

createToken(...process.argv.slice(2)).catch(err => { console.error(err); process.exit(1); });
