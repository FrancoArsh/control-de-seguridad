// create-admin-from-email.js (acepta ruta opcional al serviceAccount)
const fs = require('fs');
const path = require('path');
const { initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getDatabase } = require('firebase-admin/database');

console.log('=== create-admin-from-email (flexible) ===');
console.log('cwd:', process.cwd());

const args = process.argv.slice(2);
if (args.length < 1) {
  console.error('USO: node create-admin-from-email.js <email> [displayName] [serviceAccountPath]');
  process.exit(1);
}
const email = args[0];
const displayName = args[1] || '';
const saArg = args[2] || '../serviceAccountKey.json'; // por defecto busca en backend/

const saPath = path.resolve(saArg);
console.log('Using serviceAccount path:', saPath);
if (!fs.existsSync(saPath)) {
  console.error('ERROR: serviceAccountKey.json NO encontrado en la ruta:', saPath);
  process.exit(1);
}

const sa = JSON.parse(fs.readFileSync(saPath, 'utf8'));

try {
  initializeApp({
    credential: cert(sa),
    databaseURL: "https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com"
  });
} catch (e) {
  console.error('ERROR initializing admin SDK:', e);
  process.exit(2);
}

const auth = getAuth();
const db = getDatabase();

(async function() {
  try {
    console.log('-> buscando usuario por email:', email);
    let userRecord;
    try {
      userRecord = await auth.getUserByEmail(email);
      console.log('-> usuario encontrado. UID =', userRecord.uid);
    } catch (err) {
      console.log('-> usuario no encontrado en Auth. Creando nuevo...');
      const tempPass = Math.random().toString(36).slice(2, 10) + Math.random().toString(36).slice(2, 6);
      userRecord = await auth.createUser({
        email,
        password: tempPass,
        displayName: displayName || undefined,
      });
      console.log('-> usuario creado. UID =', userRecord.uid);
      console.log('-> contraseña temporal:', tempPass);
    }

    const uid = userRecord.uid;
    console.log('-> comprobando /admins/' + uid);
    const adminRef = db.ref(`admins/${uid}`);
    const snap = await adminRef.once('value');
    if (snap.exists()) {
      console.log('-> Perfil admin ya existe en DB. Valor:', snap.val());
    } else {
      const profile = {
        name: displayName || userRecord.displayName || null,
        email: userRecord.email || email,
        role: 'admin',
        createdAt: Date.now()
      };
      await adminRef.set(profile);
      console.log('-> Perfil admin creado en Realtime DB en /admins/' + uid);
      console.log('-> perfil:', profile);
    }
    console.log('--- FIN ---');
    process.exit(0);
  } catch (err) {
    console.error('ERROR inesperado:', err);
    process.exit(3);
  }
})();
