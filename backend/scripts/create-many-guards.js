// backend/scripts/create-many-guards.js
// Uso: node backend/scripts/create-many-guards.js 10
// Crea N guards en RTDB, genera PINs aleatorios, guarda pinHash y exporta guards-created.csv

const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

// Ajusta si tu serviceAccountKey.json está en otra ruta
const KEY_PATH = path.resolve(__dirname, '../serviceAccountKey.json');

if (!fs.existsSync(KEY_PATH)) {
  console.error('ERROR: No encontré serviceAccountKey.json en:', KEY_PATH);
  process.exit(1);
}

// Inicializa Firebase Admin
const serviceAccount = require(KEY_PATH);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL || "https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/"
});

const db = admin.database();

function randomPin(digits = 6) {
  // genera PIN numérico con 'digits' cifras (puede tener ceros a la izquierda)
  const max = 10 ** digits;
  const num = Math.floor(Math.random() * max);
  return String(num).padStart(digits, '0');
}

function niceId(base, idx) {
  // ejemplo: guard-01, guard-02...
  return `${base}-${String(idx).padStart(2, '0')}`;
}

(async () => {
  try {
    const arg = Number(process.argv[2] || 10);
    const count = Number.isInteger(arg) && arg > 0 ? arg : 10;
    console.log(`Creando ${count} guards en Firebase RTDB...`);

    const out = []; // para CSV
    for (let i = 1; i <= count; i++) {
      const id = niceId('guard', i);
      const name = `Guard ${String(i).padStart(2,'0')}`;
      const pin = randomPin(6); // PIN de 6 dígitos, modifica si quieres 4
      const saltRounds = 10;
      const pinHash = await bcrypt.hash(pin, saltRounds);

      // Guardar en RTDB: guards/{id} => { name, pinHash, createdAt }
      await db.ref(`guards/${id}`).set({
        name,
        pinHash,
        createdAt: Date.now()
      });

      out.push({ id, name, pin });
      console.log(`  creado ${id} -> PIN ${pin}`);
    }

    // escribir CSV local para que tengas las credenciales de prueba
    const csvPath = path.resolve(__dirname, '../guards-created.csv');
    const csvHeader = 'id,name,pin\n';
    const csvBody = out.map(r => `${r.id},${r.name},${r.pin}`).join('\n');
    fs.writeFileSync(csvPath, csvHeader + csvBody, 'utf8');
    console.log(`Hecho. Archivo con credenciales: ${csvPath}`);
    console.log('IMPORTANTE: elimina guards-created.csv o guárdalo seguro después de usarlo.');

    process.exit(0);
  } catch (err) {
    console.error('Error creando guards:', err);
    process.exit(1);
  }
})();
