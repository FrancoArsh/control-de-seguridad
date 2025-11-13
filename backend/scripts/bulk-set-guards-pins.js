// backend/scripts/bulk-set-guards-pins.js
// Uso:
//  node scripts/bulk-set-guards-pins.js      -> asigna PINs solo a guards sin pinHash
//  node scripts/bulk-set-guards-pins.js --force  -> fuerza regeneración para todos
// Salida: backend/output/guards-pins.csv

const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const KEY_PATH = path.resolve(__dirname, '../serviceAccountKey.json');
if (!fs.existsSync(KEY_PATH)) {
  console.error('serviceAccountKey.json no encontrado en', KEY_PATH);
  process.exit(1);
}
const serviceAccount = require(KEY_PATH);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL || "https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/"
});
const db = admin.database();

function genPinNumeric(len = 6) {
  // genera PIN numérico de `len` dígitos (ej: 6 -> 000123)
  const max = Math.pow(10, len);
  const n = Math.floor(Math.random() * max);
  return String(n).padStart(len, '0');
}

(async () => {
  const args = process.argv.slice(2);
  const FORCE = args.includes('--force');

  console.log('Bulk PIN assigner. FORCE=', FORCE);

  const snap = await db.ref('guards').once('value');
  const guards = snap.val() || {};
  const ids = Object.keys(guards);

  if (!ids.length) {
    console.log('No se encontraron guards en la BD (nodo guards/ vacío)');
    process.exit(0);
  }

  // preparar carpeta output
  const outDir = path.resolve(__dirname, '../output');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, 'guards-pins.csv');
  const csvLines = [ 'id,name,pin' ];

  for (const id of ids) {
    try {
      const rec = guards[id] || {};
      const name = rec.name || '';
      const hasPin = !!rec.pinHash;
      if (hasPin && !FORCE) {
        console.log(`skip ${id} (ya tiene pinHash). Usa --force para regenerar.`);
        // opcional: podríamos incluir en CSV una línea indicando que ya tenía PIN, pero preferimos no exponer
        continue;
      }

      // generar PIN (6 dígitos numéricos)
      const pin = genPinNumeric(6);
      const hash = await bcrypt.hash(pin, 10);

      // actualizar DB
      await db.ref(`guards/${id}`).update({ pinHash: hash, pinUpdatedAt: Date.now() });

      // anotar en CSV
      csvLines.push(`${id},"${String(name).replace(/"/g,'""')}",${pin}`);
      console.log(`assigned PIN -> ${id} (${name})`);
    } catch (e) {
      console.error('error procesando', id, e);
    }
  }

  fs.writeFileSync(outFile, csvLines.join('\n'), 'utf8');
  console.log('CSV generado en:', outFile);
  console.log('Operación finalizada. Revisa el CSV y distribuye los PINs de forma segura.');
  process.exit(0);
})();
