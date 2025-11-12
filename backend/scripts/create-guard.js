// backend/scripts/create-guard.js
// Uso: node backend/scripts/create-guard.js guard-01 "Nombre Guard" 1234

const admin = require("firebase-admin");
const bcrypt = require("bcrypt");
const path = require("path");

// ruta al serviceAccountKey.json (ajusta si es necesario)
const keyPath = path.resolve(__dirname, "../serviceAccountKey.json");

try {
  const serviceAccount = require(keyPath);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL || "https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/"
  });
} catch (e) {
  console.error("No se pudo cargar serviceAccountKey.json desde:", keyPath);
  console.error(e);
  process.exit(1);
}

const db = admin.database();

(async () => {
  const [, , id, name, pin] = process.argv;
  if (!id || !name || !pin) {
    console.log("Uso: node backend/scripts/create-guard.js guard-01 \"Nombre Guard\" 1234");
    process.exit(1);
  }
  try {
    const saltRounds = 10;
    const hash = await bcrypt.hash(pin, saltRounds);
    await db.ref(`guards/${id}`).set({
      name,
      pinHash: hash,
      createdAt: Date.now()
    });
    console.log(`Guard creado: ${id} (${name})`);
    process.exit(0);
  } catch (err) {
    console.error("Error creando guard:", err);
    process.exit(1);
  }
})();
