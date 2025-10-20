// backend/scripts/create-tokens.js
require("dotenv").config();
const admin = require("firebase-admin");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const QRCode = require("qrcode");

const SERVICE_ACCOUNT = path.resolve(__dirname, "../serviceAccountKey.json");
const serviceAccount = JSON.parse(fs.readFileSync(SERVICE_ACCOUNT, "utf8"));

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
});

const db = admin.database();
const tokensRef = db.ref("accessTokens");

(async () => {
  console.log("🔐 Generando tokens únicos para los estudiantes...");

  const studentsSnap = await db.ref("students").once("value");
  const students = studentsSnap.val();

  if (!students) {
    console.log("⚠️ No se encontraron estudiantes en la base de datos.");
    process.exit(0);
  }

  for (const [id, data] of Object.entries(students)) {
    // Token aleatorio único
    const token = crypto.randomBytes(16).toString("hex");

    // Guardar el token en la base de datos
    await tokensRef.child(id).set({
      token,
      createdAt: Date.now(),
      expiresAt: Date.now() + 5 * 60 * 1000 // Expira en 5 minutos
    });

    // Generar QR asociado
    const qrData = { id, token };
    const qrPath = path.resolve(__dirname, `../qrs/${id}.png`);

    // Asegurar carpeta qrs
    if (!fs.existsSync(path.dirname(qrPath))) fs.mkdirSync(path.dirname(qrPath));

    await QRCode.toFile(qrPath, JSON.stringify(qrData), { width: 250 });

    console.log(`✅ Token y QR generados para ${id}`);
  }

  console.log("🎉 Todos los QR fueron creados correctamente.");
  process.exit(0);
})();
