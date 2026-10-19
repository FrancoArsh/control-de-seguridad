// backend/scripts/create-students.js
require("dotenv").config();
const { initializeApp, cert } = require('firebase-admin/app');
const { getDatabase } = require('firebase-admin/database');
const fs = require("fs");
const path = require("path");

const SERVICE_ACCOUNT = path.resolve(__dirname, "../serviceAccountKey.json");
const serviceAccount = JSON.parse(fs.readFileSync(SERVICE_ACCOUNT, "utf8"));

initializeApp({
  credential: cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = getDatabase();

(async () => {
  const studentsRef = db.ref("students");
  console.log("Cargando 20 estudiantes de prueba...");

  for (let i = 1; i <= 20; i++) {
    const studentId = `est-${String(i).padStart(3, "0")}`;
    await studentsRef.child(studentId).set({
      name: `Alumno ${i}`,
      rut: `1234567-${i}`,
      email: `alumno${i}@correo.cl`,
      carrera: "Ingeniería en Informática",
      createdAt: Date.now()
    });
    console.log(`Estudiante ${studentId} agregado.`);
  }

  console.log("✅ Todos los estudiantes fueron cargados correctamente.");
  process.exit(0);
})();
