// backend/scripts/import-students.js
const csv = require('csvtojson');
const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

const serviceAccount = require(path.resolve(__dirname, '../serviceAccountKey.json'));
admin.initializeApp({ credential: admin.credential.cert(serviceAccount), databaseURL: process.env.FIREBASE_DATABASE_URL });

const db = admin.database();
const csvPath = process.argv[2] || path.resolve(__dirname, 'students.csv');

async function importStudents() {
  const jsonArray = await csv().fromFile(csvPath);
  console.log('Registros leídos:', jsonArray.length);
  for (const s of jsonArray) {
    // Asume CSV: studentUid,name,rut,career,email
    const id = s.studentUid || s.rut || (`stu-${Date.now()}-${Math.floor(Math.random()*1000)}`);
    await db.ref(`students/${id}`).set({
      name: s.name || '',
      rut: s.rut || '',
      career: s.career || '',
      email: s.email || ''
    });
    console.log('Creado:', id);
  }
  console.log('Importación finalizada');
  process.exit(0);
}

importStudents().catch(err => { console.error(err); process.exit(1); });
