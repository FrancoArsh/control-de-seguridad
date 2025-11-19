const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const path = require('path');

const SERVICE = './serviceAccountKey.json';

admin.initializeApp({
  credential: admin.credential.cert(require(path.resolve(SERVICE))),
  databaseURL: "https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/"
});

const db = admin.database();

const PIN_MAP = {
  "guard-01":"270326",
  "guard-02":"198346",
  "guard-03":"524392",
  "guard-04":"903911",
  "guard-05":"364955",
  "guard-06":"083799",
  "guard-07":"307180",
  "guard-08":"718936",
  "guard-09":"243469",
  "guard-10":"126524"
};

(async () => {
  try {
    for (const [id, pin] of Object.entries(PIN_MAP)) {
      const hash = await bcrypt.hash(String(pin).trim(), 10);
      console.log(`Updating ${id} ... hash length: ${hash.length}`);
      await db.ref(`guards/${id}`).update({ pinHash: hash });
    }
    console.log("All hashes updated.");
    process.exit(0);
  } catch (e) {
    console.error("Error updating hashes:", e);
    process.exit(1);
  }
})();


