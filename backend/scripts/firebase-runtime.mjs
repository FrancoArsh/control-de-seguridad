import fs from "node:fs";
import dotenv from "dotenv";
import { cert, initializeApp } from "firebase-admin/app";
import { getDatabase } from "firebase-admin/database";

dotenv.config();

function parseServiceAccount() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (raw) {
    const value = raw.trim();
    try {
      return JSON.parse(value);
    } catch (_) {
      try {
        return JSON.parse(Buffer.from(value, "base64").toString("utf8"));
      } catch (error) {
        throw new Error(`FIREBASE_SERVICE_ACCOUNT no contiene JSON válido: ${error.message}`);
      }
    }
  }

  const credentialsPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (credentialsPath && fs.existsSync(credentialsPath)) {
    return JSON.parse(fs.readFileSync(credentialsPath, "utf8"));
  }
  return null;
}

export function createDatabaseClient(name) {
  const config = {
    projectId: process.env.GCLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT || undefined,
    databaseURL: process.env.FIREBASE_DATABASE_URL || "https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/"
  };
  const serviceAccount = parseServiceAccount();
  if (serviceAccount) config.credential = cert(serviceAccount);
  const app = initializeApp(config, `${name}-${Date.now()}`);
  return { app, db: getDatabase(app) };
}
