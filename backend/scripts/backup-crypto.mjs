import crypto from "node:crypto";

function keyFrom(value) {
  if (!value) throw new Error("BACKUP_ENCRYPTION_KEY es obligatorio para respaldos cifrados.");
  const key = /^[a-f0-9]{64}$/i.test(value) ? Buffer.from(value, "hex") : Buffer.from(value, "base64");
  if (key.length !== 32) throw new Error("BACKUP_ENCRYPTION_KEY debe ser una clave de 32 bytes en hex o base64.");
  return key;
}

export function encryptBackup(value, secret = process.env.BACKUP_ENCRYPTION_KEY) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", keyFrom(secret), iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return { schemaVersion: 2, encrypted: true, algorithm: "aes-256-gcm", iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") };
}

export function decryptBackup(envelope, secret = process.env.BACKUP_ENCRYPTION_KEY) {
  if (!envelope?.encrypted) return envelope;
  if (envelope.algorithm !== "aes-256-gcm") throw new Error("Algoritmo de respaldo no soportado.");
  const decipher = crypto.createDecipheriv("aes-256-gcm", keyFrom(secret), Buffer.from(envelope.iv, "base64"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8"));
}
