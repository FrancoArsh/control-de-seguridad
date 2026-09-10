import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");

test("la configuración mínima del backend está versionada", () => {
  assert.ok(fs.existsSync(path.join(root, "src", "server.ts")));
  assert.ok(fs.existsSync(path.join(root, "firebase.json")));
  assert.ok(fs.existsSync(path.join(root, "database.rules.json")));
});
