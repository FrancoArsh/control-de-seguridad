import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('las reglas Firebase bloquean acceso directo del cliente', () => {
  const rules = JSON.parse(fs.readFileSync(new URL('../../database.rules.json', import.meta.url), 'utf8'));
  assert.equal(rules.rules['.read'], false);
  assert.equal(rules.rules['.write'], false);
});

test('staging exige secretos separados y no usa origen institucional real', () => {
  const env = fs.readFileSync(new URL('../../.env.staging.example', import.meta.url), 'utf8');
  assert.match(env, /NODE_ENV=staging/);
  assert.match(env, /QR_SECRET=/);
  assert.match(env, /JWT_SECRET=/);
  assert.doesNotMatch(env, /inacap\.cl/i);
});
