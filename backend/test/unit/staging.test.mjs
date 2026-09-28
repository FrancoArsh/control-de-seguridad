import test from 'node:test';
import assert from 'node:assert/strict';
import { validateStaging } from '../../dist/environment.js';

const env = { NODE_ENV: 'staging', GCLOUD_PROJECT: 'control-seguridad-staging', FIREBASE_DATABASE_URL: 'https://control-seguridad-staging-default-rtdb.firebaseio.com/', QR_SECRET: 'qr', JWT_SECRET: 'jwt', ADMIN_SECRET: 'admin' };
const account = { project_id: 'control-seguridad-staging' };
test('staging acepta exclusivamente su proyecto y secretos independientes', () => {
  assert.doesNotThrow(() => validateStaging(env, account));
  for (const change of [{ GCLOUD_PROJECT: 'production' }, { FIREBASE_DATABASE_URL: 'https://control-de-seguridad-b4fa7-default-rtdb.firebaseio.com/' }, { QR_SECRET: 'jwt' }, { FIREBASE_AUTH_EMULATOR_HOST: 'localhost:9099' }, { FIREBASE_DATABASE_URL: '' }]) {
    assert.throws(() => validateStaging({ ...env, ...change }, account));
  }
  assert.throws(() => validateStaging(env, { project_id: 'control-de-seguridad-b4fa7' }));
  assert.throws(() => validateStaging(env, null));
});
