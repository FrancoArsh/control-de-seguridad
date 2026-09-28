export function validateStaging(env: NodeJS.ProcessEnv, account: any) {
  if (env.NODE_ENV !== 'staging') return;
  const project = 'control-seguridad-staging';
  const expected = `https://${project}-default-rtdb.firebaseio.com/`;
  if (!env.FIREBASE_DATABASE_URL || new URL(env.FIREBASE_DATABASE_URL).href !== expected ||
      account?.project_id !== project || env.GCLOUD_PROJECT !== project ||
      env.FIREBASE_AUTH_EMULATOR_HOST || env.FIREBASE_DATABASE_EMULATOR_HOST) {
    throw new Error('Staging requires its isolated project, credentials and database URL.');
  }
  if (!env.QR_SECRET || !env.JWT_SECRET || !env.ADMIN_SECRET ||
      new Set([env.QR_SECRET, env.JWT_SECRET, env.ADMIN_SECRET]).size !== 3) {
    throw new Error('Staging requires three independent secrets.');
  }
}
