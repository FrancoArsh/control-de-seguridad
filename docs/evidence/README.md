# Evidencia de verificación del prototipo

## Versión presentada

- Rama: `feature/staging-security-hardening`
- Commit de corrección: `a408ea6306fe0b66c2bb9f73f992d4fb971107cf`
- Fecha: 23 de octubre de 2026
- Integración: Firebase Emulator, proyecto de demostración `demo-control-seguridad`
- Rendimiento: servidor local de desarrollo en `127.0.0.1:3000`

## QR dinámico

Las pruebas cubren QR vigente, expirado, reutilizado, firma adulterada, vigencia futura, entrada y salida simultáneas con nonces distintos, y salidas simultáneas. El resultado observado fue una sola transición autorizada, protección contra replay y estado final consistente.

## Roles y auditoría

La suite verificó aislamiento entre administrador, guardia y usuario. También comprobó que una sesión activa queda invalidada después de desactivar la cuenta. Las excepciones manuales requieren guardia en turno, identificador y motivo; registran `validationMode: manual`, guardia, turno, fecha, movimiento y motivo, sin almacenar el token QR.

## Integración, recuperación y respaldo

El comando `npm run test:integration`, ejecutado mediante Firebase Emulator, terminó con **19 pruebas aprobadas y 0 fallidas**. Incluyó paginación de 8.501 movimientos, transacciones concurrentes, recuperación de publicaciones pendientes, respaldo redactado, respaldo cifrado, restauración aislada, retención y rotación de credenciales regenerables.

## Rendimiento

La medición está en [performance-health-2026-10-23.json](performance-health-2026-10-23.json). Se enviaron 1.000 solicitudes a `GET /health`, con concurrencia 50: 1.000 completadas, 0 fallidas, P95 de 44,06 ms y máximo de 73,45 ms.

Esta es una línea base del endpoint de salud. No representa la latencia de validación QR ni la disponibilidad mensual del sistema.

## Capturas

Las capturas usan datos sintéticos controlados por la prueba de navegador:

- [Inicio de sesión](login-current.png)
- [Historial de administrador en escritorio](history-admin-desktop.png)
- [Historial de administrador en móvil](history-admin-mobile.png)
- [Panel de guardia en escritorio](guard-panel-desktop.png)
- [Panel de guardia en móvil](guard-panel-mobile.png)

La suite de navegador pasó en Chromium y WebKit, en cinco tamaños de pantalla. Las capturas demuestran la interfaz y su adaptación; no acreditan datos institucionales reales.

## Pantalla heredada de guardia

`frontend/guard.html` fue corregida en el commit `a408ea6` para redirigir al portal actual. Ya no llama a `/guard/authorize`, endpoint retirado que responde `410`. El flujo vigente se encuentra en `frontend/portal.html`, con excepciones manuales en `/portal/guard/exception`.

## Reproducción

Desde `backend`:

```powershell
npm ci
npm test
firebase emulators:exec --only "database,auth" --project demo-control-seguridad --config firebase.json "npm run test:integration"
node scripts/load-test.mjs --url=http://127.0.0.1:3000 --path=/health --requests=1000 --concurrency=50
```

Las pruebas de emulador requieren Firebase CLI y Java. Las credenciales reales, archivos `.env` y cuentas de prueba no forman parte de estas evidencias.
