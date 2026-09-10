# Operación y evidencias de Control de Seguridad

## Alcance de esta etapa

- La API valida QR estáticos y dinámicos, registra auditoría y mantiene un estado de presencia por persona.
- El cambio de estado se confirma con una transacción de Firebase Realtime Database.
- El endpoint `GET /presence` entrega solo personas con `inside=true` y exige autenticación de guardia o administrador.
- Los nonces dinámicos se eliminan periódicamente cuando su `expiresAt` ya venció.

## Despliegue

1. Usar Node.js 20 LTS, `npm ci`, `npm run build` y `npm start`.
2. Configurar `NODE_ENV=production`, `FIREBASE_DATABASE_URL`, `FIREBASE_SERVICE_ACCOUNT` o `GOOGLE_APPLICATION_CREDENTIALS`, `JWT_SECRET` y un `QR_SECRET` independiente.
3. Definir `ALLOWED_ORIGINS` con los orígenes reales y nunca dejar secretos en el repositorio.
4. Publicar detrás de HTTPS y un proxy con límites de conexión y registro de errores.
5. Verificar `/health`, login de guardia, generación de QR y una validación controlada antes de abrir el punto de control.

### Staging reproducible

- Construir la imagen desde la raíz del repositorio: `docker build -f backend/Dockerfile -t control-seguridad:staging .`.
- Ejecutar con un archivo de variables fuera del repositorio y publicar solo por HTTPS.
- Usar un proyecto Firebase separado del productivo; el staging nunca debe compartir credenciales ni base de datos.

## Respaldo y retención

- Programar exportación diaria de `accessHistory`, `accessState`, `guardShifts`, `guardAuthorizations`, `adminAuditLog` y `securityEvents` hacia almacenamiento institucional cifrado.
- Mantener como mínimo una copia diaria por 30 días y una copia semanal por 12 semanas, sujeto a la política de privacidad y retención aprobada por INACAP.
- Probar restauración mensualmente en un proyecto Firebase separado y registrar fecha, responsable, resultado y diferencias.
- Definir una retención diferenciada: eventos de seguridad y auditoría pueden requerir más tiempo que los nonces, que deben eliminarse apenas expiran.
- No respaldar tokens QR completos ni secretos de firma junto con los datos operativos.
- La automatización de referencia está en `.github/workflows/backup-staging.yml`: se ejecuta diariamente a las 03:00 UTC, usa `STAGING_FIREBASE_DATABASE_URL` y `STAGING_FIREBASE_SERVICE_ACCOUNT` como secretos de CI y conserva un artefacto por 30 días. Este artefacto no reemplaza el almacenamiento institucional cifrado ni una política de respaldo aprobada.

### Recuperación de credenciales

- Los respaldos redactados no restauran tokens ni PIN porque esos valores son secretos operativos.
- Después de una restauración se debe ejecutar `npm run credentials:recovery -- --apply=true` contra la base recuperada, entregar el archivo generado por un canal seguro y eliminarlo después de confirmar la rotación.
- La operación se inicia con `npm run credentials:recovery` en modo `preview`; la prueba reproducible en Emulator es `npm run emulator:recovery`.
- La recuperación debe quedar registrada con responsable, fecha, alcance, confirmación de entrega y comprobación de acceso posterior.

### Comandos operativos

- Respaldo redactado: `npm run backup:staging -- --output=./backups/staging`.
- Vista previa de retención: `npm run retention:preview -- --retention-days=90`.
- Aplicación aprobada: `npm run retention:apply -- --retention-days=90`.
- Vista previa de restauración: `npm run restore:preview -- --file=./backups/staging/rtdb.json`.
- Restauración aprobada: `npm run restore:apply -- --file=./backups/staging/rtdb.json`.
- Prueba completa sobre Emulator: `npm run emulator:ops`.

La retención y la restauración comienzan siempre en modo `preview`; `--apply=true` es una decisión explícita y debe quedar respaldada por un registro de aprobación.

## Pruebas y evidencias para TIH184

- Requisitos: catálogo RF/RNF con criterio de aceptación y evidencia asociada.
- Arquitectura: diagrama de capas, modelo de datos, decisiones y matriz de amenazas.
- Seguridad: reglas Firebase, prueba negativa de autorización, expiración, replay y revisión OWASP ASVS.
- Concurrencia: salida de `npm run emulator:test` con una sola autorización exitosa ante solicitudes simultáneas.
- Operación: captura de `/health`, métricas, SLA, procedimiento de contingencia y prueba de recuperación.
- Rendimiento: salida de `npm run load:test -- --url=http://127.0.0.1:3000 --path=/health --requests=200 --concurrency=20`.
- Operación de datos: salida de `npm run emulator:ops`, que comprueba respaldo redactado, preview y borrado controlado.
- Recuperación: salida de `npm run emulator:recovery`, que comprueba preview sin cambios y rotación efectiva de token y PIN.

## Riesgos abiertos

- La base de datos de producción debe definir reglas y roles junto con TI y privacidad.
- La migración desde registros manuales requiere línea base observada en una sede piloto.
- La restauración y el borrado por retención deben ser aprobados por el responsable institucional de datos.
