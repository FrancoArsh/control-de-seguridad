# Operacion y despliegue

## Respaldos

El scheduler de `.github/workflows/backup-staging.yml` ejecuta diariamente a las 03:00 UTC y permite ejecucion manual. Requiere estos secretos de GitHub:

- `STAGING_FIREBASE_PROJECT_ID`
- `STAGING_FIREBASE_DATABASE_URL`
- `STAGING_FIREBASE_SERVICE_ACCOUNT`
- `STAGING_BACKUP_ENCRYPTION_KEY`: 32 bytes, hex o base64

El respaldo incluye datos RTDB operativos, `admins`, `portalProfiles` y un inventario de usuarios Auth sin contrasenas. No incluye sesiones activas ni credenciales recuperables en texto plano. El archivo se cifra con AES-256-GCM antes de publicarse como artifact.

El horario indica cuándo GitHub programa el trabajo; registrar la hora real del evento y su conclusión como evidencia. En cambios de la rutina y ejecuciones manuales se realiza respaldo y prueba de recuperación. La retención automática solo corre en ejecuciones programadas, después de guardar el archivo cifrado y comparar las colecciones restauradas en un emulador vacío. El log de recuperación registra duración y última marca de acceso disponible. Con un historial vacío esa marca queda sin medición. Las fallas o cancelaciones del trabajo generan una incidencia en GitHub; comprobar aparte la recepción si se usa correo institucional. El inventario de Auth sirve para conciliación de cuentas y requiere un procedimiento de recuperación de identidad separado.

## Restauracion

1. Ejecutar `restore-rtdb.mjs` en modo preview.
2. Confirmar el proyecto y el archivo de respaldo.
3. Ejecutar `--apply=true` en un entorno aislado.
4. Ejecutar `credential-recovery.mjs --apply=true` para regenerar tokens y PIN.
5. Restablecer contrasenas de Firebase Auth por un canal administrativo.
6. Validar login, roles, QR, auditoría de ingresos y rechazo de solicitudes de salida.

La restauracion no recupera contrasenas Auth, sesiones ni nonces QR. El tiempo de recuperacion debe medirse desde la descarga hasta la validacion del primer acceso y registrarse como evidencia.

## Datos personales

La retencion elimina eventos vencidos y nonces expirados. La eliminacion individual requiere una solicitud aprobada y `delete-personal-data.mjs --id=<id> --confirm=true`; deja un registro minimo de auditoria. La eliminacion de la identidad Firebase Auth debe ejecutarse separadamente con el UID confirmado. Antes de aplicar se debe revisar obligacion legal, necesidad de conservar evidencias y alcance de la solicitud.

Para una visita, usar el identificador interno `manual-<hash>` del evento. Verificar el ambiente y ejecutar `node scripts/delete-personal-data.mjs --id=<id>` para inventariar historial, auditoría, asistencia por sesión y estado de acceso. Para aplicar durante una ventana de mantenimiento, detener todos los escritores (incluida la recuperación de publicaciones), repetir el inventario y añadir `--confirm=true --writers-stopped=true`. La operación elimina los registros identificados y deja un comprobante con fecha y cantidades. Repetir la vista previa y verificar cantidades en cero antes de reabrir. Registrar aparte los respaldos y exportaciones afectados, su vencimiento y la necesidad de reaplicar la solicitud si se restaura una copia anterior. El alcance del comando es la base operativa. Para una solicitud aprobada, inventariar las exportaciones entregadas y registrar responsable, ubicación y confirmación de retiro en cada destino. Identificar las copias cifradas anteriores afectadas, restringir su acceso y registrar su fecha efectiva de eliminación conforme a la política aplicable. Conservar el identificador de la solicitud y el identificador de visita en un registro de acceso restringido, separado de los respaldos. Si se recupera una copia anterior, reaplicar las solicitudes pendientes en el ambiente aislado y exigir un inventario en cero antes de reabrir el servicio. El ensayo remoto usa dos visitas sintéticas en un subárbol exclusivo mediante `node scripts/verify-staging-visitor-erasure.mjs` después de compilar. Desplegar los índices de `accessHistory/id` y `adminAuditLog/entityId` definidos en las reglas del repositorio.

## HTTPS y despliegue

Antes de publicar:

- usar un proveedor definido y un dominio controlado por el responsable del proyecto;
- terminar TLS en el proveedor y redirigir HTTP a HTTPS;
- configurar `NODE_ENV=production`, secretos independientes y `ALLOWED_ORIGINS` exactos;
- usar cookies `Secure`, `HttpOnly` y `SameSite=Strict`;
- no incluir cuentas de servicio en la imagen Docker;
- configurar health checks, logs sin tokens, alertas y rollback a la imagen anterior;
- probar restauracion y rotacion de secretos antes de aceptar tráfico.

El repositorio deja preparada la configuración, pero no considera contratado un dominio, proveedor cloud, certificado ni scheduler institucional hasta que exista una cuenta y un secreto verificable.

## Dependencias

`npm audit fix` eliminó la cadena vulnerable de `qs`. Permanecen vulnerabilidades moderadas transitivas de `uuid` en Firebase Admin; corregirlas requiere evaluar una actualización mayor de Firebase Admin y repetir compilación, integración y pruebas de staging. No se debe usar `npm audit fix --force` sin esa validación.
