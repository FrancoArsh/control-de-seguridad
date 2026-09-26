# Retención, ambientes y Git

## Retención propuesta

- Nonces QR: eliminar al vencer.
- Historial de acceso, auditoría y eventos de seguridad: 90 días en la base operativa.
- Respaldos diarios: 30 días.
- Respaldos semanales: 12 semanas.
- Eliminación: preview, aprobación del responsable institucional, aplicación y evidencia del resultado.

Los plazos son una propuesta técnica para TIH184 y requieren validación del responsable de privacidad de la institución.

## Ambientes

Development usa credenciales locales. Staging exige `NODE_ENV=staging`, un proyecto Firebase separado, `QR_SECRET` diferente de `JWT_SECRET` y orígenes HTTPS explícitos. Production exige las mismas condiciones más HTTPS, secretos de un gestor seguro y respaldo institucional.

Las reglas de Realtime Database bloquean lectura y escritura directa desde clientes. El backend usa Admin SDK y concentra autorización, auditoría y validación.

## Flujo Git

- `main`: versión estable y demostrable.
- `feature/<nombre>`: trabajo de una mejora.
- Commits pequeños con verbo y alcance, por ejemplo `feat: add guard shift report`.
- Ejecutar `npm test`, `node --check frontend/js/portal.js` y `git diff --check` antes de integrar.
- Integrar mediante revisión del diff y conservar evidencia de pruebas en la descripción del cambio.

## Evidencia de seguridad

La revisión actual registra `npm test`, integración con Emulator, prueba de carga y `npm audit`. Una salida de auditoría con vulnerabilidades moderadas debe bloquear el despliegue productivo hasta evaluar actualización, mitigación o aceptación formal del riesgo.
