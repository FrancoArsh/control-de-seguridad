# Arquitectura, amenazas y operación

## Arquitectura

El sistema usa tres capas: portal web estático, API Express y Firebase. El navegador nunca escribe directamente en Realtime Database. La API valida la sesión `HttpOnly`, consulta Firebase Admin SDK, aplica autorización por rol y registra los eventos en `accessHistory`.

Los QR dinámicos contienen una identidad, emisión, vencimiento y nonce firmados con HMAC. El nonce se consume mediante transacción. El estado `accessState/{studentId}` también se actualiza mediante transacción para impedir dos entradas o salidas simultáneas.

## Modelo de datos principal

| Ruta | Propósito | Datos sensibles |
|---|---|---|
| `students/{id}` | Perfil y estado operativo | Nombre, sede, tipo |
| `guards/{id}` | Perfil del guardia y vínculo Auth | Correo, hash de PIN |
| `portalProfiles/{uid}` | Rol y estado de la cuenta | UID |
| `accessState/{id}` | Presencia actual | Estado y timestamps |
| `accessHistory/{event}` | Auditoría de accesos | Persona, motivo, validador |
| `guardShifts/{shift}` | Turnos | Guardia, inicio, término |
| `dynamicQrNonces/{nonce}` | Anti-replay temporal | Vencimiento |

## Amenazas y controles

| Amenaza | Control implementado | Evidencia |
|---|---|---|
| Reutilización de QR | Firma HMAC, expiración y nonce transaccional | `qa-qr-evidence.json` |
| Doble acceso simultáneo | Transacción en `accessState` | `npm run emulator:test` |
| Escalamiento de privilegios | Sesión y rol resueltos por backend | prueba de permisos |
| Exposición de secretos | Variables fuera del repositorio y respaldos redactados | `.env.example`, backup |
| Pérdida de trazabilidad | Auditoría con actor, hora, resultado y motivo | `accessHistory` |

## KPIs y SLAs

| Indicador | Meta | Fuente |
|---|---:|---|
| Tiempo promedio de validación | <= 2 s | Métrica API/load test |
| Rechazos por reutilización de QR | 100% detectados | `accessHistory.reason` |
| Disponibilidad mensual del servicio | >= 99,5% | `/health` |
| Restauración ante incidente (RTO) | <= 4 h | Simulacro mensual |
| Pérdida máxima de datos (RPO) | <= 24 h | Respaldo diario |

