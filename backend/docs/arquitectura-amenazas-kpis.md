# Arquitectura, amenazas y operación

## Arquitectura

El sistema usa tres capas: portal web estático, API Express y Firebase. El navegador nunca escribe directamente en Realtime Database. La API valida la sesión `HttpOnly`, consulta Firebase Admin SDK, aplica autorización por rol y registra los eventos en `accessHistory`.

Los QR dinámicos contienen una identidad, emisión, vencimiento y nonce firmados con HMAC. La transacción en `accessState/{id}` consume el nonce y registra el ingreso de la persona. Portería registra únicamente entradas. El historial conserva movimientos anteriores.

## Modelo de datos principal

| Ruta | Propósito | Datos sensibles |
|---|---|---|
| `students/{id}` | Perfil y estado operativo | Nombre, sede, tipo |
| `guards/{id}` | Perfil del guardia y vínculo Auth | Correo, hash de PIN |
| `portalProfiles/{uid}` | Rol y estado de la cuenta | UID |
| `accessState/{id}` | Último ingreso y control de concurrencia | Estado y timestamps |
| `accessHistory/{event}` | Auditoría de accesos | Persona, motivo, validador |
| `guardShifts/{shift}` | Turnos | Guardia, inicio, término |
| `dynamicQrNonces/{nonce}` | Anti-replay temporal | Vencimiento |

## Amenazas y controles

| Amenaza | Control implementado | Evidencia |
|---|---|---|
| Reutilización de QR | Firma HMAC, expiración y nonce transaccional | Prueba de reutilización en `backend/test/integration.test.mjs` |
| Doble acceso simultáneo | Transacción en `accessState` | `npm run emulator:test` |
| Escalamiento de privilegios | Sesión y rol resueltos por backend | prueba de permisos |
| Exposición de secretos | Variables fuera del repositorio y respaldos redactados | `.env.example`, backup |
| Pérdida de trazabilidad | Auditoría con actor, hora, resultado y motivo | `accessHistory` |

## KPIs y SLAs

### Decisión visible en portería

La meta por intento es mostrar la decisión correcta en menos de 1000 ms desde que el QR aparece completo en el encuadre. En cada jornada de prueba se calcula 100 × decisiones correctas visibles bajo el umbral / intentos iniciados. Incluir en el denominador las lecturas sin respuesta y las decisiones incorrectas. Informar cantidades por dispositivo y por resultado esperado. Con cero intentos el indicador queda sin medición.

El P95 HTTP de `POST /validate` se mide por versión y por tipo de decisión, desde el envío hasta la recepción de la respuesta. Permite investigar demoras del backend. Para verificar la meta de portería se requiere además medir la captura y la presentación de la decisión en el dispositivo.

### Trazabilidad del ingreso

Por turno, contrastar los ingresos aprobados observados con los eventos en el historial que permiten identificar a la persona, al guardia y la fecha y hora del ingreso. Calcular 100 × ingresos observados con coincidencia única y completa / ingresos aprobados observados. Informar duplicados y registros faltantes. La línea base y la medición operacional están pendientes de observación.

### Objetivos de servicio propuestos

| Objetivo | Meta | Verificación |
|---|---:|---|
| Disponibilidad mensual | ≥ 99,5 % | Sondas periódicas desde fuera del servicio y registro de interrupciones. Informar cobertura y lapsos sin observación. |
| Recuperación (RTO) | ≤ 4 h | Cronometrar desde la interrupción hasta la verificación funcional del servicio restaurado. |
| Pérdida de datos (RPO) | ≤ 24 h | En cada simulacro, comparar la hora de interrupción con la del último dato recuperable en el respaldo restaurado. |
