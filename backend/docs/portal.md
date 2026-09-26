# Portal de Control de Seguridad

La entrada `/` presenta el portal con correo y contraseña. La sesión se guarda en una cookie `HttpOnly`, `Secure` en producción y `SameSite=Strict`. El navegador no recibe el token de sesión ni las credenciales administrativas.

## Configuración de Firebase Authentication

1. Activar el proveedor **Correo electrónico/contraseña** en Firebase Authentication.
2. Configurar `FIREBASE_WEB_API_KEY` con la API key web del proyecto correspondiente al entorno.
3. Crear cada cuenta en Firebase Authentication.
4. Vincular el UID de la cuenta con el registro operativo:

```json
{
  "portalProfiles": {
    "uid-de-administrador": { "role": "admin", "id": "uid-de-administrador", "active": true },
    "uid-de-guardia": { "role": "guard", "id": "guard-001", "active": true },
    "uid-de-estudiante": { "role": "member", "id": "stu-001", "active": true }
  }
}
```

- `admin` busca el perfil en `admins/{id}` y exige `role: "admin"`.
- `guard` busca el perfil en `guards/{id}`.
- `member` busca el perfil en `students/{id}`.

## Operacion de cuentas

- `POST /portal/password-reset` solicita el correo de recuperacion y siempre responde de forma generica para no revelar si una cuenta existe.
- `GET /portal/users` permite al administrador consultar perfiles sin exponer hashes, PIN ni tokens estaticos.
- `POST /portal/users` crea una cuenta Firebase y su perfil operativo; exige una contrasena inicial de al menos 12 caracteres.
- `PATCH /portal/users/{uid}` activa o desactiva la cuenta en Firebase y en el perfil operativo.
- Las sesiones se almacenan como hashes de cookies en `portalSessions`, expiran a las seis horas y se limpian periodicamente.

## Vistas implementadas

- Inicio: resumen según rol.
- Escanear QR: disponible solo para guardias con turno activo.
- Personas dentro: disponible solo para administradores.
- Historial: administradores ven todos los eventos; guardias solo ven sus propias validaciones; los miembros solo ven sus eventos.
- Mi código QR: disponible para miembros.
- Usuarios: disponible para administradores; permite alta, edición, consulta, activación, desactivación y QR de estudiantes.
- Reportes: CSV para usuarios autorizados y PDF para administradores.

La validación `POST /validate` requiere una sesión administrativa o una sesión de guardia con turno activo. El login antiguo de guardia permanece disponible para compatibilidad, pero el portal es la entrada recomendada.

## Riesgos de dependencias

`npm audit --omit=dev` identifica vulnerabilidades moderadas transitivas en `qs` y `uuid`. La actualización forzada implicaría cambios mayores en `firebase-admin`; se debe planificar una actualización controlada y repetir las pruebas antes del despliegue productivo.
