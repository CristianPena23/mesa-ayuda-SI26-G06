# Hallazgos anotados para la Parte 6 — Grupo SI26-G06

Detectados durante el despliegue (Parte 3). El enunciado pide **anotarlos y no corregirlos todavía**.
En la Parte 6 cada uno se explica (causa raíz), se corrige y se verifica con herramientas.

| # | Archivo | Hallazgo | Por qué es un riesgo |
|---|---------|----------|----------------------|
| H1 | `env_del_examen.txt` (`.env`) | Archivo de variables con secretos **subido al repositorio** | Cualquiera con acceso al repo (o a su historial) obtiene la contraseña de la BD y el secreto JWT. Borrarlo después no basta: queda en el historial de git. |
| H2 | `.gitignore` | No ignora `.env` | Es la causa raíz de H1: nada impide volver a subirlo. |
| H3 | `.env` | `DB_USER=root` | La app se conecta con el superusuario de MySQL. Una inyección SQL tendría control total de la base (borrar tablas, leer todo, crear usuarios). Viola mínimo privilegio. |
| H4 | `.env` | `JWT_SECRET=mesa-ayuda-secret-2026` (débil y publicado) | Con ese secreto cualquiera puede **firmar tokens válidos** y hacerse pasar por cualquier usuario, incluido un administrador. |
| H5 | `Dockerfile` | No define `USER`: el contenedor corre como **root** | Si alguien explota la API, obtiene root dentro del contenedor, lo que facilita escapar al host. |
| H6 | `Dockerfile` | `COPY . .` sin `.dockerignore` | Mete en la imagen el `.env`, `.git` y `.DS_Store`. Los secretos quedan "horneados" en la imagen. |
| H7 | `Dockerfile` | `uvicorn ... --reload` | Modo de desarrollo en producción: vigila y recarga archivos, consume más recursos y no es estable. |
| H8 | `Dockerfile` | Imagen base `python:3.12` completa | Imagen grande con muchos paquetes innecesarios = más vulnerabilidades (CVE) y más superficie de ataque. Preferible `python:3.12-slim`. |
| H9 | `requirements.txt` | Dependencias **sin versión fija** | Cada build puede instalar versiones distintas, incluidas versiones con vulnerabilidades o cambios incompatibles. No es reproducible. |
| H10 | `docker-compose.yml` | `ports: "${APP_PORT}:${APP_PORT}"` publica en `0.0.0.0` | Docker escribe sus propias reglas en iptables y **se salta ufw**: la API queda expuesta en todas las interfaces. (Se mitiga ya en la Parte 3 publicando solo en la IP de Tailscale.) |
| H11 | raíz del repo | `.DS_Store` versionado | Archivo de macOS que filtra nombres de archivos/carpetas del equipo del desarrollador. |

## Hallazgos en el código (`app/main.py`, `app/database.py`)

| # | Ubicación | Hallazgo | Por qué es un riesgo |
|---|-----------|----------|----------------------|
| H12 | `main.py` → `POST /auth/login` | **Inyección SQL**: el `username` se mete en la consulta con f-string (`WHERE username = '{datos.username}'`) | Un atacante puede alterar la consulta. Con `root` como usuario de BD (H3), la inyección da control total de la base. |
| H13 | `main.py` → `GET /tickets/buscar` | **Inyección SQL** en el parámetro `q` (`LIKE '%{q}%'`) | Permite leer tablas ajenas con `UNION SELECT`, por ejemplo `usuarios` con sus hashes. |
| H14 | `main.py` → `GET /debug/config` | Endpoint de depuración **sin autenticación** que devuelve contraseña de la BD, `JWT_SECRET` y **todas** las variables de entorno | Fuga directa de todos los secretos con una sola petición. |
| H15 | `main.py` → `registro` y `login` | Se **registran contraseñas en texto plano** en los logs (`logger.info(... {datos.password} ...)`) | Quien lea los logs (o Wazuh, o un respaldo) obtiene contraseñas reales de los usuarios. |
| H16 | `main.py` → CORS | `allow_origins=["*"]` junto con `allow_credentials=True` | Cualquier sitio web puede hacer peticiones a la API en nombre del usuario. |
| H17 | `main.py` → `GET /tickets/{ticket_id}` | **IDOR**: no verifica que el ticket sea del usuario | Cualquier usuario autenticado lee tickets de otros cambiando el número en la URL. |
| H18 | `main.py` → `PATCH /tickets/{id}/estado` | **IDOR / control de acceso roto**: cualquiera cambia el estado de cualquier ticket | Rompe la integridad de los datos de otros usuarios. |
| H19 | `main.py` → `GET /admin/usuarios` | Devuelve `password_hash` de todos los usuarios | Exposición innecesaria de datos sensibles, aun para un admin. |
| H20 | `database.py` → `init_db()` | La app ejecuta DDL (`CREATE TABLE`) al arrancar | Obliga a dar privilegios de creación al usuario de la app, contra el mínimo privilegio. |
| H21 | `database.py` → `get_connection()` | Conexión a MySQL **sin TLS** | Las credenciales y los datos viajan sin cifrar a nivel de aplicación. |
| H22 | `password_hash VARCHAR(64)` | Sugiere un SHA-256 sin sal (revisar `app/security.py`) | Los hashes rápidos y sin sal se rompen con diccionarios o tablas precalculadas. |

## Hallazgos en el frontend y en los Dockerfile

| # | Ubicación | Hallazgo | Por qué es un riesgo |
|---|-----------|----------|----------------------|
| H23 | Frontend (consola del navegador) | Tras el login se imprime **el token JWT completo** en la consola (`Sesión iniciada <usuario> eyJhbGci...`) | Cualquier extensión, script de terceros o persona con acceso al equipo puede copiar el token y suplantar al usuario. Los tokens nunca deben ir a logs. |
| H24 | Frontend → formulario de ticket | La descripción "admite formato HTML" | Si se renderiza con `innerHTML` sin sanitizar, es **XSS almacenado**: un ticket malicioso ejecuta código en el navegador de quien lo abra (por ejemplo, un admin). La CSP `script-src 'self'` mitiga la ejecución, pero la causa raíz está en el código. |
| H25 | `frontend/Dockerfile` | `npm run build --configuration production` no compila (npm se queda con la opción) | Calidad: el código entregado no se podía desplegar tal cual. Se corrigió con `npm run build -- --configuration production`. |
| H26 | `frontend/nginx.conf` (base) | `autoindex on`, sin `server_tokens off`, sin encabezados de seguridad | Listado de directorios y fuga de versión. Corregido en la Parte 4. |
| H27 | `backend/Dockerfile` | `EXPOSE 8000` no coincide con el puerto real de la app | Documentación engañosa del contenedor (menor). |

> Pendiente: revisar `app/security.py`, `app/schemas.py` y `app/config.py` (algoritmo de hash, validación del JWT, expiración del token, validación de entradas). Verificar todo con SonarQube, Bearer y ZAP en la Parte 6.
