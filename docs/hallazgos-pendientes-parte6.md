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

## Hallazgo nuevo detectado por SonarQube

| # | Dónde | Qué pasa | Por qué es grave |
|---|---|---|---|
| H28 | `backend/app` (línea 37 según SonarQube, decodificación del JWT) | El token JWT se lee **sin verificar su firma** | Cualquiera puede fabricar un token con `rol=admin` y la API lo acepta, sin conocer `JWT_SECRET`. Es suplantación total. |

## Análisis estático con SonarQube Community (versión base)

Resultado del primer análisis (código v-base, antes de corregir):

| Proyecto | Seguridad | Confiabilidad | Mantenibilidad | Quality Gate |
|---|---|---|---|---|
| mesa-ayuda-backend (Python, 258 líneas) | D (2) | D (1) | A (7) | Passed |
| mesa-ayuda-frontend (TypeScript/HTML, 416 líneas) | E (1, Blocker) | C (7) | A (3) | Passed |

Correspondencia con los hallazgos manuales:

- Detectados por SonarQube: H22 (hash débil), H24 (sanitización de Angular desactivada → XSS) y H28 (JWT sin verificar firma, que no estaba en la lista manual).
- No detectados: H12/H13 (inyección SQL), H14 (`/debug/config`), H15 (contraseñas en logs), H16 (CORS), H17/H18 (IDOR), H19, y todo lo de configuración (`.env`, Dockerfile, compose). La edición Community no hace análisis de flujo de datos (taint analysis), que es lo que detecta inyecciones, y no revisa archivos de configuración ni lógica de autorización.
- El Quality Gate "Sonar way" marcó **Passed** con vulnerabilidades abiertas porque sus condiciones aplican solo al código nuevo, y en el primer análisis no hay período de comparación. "Passed" no equivale a "seguro".
- Conclusión: el análisis estático es una capa más, no reemplaza la revisión manual ni las pruebas dinámicas.

## Error de configuración propio detectado al validar (Parte 5 → corregido en Parte 6)

| # | Dónde | Qué pasaba | Corrección |
|---|---|---|---|
| H29 | `infra/wazuh/agent.conf` (FIM del backend) | El filtro era `restrict="docker-compose.yml$\|\.env$"`. `restrict` usa *sregex* de Wazuh, donde `\` es un carácter literal, así que el `.env` **nunca** coincidía: el archivo con los secretos no se vigilaba aunque la configuración "pareciera" correcta. Solo `docker-compose.yml` generaba alertas. | Se cambió a `restrict="docker-compose.yml$\|.env$"`. Verificado: al rotar el `JWT_SECRET` (04/10/2026 14:37) Wazuh generó la regla 550 en modo `realtime` sobre `/home/sgadmin/backend/.env`, con `syscheck.diff` truncado por `nodiff` (el secreto no queda en el SIEM). |

Lección: configurar un control no basta; hay que **probar que detecta**. Este punto ciego solo apareció al intentar producir la alerta a propósito.

## Incidente operativo durante el despliegue

Al encender la VM `sg-robayo-security`, Docker arrancó antes de que Tailscale asignara la IP `100.91.88.2`, y el manager y el dashboard no pudieron publicar sus puertos (1514, 1515, 443): todos los agentes quedaron *Disconnected*. Se recrearon los contenedores y se agregó `/etc/systemd/system/docker.service.d/esperar-tailscale.conf` para que Docker espere a `tailscaled` y a la IP de `tailscale0`. Publicar en la IP de Tailscale (y no en `0.0.0.0`) sigue siendo lo correcto, porque Docker se salta `ufw`.

## Análisis estático con SonarQube Community (versión corregida, Parte 6)

Análisis con `sonar.projectVersion=parte6-corregida`, comparado contra la versión base como "código nuevo":

| Proyecto | Seguridad | Confiabilidad | Mantenibilidad | Quality Gate |
|---|---|---|---|---|
| mesa-ayuda-backend | D (2) → **A (0)** | D (1) → **A (0)** | A (7) → **A (0)** | Failed (solo cobertura) |
| mesa-ayuda-frontend | E (1 Blocker) → **A (0)** | C (7) → C (7) | A (3) → A (1) | Passed |

- Desaparecieron los tres problemas de seguridad que SonarQube sí detectaba: H22 (hash débil), H28 (JWT sin verificar firma) y H24 (sanitización de Angular desactivada).
- El primer análisis tras corregir generó 3 problemas nuevos de mantenibilidad (dos `HTTPException` 400 sin documentar y una consulta SQL repetida). Se corrigieron junto con los 5 heredados de la versión base: cada endpoint declara sus respuestas de error con `responses=` y la consulta repetida es la constante `SQL_TICKET_POR_ID`. Resultado: **0 issues** en el backend.
- El Quality Gate del backend queda en **Failed por una sola condición: cobertura de pruebas 0 % < 80 %** sobre el código nuevo. El proyecto no tiene pruebas unitarias automatizadas (ni la versión base ni la corregida). Es una carencia real que SonarQube detecta correctamente; se deja como recomendación para el pipeline DevSecOps. Las pruebas de seguridad se hicieron de forma dinámica contra la app desplegada (`infra/pruebas/pruebas-parte6.ps1`, 11/11 OK).
- Los 7 problemas de confiabilidad del frontend son de accesibilidad (campos `input` sin `id`/`label` asociados), no de seguridad.
- Lectura: el "Passed" del primer análisis no significaba "seguro" (no había código nuevo que evaluar), y este "Failed" no significa "inseguro": señala la falta de pruebas automatizadas.

## Bearer CLI sobre el backend (SAST, 6.3)

Informes en `docs/`: `bearer-backend-base-2026-10-04.html`, `bearer-backend-corregido-2026-10-04.html`, `bearer-backend-final-2026-10-04.html`.

| Ejecución | Críticos | Medios | Detalle |
|---|---|---|---|
| Base (`v-base`) | 4 | 3 | JWT sin verificar firma (CWE-347), 3 "SQL sin sanear" en `database.py` (CWE-89), contraseñas en logs ×2 (CWE-532), MD5 (CWE-328) |
| Corregido | 3 | 2 | Los 3 de SQL son falsos positivos; los logs ya no tenían la clave pero sí el nombre de usuario |
| Final | 0 | 0 | Logs solo con el id interno; 4 falsos positivos revisados y justificados en `backend/bearer.ignore` |

- Bearer confirmó H28 (JWT), H22 (MD5) y H15 (claves en logs), y aportó un hallazgo que la revisión manual pasó por alto: tras la primera corrección los logs todavía guardaban el **nombre de usuario** (dato personal, Ley 1581; además, en un login fallido la persona a veces escribe su clave en el campo de usuario). Se corrigió registrando solo el id interno, que es la remediación que propone la propia regla.
- Los 3 hallazgos de SQL apuntan a `cur.execute(sql, params)` dentro de las funciones auxiliares de `database.py`: Bearer no puede saber de dónde viene `sql`. En el código corregido todas las llamadas usan una consulta constante con `%s` y los datos van en `params`; las pruebas de inyección (`infra/pruebas/pruebas-parte6.ps1`) lo confirman. Se marcaron como falsos positivos con su justificación, autor y fecha (`bearer ignore add --false-positive`), no se ocultaron.
- Limitación observada: en la versión base Bearer marcó las mismas tres funciones de `database.py`, pero **no** señaló la inyección real (los f-strings de `main.py`, H12 y H13). Las herramientas apoyan la revisión manual; no la reemplazan.

## OWASP ZAP baseline contra la URL pública (DAST, 6.3)

Informes en `docs/`: `zap-baseline-antes-2026-10-04.html`, `zap-baseline-despues-2026-10-04.html`, `zap-baseline-final-2026-10-04.html`.

- **Antes:** la versión `v-base` del frontend se levantó de forma temporal en el PC de un integrante, publicada con un túnel rápido de Cloudflare propio, y se escaneó. Solo se corrigió el error de compilación H25 para poder construirla; el `nginx.conf` era el original (sin encabezados de seguridad). Al terminar, los contenedores y el túnel se eliminaron.
- **Después / final:** la aplicación desplegada (Nginx endurecido de la Parte 4 + correcciones de la Parte 6), por su túnel de Cloudflare.

| Escaneo | WARN | PASS | FAIL |
|---|---|---|---|
| Antes (base) | 11 | 56 | 0 |
| Después (Partes 4 y 6 desplegadas) | 7 | 60 | 0 |
| Final (Angular actualizado) | 6 | 61 | 0 |

| Alerta | Antes | Final | Comentario |
|---|---|---|---|
| CSP Header Not Set | WARN | PASS | `Content-Security-Policy` en Nginx |
| Missing Anti-clickjacking Header | WARN | PASS | `X-Frame-Options` / `frame-ancestors` |
| X-Content-Type-Options Missing | WARN | PASS | `nosniff` |
| Strict-Transport-Security Not Set | WARN | PASS | HSTS |
| Permissions Policy Not Set | WARN | PASS | `Permissions-Policy` |
| Vulnerable JS Library (`@angular/core` 21.2.6) | WARN | PASS | Ver H30 |
| CSP: style-src unsafe-inline | — | WARN | Aparece porque ahora hay CSP. Riesgo aceptado: PrimeNG inyecta estilos en línea; los scripts sí están restringidos (`script-src 'self'`, sin `unsafe-inline`) |
| Dangerous JS Functions (`bypassSecurityTrustHtml(`) | WARN | WARN | Falso positivo en el final: es la definición del método dentro de Angular. El código propio ya no lo llama (`findstr` en `frontend/src` solo halla el comentario de la corrección) y la prueba en navegador muestra el `onerror` eliminado |
| Cache-control / Storable content / COEP / Modern Web App | WARN | WARN | Informativas o de riesgo bajo sobre caché de estáticos y aislamiento entre orígenes; recomendación, no se tocan |
| HTTP Server Response Header | PASS | PASS | En la base pasa solo porque Cloudflare reemplaza el encabezado `Server`; la corrección propia es `server_tokens off` (H26) |

## Hallazgo nuevo por análisis de dependencias

| # | Dónde | Qué pasaba | Corrección |
|---|---|---|---|
| H30 | `frontend/package-lock.json` | Angular 21.2.6 con 7 vulnerabilidades publicadas (`npm audit`: 4 altas, 3 medias). Cuatro son **bypass del sanitizador de Angular (XSS)** (GHSA-58w9-8g37-x9v5, GHSA-f3m7-gqxr-g87x, GHSA-jj27-h5hq-8x99, GHSA-hh8m-fm6v-7cvg), justo el mecanismo del que depende la corrección de H24; las demás son DoS y fugas en `HttpTransferCache`. ZAP lo reportó como *Vulnerable JS Library*. | `npm update` dentro de los rangos de `package.json` → todo Angular en **21.2.25**; `npm audit --omit=dev`: **0 vulnerabilidades**. Lección: corregir el código propio no basta si la librería en la que se confía tiene fallos conocidos. |

Notas de mantenimiento (no son vulnerabilidades): `@primeng/themes` está *deprecated* (migrar a `@primeuix/themes`) y `@angular/animations` está *deprecated* en favor de `animate.enter`/`animate.leave`.
