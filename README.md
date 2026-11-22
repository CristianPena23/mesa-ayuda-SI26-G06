Mesa de Ayuda · Despliegue seguro, monitoreo y ciclo DevSecOps (SI26-G06)

Aplicación de mesa de ayuda (tickets de soporte) desplegada sobre cuatro nodos con defensa en profundidad, monitoreada con Wazuh y auditada y corregida con un ciclo DevSecOps. Proyecto del parcial de Seguridad Informática, Ingeniería Multimedia, Universidad Militar Nueva Granada.

	
Aplicación	Backend FastAPI + MySQL, frontend Angular servido con Nginx
Infraestructura	4 VM con Multipass, red privada Tailscale con ACL por etiquetas, túnel de Cloudflare
Monitoreo	Wazuh 4.14 (6 agentes), reglas personalizadas y respuesta activa
Auditoría	SonarQube, Bearer, OWASP ZAP, npm audit y revisión manual
Referencias	OWASP Top 10:2021, CWE, MITRE ATT&CK, ISO/IEC 27001:2022
Equipo	Cristian Camilo Peña Garzón · Laura Robayo
Arquitectura
Usuario ──HTTPS──▶ Cloudflare ──túnel saliente──▶ Nginx (nodo frontend)
                                                     │ /api por la red privada
                                                     ▼
                                        FastAPI en Docker (nodo backend)
                                                     │ TLS
                                                     ▼
                                              MySQL (nodo db)

Todos los nodos ──eventos──▶ Wazuh (nodo security)
sg-robayo-db, sg-robayo-backend y sg-robayo-frontend corren como VM Multipass.
sg-robayo-security aloja Wazuh en otro equipo, porque requiere más RAM.
Ningún nodo abre puertos a Internet: el tráfico público entra por un túnel de salida de Cloudflare.
Se intentó usar nube (Oracle y Azure), pero no fue posible por capacidad y validación de cuenta, así que se optó por virtualización local.
Controles de seguridad por capa
Capa	Controles	ISO 27001:2022
Red	Tailscale con ACL por etiquetas (tag:db, tag:backend, tag:frontend, tag:security), todo denegado por defecto; cada servicio solo es alcanzable desde el nodo que lo necesita	8.20
Host	Firewall ufw con entrada denegada por defecto; SSH solo por llave, sin root y con máximo 3 intentos; actualizaciones automáticas de seguridad; script de bastionado bootstrap-nodo.sh	8.5
Perímetro	Túnel de Cloudflare sin puertos abiertos; Nginx con Content-Security-Policy, Strict-Transport-Security, X-Frame-Options y nosniff; límite de 10 intentos por minuto en el login (HTTP 429)	8.20
Aplicación	Contenedor sin privilegios (usuario no root), puerto publicado solo en la IP de la red privada, consultas parametrizadas, JWT firmado, contraseñas con scrypt, secretos fuera del repositorio	8.28, 8.5
Datos	MySQL con require_secure_transport, skip_name_resolve, escucha solo en la red privada y usuario de aplicación con mínimo privilegio; respaldos diarios cifrados con age (clave privada fuera del servidor)	8.24, 8.13
Monitoreo	Wazuh con 6 agentes, decodificador y reglas propias sobre el log de auditoría del backend, integridad de archivos y respuesta activa	8.15, 8.16

Docker publica puertos saltándose ufw, por lo que el puerto del backend se publica únicamente en la IP de la red privada.

Detección y respuesta (Wazuh)
Escenario	Detección	Resultado
Fuerza bruta contra el login de la app	Regla 100100 por cada fallo y regla 100106 con 5 o más fallos en 60 s desde la misma IP (nivel 10, MITRE T1110)	Alerta con agente e IP del atacante
Modificación de archivo sensible	Integridad de archivos (regla 550) con hashes antes y después	Alerta en tiempo real; también se vigila el .env sin exponer su contenido
Fuerza bruta SSH	Regla 5712 y respuesta activa firewall-drop (regla 651)	IP del atacante bloqueada 180 s

Durante las pruebas se encontró un punto ciego: el filtro de integridad no coincidía con el .env. Se corrigió (hallazgo H29).

Ciclo DevSecOps

El código original está marcado con el tag v-base y las correcciones van encima, en commits separados por hallazgo o grupo lógico, en la rama pena_robayo.

30 hallazgos documentados en docs/, con 12 fichas completas en el informe: identificación, clasificación, causa raíz, detección, demostración del impacto, corrección y verificación.
Entre los hallazgos corregidos: inyección SQL en login y búsqueda, JWT sin verificación de firma, contraseñas con MD5, IDOR en tickets, XSS almacenado, endpoint /debug/config expuesto y secretos en el repositorio.
Secretos en el repositorio: borrarlos en un commit nuevo no basta porque quedan en el historial. Se rotaron (nuevo JWT_SECRET de 64 caracteres y nueva clave de base de datos) y se comprobó que los anteriores ya no funcionan.
Verificación: el script infra/pruebas/pruebas-parte6.ps1 repite contra la aplicación desplegada los 11 ataques que funcionaban en la versión original; en la versión corregida todos quedan bloqueados y la aplicación sigue funcionando.
Resultados antes y después
Herramienta	Antes	Después
SonarQube, backend	D en seguridad y confiabilidad	A
SonarQube, frontend	E	A
Bearer	4 críticos y 3 medios	0 (4 falsos positivos documentados en bearer.ignore)
OWASP ZAP	11 advertencias	6, justificadas en el informe
npm audit (Angular)	7 vulnerabilidades	0 (actualización a 21.2.25)

Lección clave: ninguna herramienta sola encontró todo. SonarQube Community no detectó la inyección SQL; se halló con revisión manual y se confirmó con ataques reales. Por eso la verificación final fue atacar la aplicación desplegada.

Estructura del repositorio
mesa-ayuda-SI26-G06/
├── backend/      # API FastAPI
├── frontend/     # Angular + Nginx
├── infra/
│   ├── tailscale-acl.hujson   # ACL de la red privada
│   ├── bootstrap-nodo.sh      # bastionado de cada nodo
│   ├── wazuh/                 # reglas, decodificadores y scripts de ataque
│   └── pruebas/               # pruebas de verificación de la Parte 6
└── docs/         # reportes de Bearer y ZAP, hallazgos e informe
Reparto del trabajo
Cristian Peña: infraestructura de los nodos (red privada, ACL, firewall, SSH), backend en Docker, frontend con Nginx y túnel, y corrección del código en el ciclo DevSecOps.
Laura Robayo: Wazuh con sus agentes, detecciones de integridad y fuerza bruta SSH, y respuesta activa.
En conjunto: base de datos MySQL y mapeo a ISO 27001.
Nota

Proyecto académico. Los secretos reales (.env, claves, tokens) no forman parte del repositorio; solo se incluye .env.example.
