import logging
import os
from logging.handlers import RotatingFileHandler

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.database import execute, fetch_all, fetch_one, init_db
from app.schemas import EstadoIn, LoginIn, RegistroIn, TicketIn
from app.security import crear_token, hash_password, usuario_actual, verify_password

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("mesa_ayuda")

# --- Auditoría de autenticación (D2, SI26-G06) -------------------------------
# Registra los intentos de login FALLIDOS en /app/logs/app.log (montado en el host
# como /var/log/mesa_ayuda/app.log). El agente Wazuh de sg-backend lee ese archivo.
# Se registra la IP real del cliente (X-Real-IP que pone Nginx) y NUNCA la contraseña.
_audit_logger = logging.getLogger("mesa_ayuda_audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False
try:
    os.makedirs("/app/logs", exist_ok=True)
    _handler = RotatingFileHandler("/app/logs/app.log", maxBytes=1_000_000, backupCount=3)
    _handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _audit_logger.addHandler(_handler)
except Exception as exc:  # pragma: no cover
    logger.warning(f"No se pudo abrir el log de auditoria: {exc}")


def _ip_cliente(request: Request) -> str:
    # Nginx entrega la IP real en X-Real-IP (que a su vez saca de CF-Connecting-IP,
    # y solo confía en ese encabezado si viene de la red interna de Docker).
    ip = request.headers.get("x-real-ip")
    if not ip:
        xff = request.headers.get("x-forwarded-for", "")
        ip = xff.split(",")[0].strip() if xff else ""
    if not ip and request.client:
        ip = request.client.host
    return ip or "-"


app = FastAPI(
    title="Mesa de Ayuda API",
    description="API de la Mesa de Ayuda - Seguridad Informatica UMNG 2026-II",
    version="2.0.0",
    # Parte 6: /docs, /redoc y /openapi.json describen toda la API a un atacante.
    # Se apagan en produccion; se encienden solo con ENABLE_DOCS=1.
    docs_url="/docs" if os.getenv("ENABLE_DOCS") == "1" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.getenv("ENABLE_DOCS") == "1" else None,
)


@app.middleware("http")
async def auditoria_autenticacion(request: Request, call_next):
    response = await call_next(request)
    try:
        if request.url.path == "/auth/login" and response.status_code == 401:
            _audit_logger.info(
                f'mesa_ayuda AUTH_FAIL src_ip={_ip_cliente(request)} path={request.url.path}'
            )
    except Exception:  # pragma: no cover
        pass
    return response


# --- CORS (Parte 6, corrige H16) -------------------------------------------------
# Antes: allow_origins=["*"] con allow_credentials=True (cualquier sitio podia usar
# la API en nombre del usuario). El frontend llama a /api por el MISMO dominio
# (Nginx hace de proxy), asi que no necesita CORS. Solo se habilita si se define
# CORS_ORIGINS con una lista explicita de origenes.
_CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if _CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_CORS_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.on_event("startup")
def startup():
    init_db()
    logger.info("Base de datos inicializada")


# ---------------------------------------------------------------- General

@app.get("/health", tags=["General"])
def health():
    return {"estado": "ok", "grupo": config.GRUPO_CODIGO, "version": app.version}


# Parte 6 (corrige H14): se ELIMINO el endpoint /debug/config, que devolvia sin
# autenticacion la clave de la BD, el JWT_SECRET y todas las variables de entorno.


# ---------------------------------------------------------------- Autenticacion

@app.post("/auth/registro", tags=["Autenticacion"], responses={400: {"description": "El usuario ya existe"}})
def registro(datos: RegistroIn):
    existe = fetch_one("SELECT id FROM usuarios WHERE username = %s", (datos.username,))
    if existe:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    nuevo_id = execute(
        "INSERT INTO usuarios (username, email, password_hash) VALUES (%s, %s, %s)",
        (datos.username, datos.email, hash_password(datos.password)),
    )
    # Parte 6 (corrige H15 y hallazgo de Bearer CWE-532): el log no lleva la
    # contrasena, ni el correo, ni el nombre de usuario (datos personales, Ley 1581).
    # Solo el id interno, que sirve para auditar sin exponer a la persona.
    logger.info("Registro de usuario nuevo id=%s", nuevo_id)
    return fetch_one(
        "SELECT id, username, email, rol FROM usuarios WHERE id = %s", (nuevo_id,)
    )


_HASH_RELLENO = hash_password("relleno-para-igualar-tiempos")


@app.post("/auth/login", tags=["Autenticacion"], responses={401: {"description": "Credenciales invalidas"}})
def login(datos: LoginIn):
    # Parte 6 (corrige H12): consulta PARAMETRIZADA. El %s lo rellena el driver
    # (PyMySQL) escapando el valor, asi que "admin' OR '1'='1" se busca como un
    # nombre de usuario literal y no cambia la consulta.
    usuario = fetch_one(
        "SELECT id, username, rol, password_hash FROM usuarios WHERE username = %s",
        (datos.username,),
    )
    # Si el usuario no existe se verifica contra un hash de relleno, para que la
    # respuesta tarde lo mismo y no se pueda adivinar que usuarios existen.
    hash_guardado = usuario["password_hash"] if usuario else _HASH_RELLENO
    if not verify_password(datos.password, hash_guardado) or not usuario:
        # Parte 6 (corrige H15 y hallazgo de Bearer CWE-532): ni la contrasena ni
        # el usuario intentado van al log (a veces la gente escribe su clave en el
        # campo de usuario). La IP de origen ya la registra el log de auditoria
        # (AUTH_FAIL), que es lo que Wazuh usa para detectar fuerza bruta.
        logger.warning("Login fallido")
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    return {"access_token": crear_token(usuario), "token_type": "bearer", "rol": usuario["rol"]}


# ---------------------------------------------------------------- Tickets

ESTADOS_VALIDOS = {"abierto", "en_progreso", "cerrado"}
SQL_TICKET_POR_ID = "SELECT * FROM tickets WHERE id = %s"


def _ticket_autorizado(ticket_id: int, usuario: dict):
    """Parte 6 (corrige H17 y H18 - IDOR): devuelve el ticket solo si pertenece al
    usuario o si el usuario es admin. Si no, responde igual que si no existiera
    (404), para no revelar que ese numero de ticket existe."""
    if usuario["rol"] == "admin":
        return fetch_one(SQL_TICKET_POR_ID, (ticket_id,))
    return fetch_one(
        "SELECT * FROM tickets WHERE id = %s AND usuario_id = %s",
        (ticket_id, usuario["id"]),
    )


@app.get("/tickets", tags=["Tickets"])
def mis_tickets(usuario: dict = Depends(usuario_actual)):
    return fetch_all(
        "SELECT * FROM tickets WHERE usuario_id = %s ORDER BY id DESC", (usuario["id"],)
    )


@app.get("/tickets/buscar", tags=["Tickets"], responses={400: {"description": "Busqueda demasiado larga"}})
def buscar_tickets(q: str, usuario: dict = Depends(usuario_actual)):
    # Parte 6 (corrige H13): consulta PARAMETRIZADA; un "' UNION SELECT ..." ya no
    # puede leer otras tablas. Se escapan % y _ para que se busquen literalmente.
    if len(q) > 100:
        raise HTTPException(status_code=400, detail="Busqueda demasiado larga")
    patron = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    return fetch_all(
        "SELECT * FROM tickets WHERE usuario_id = %s AND titulo LIKE %s ORDER BY id DESC",
        (usuario["id"], patron),
    )


@app.get("/tickets/{ticket_id}", tags=["Tickets"], responses={404: {"description": "Ticket no encontrado o ajeno"}})
def ver_ticket(ticket_id: int, usuario: dict = Depends(usuario_actual)):
    ticket = _ticket_autorizado(ticket_id, usuario)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")
    return ticket


@app.post("/tickets", tags=["Tickets"])
def crear_ticket(datos: TicketIn, usuario: dict = Depends(usuario_actual)):
    nuevo_id = execute(
        "INSERT INTO tickets (titulo, descripcion, prioridad, usuario_id) "
        "VALUES (%s, %s, %s, %s)",
        (datos.titulo, datos.descripcion, datos.prioridad, usuario["id"]),
    )
    return fetch_one(SQL_TICKET_POR_ID, (nuevo_id,))


@app.patch(
    "/tickets/{ticket_id}/estado",
    tags=["Tickets"],
    responses={
        400: {"description": "Estado no valido"},
        404: {"description": "Ticket no encontrado o ajeno"},
    },
)
def cambiar_estado(ticket_id: int, datos: EstadoIn, usuario: dict = Depends(usuario_actual)):
    if datos.estado not in ESTADOS_VALIDOS:
        raise HTTPException(status_code=400, detail="Estado no valido")
    ticket = _ticket_autorizado(ticket_id, usuario)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")
    execute("UPDATE tickets SET estado = %s WHERE id = %s", (datos.estado, ticket_id))
    return fetch_one(SQL_TICKET_POR_ID, (ticket_id,))


# ---------------------------------------------------------------- Administracion

@app.get("/admin/usuarios", tags=["Administracion"], responses={403: {"description": "Solo administradores"}})
def listar_usuarios(usuario: dict = Depends(usuario_actual)):
    if usuario["rol"] != "admin":
        raise HTTPException(status_code=403, detail="Solo administradores")
    return fetch_all(
        # Parte 6 (corrige H19): ya no se devuelve password_hash.
        "SELECT id, username, email, rol, creado_en FROM usuarios"
    )
