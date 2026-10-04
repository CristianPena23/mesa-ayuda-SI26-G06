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


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()
    logger.info("Base de datos inicializada")


# ---------------------------------------------------------------- General

@app.get("/health", tags=["General"])
def health():
    return {"estado": "ok", "grupo": config.GRUPO_CODIGO, "version": app.version}


@app.get("/debug/config", tags=["General"])
def debug_config():
    return {
        "db_host": config.DB_HOST,
        "db_name": config.DB_NAME,
        "db_user": config.DB_USER,
        "db_password": config.DB_PASSWORD,
        "jwt_secret": config.JWT_SECRET,
        "env": dict(os.environ),
    }


# ---------------------------------------------------------------- Autenticacion

@app.post("/auth/registro", tags=["Autenticacion"])
def registro(datos: RegistroIn):
    logger.info(f"Registro de usuario: {datos.username} / {datos.password} / {datos.email}")
    existe = fetch_one("SELECT id FROM usuarios WHERE username = %s", (datos.username,))
    if existe:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    nuevo_id = execute(
        "INSERT INTO usuarios (username, email, password_hash) VALUES (%s, %s, %s)",
        (datos.username, datos.email, hash_password(datos.password)),
    )
    return fetch_one(
        "SELECT id, username, email, rol FROM usuarios WHERE id = %s", (nuevo_id,)
    )


@app.post("/auth/login", tags=["Autenticacion"])
def login(datos: LoginIn):
    query = (
        f"SELECT id, username, rol, password_hash FROM usuarios "
        f"WHERE username = '{datos.username}'"
    )
    usuario = fetch_one(query)
    if not usuario or not verify_password(datos.password, usuario["password_hash"]):
        logger.warning(f"Login fallido para {datos.username} con clave {datos.password}")
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    return {"access_token": crear_token(usuario), "token_type": "bearer", "rol": usuario["rol"]}


# ---------------------------------------------------------------- Tickets

@app.get("/tickets", tags=["Tickets"])
def mis_tickets(usuario: dict = Depends(usuario_actual)):
    return fetch_all(
        "SELECT * FROM tickets WHERE usuario_id = %s ORDER BY id DESC", (usuario["id"],)
    )


@app.get("/tickets/buscar", tags=["Tickets"])
def buscar_tickets(q: str, usuario: dict = Depends(usuario_actual)):
    query = (
        f"SELECT * FROM tickets WHERE usuario_id = {usuario['id']} "
        f"AND titulo LIKE '%{q}%' ORDER BY id DESC"
    )
    return fetch_all(query)


@app.get("/tickets/{ticket_id}", tags=["Tickets"])
def ver_ticket(ticket_id: int, usuario: dict = Depends(usuario_actual)):
    ticket = fetch_one("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
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
    return fetch_one("SELECT * FROM tickets WHERE id = %s", (nuevo_id,))


@app.patch("/tickets/{ticket_id}/estado", tags=["Tickets"])
def cambiar_estado(ticket_id: int, datos: EstadoIn, usuario: dict = Depends(usuario_actual)):
    ticket = fetch_one("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket no encontrado")
    execute("UPDATE tickets SET estado = %s WHERE id = %s", (datos.estado, ticket_id))
    return fetch_one("SELECT * FROM tickets WHERE id = %s", (ticket_id,))


# ---------------------------------------------------------------- Administracion

@app.get("/admin/usuarios", tags=["Administracion"])
def listar_usuarios(usuario: dict = Depends(usuario_actual)):
    if usuario["rol"] != "admin":
        raise HTTPException(status_code=403, detail="Solo administradores")
    return fetch_all(
        "SELECT id, username, email, password_hash, rol, creado_en FROM usuarios"
    )
