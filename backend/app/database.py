import logging
import os

import pymysql
from pymysql.cursors import DictCursor

from app import config

logger = logging.getLogger("mesa_ayuda")

# --- Cambio de despliegue (Parte 2/3, SI26-G06) -------------------------------
# MySQL exige TLS (require_secure_transport=ON y app_mesa con REQUIRE SSL).
# Si DB_SSL_CA apunta al certificado de la CA del servidor MySQL, la conexión va
# cifrada y se verifica que el certificado del servidor esté firmado por esa CA.
# check_hostname=False porque el certificado autogenerado de MySQL no lleva la IP
# de Tailscale como nombre; la cadena de confianza sí se valida (CERT_REQUIRED).
_SSL_CA = os.getenv("DB_SSL_CA")
_SSL = {"ca": _SSL_CA, "check_hostname": False} if _SSL_CA else None


def get_connection():
    return pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        db=config.DB_NAME,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        cursorclass=DictCursor,
        autocommit=True,
        ssl=_SSL,
    )


def fetch_one(sql, params=None):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()


def fetch_all(sql, params=None):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def execute(sql, params=None):
    """Ejecuta un INSERT/UPDATE y devuelve el id afectado."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.lastrowid


def init_db():
    # --- Cambio de despliegue (Parte 2/3, SI26-G06) ---------------------------
    # El usuario de la aplicación (app_mesa) solo tiene SELECT/INSERT/UPDATE/DELETE.
    # Las tablas las crea el administrador con infra/db/schema.sql (separación de
    # funciones). La creación desde la app solo se ejecuta si DB_INIT_SCHEMA=1.
    if os.getenv("DB_INIT_SCHEMA", "0") != "1":
        logger.info("init_db omitido: el esquema lo administra el DBA (infra/db/schema.sql)")
        return
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(120) NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    rol VARCHAR(20) NOT NULL DEFAULT 'usuario',
                    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    titulo VARCHAR(150) NOT NULL,
                    descripcion TEXT NOT NULL,
                    prioridad VARCHAR(10) NOT NULL DEFAULT 'media',
                    estado VARCHAR(20) NOT NULL DEFAULT 'abierto',
                    usuario_id INT,
                    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
                )
                """
            )
