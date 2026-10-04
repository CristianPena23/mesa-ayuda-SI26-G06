import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Header, HTTPException

from app import config

# =============================================================================
# Contraseñas (Parte 6, SI26-G06) - corrige H22
# Antes: MD5 sin sal (rápido y sin sal = se rompe con diccionarios y tablas
# precalculadas). Ahora: scrypt de la librería estándar, con sal aleatoria por
# usuario y parámetros costosos en memoria y CPU (recomendación OWASP:
# N=2^15, r=8, p=3). No agrega dependencias externas.
# Formato guardado: scrypt$N$r$p$sal_b64$hash_b64  (cabe en VARCHAR(255)).
# =============================================================================
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 3
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hash_password(password: str) -> str:
    sal = secrets.token_bytes(16)
    derivada = hashlib.scrypt(
        password.encode(), salt=sal, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN, maxmem=_SCRYPT_MAXMEM,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(sal)}${_b64(derivada)}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        alg, n, r, p, sal_b64, hash_b64 = password_hash.split("$")
        if alg != "scrypt":
            return False
        esperado = base64.b64decode(hash_b64)
        derivada = hashlib.scrypt(
            password.encode(), salt=base64.b64decode(sal_b64), n=int(n), r=int(r),
            p=int(p), dklen=len(esperado), maxmem=_SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError):
        # Hash con formato viejo (MD5) o dañado: no se acepta.
        return False
    # Comparación en tiempo constante (no revela cuántos bytes coinciden).
    return hmac.compare_digest(derivada, esperado)


# =============================================================================
# Tokens JWT (Parte 6, SI26-G06) - corrige H28 y refuerza H4
# Antes: jwt.decode(..., options={"verify_signature": False}) -> la API aceptaba
# CUALQUIER token, incluso uno fabricado a mano con rol=admin.
# Ahora: se verifica la firma, el algoritmo queda fijo y el token caduca.
# =============================================================================
_ALGORITMOS_PERMITIDOS = {"HS256", "HS384", "HS512"}
_JWT_ALG = config.JWT_ALGORITHM if config.JWT_ALGORITHM in _ALGORITMOS_PERMITIDOS else "HS256"
_JWT_MINUTOS = int(os.getenv("JWT_EXP_MINUTES", "60"))

# Falla cerrado: si el secreto es débil (como el "mesa-ayuda-secret-2026" del
# repo base), la API NO arranca. Se genera uno nuevo con: openssl rand -hex 32
if not config.JWT_SECRET or len(config.JWT_SECRET) < 32:
    raise RuntimeError(
        "JWT_SECRET ausente o demasiado corto (minimo 32 caracteres). "
        "Genere uno con: openssl rand -hex 32"
    )


def crear_token(usuario: dict) -> str:
    ahora = datetime.now(timezone.utc)
    payload = {
        "sub": str(usuario["id"]),
        "username": usuario["username"],
        "rol": usuario["rol"],
        "iat": ahora,
        "exp": ahora + timedelta(minutes=_JWT_MINUTOS),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=_JWT_ALG)


def usuario_actual(authorization: str = Header(default="")) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token requerido")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(
            token,
            config.JWT_SECRET,
            algorithms=[_JWT_ALG],  # solo el algoritmo esperado (bloquea "none")
            options={"require": ["exp", "iat", "sub"]},  # firma y caducidad obligatorias
        )
        return {
            "id": int(payload["sub"]),
            "username": payload.get("username"),
            "rol": payload.get("rol", "usuario"),
        }
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Token inválido")
