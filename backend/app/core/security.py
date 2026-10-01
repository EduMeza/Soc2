from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import bcrypt
from jose import jwt

from .config import settings


# El secreto JWT proviene exclusivamente de la configuracion del entorno.
# config.py valida que exista y que cumpla los requisitos minimos.
SECRET_KEY = settings.JWT_SECRET
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(
        plain.encode("utf-8"),
        hashed.encode("utf-8"),
    )


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
    )


def get_bootstrap_credentials() -> Optional[Tuple[str, str]]:
    """Devuelve las credenciales iniciales solo si ambas fueron configuradas.

    No existen usuario ni contrasena predeterminados.
    """
    username = (settings.INITIAL_ADMIN_USERNAME or "").strip()
    password = settings.INITIAL_ADMIN_PASSWORD or ""

    if not username or not password:
        return None

    return username, password