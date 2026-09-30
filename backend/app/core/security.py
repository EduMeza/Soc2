import bcrypt
from jose import jwt
from datetime import datetime, timedelta
from typing import Optional, Tuple
from .config import settings

# Secreto JWT obligatorio: proviene exclusivamente de la configuracion del entorno.
# No hay valor por defecto ni generacion automatica (ver core/config.py).
SECRET_KEY = settings.JWT_SECRET
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def get_bootstrap_credentials() -> Optional[Tuple[str, str]]:
    """Credenciales de bootstrap tomadas del entorno.

    Devuelve (usuario, contrasena) solo si INITIAL_USER e INITIAL_PASSWORD estan
    ambas configuradas. En cualquier otro caso devuelve None y no se crea ningun
    usuario. Nunca genera ni devuelve una contrasena por defecto.
    """
    username = (settings.INITIAL_USER or "").strip()
    password = settings.INITIAL_PASSWORD or ""
    if not username or not password:
        return None
    return username, password
