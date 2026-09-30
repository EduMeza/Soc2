import os

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - python-dotenv es opcional
    load_dotenv = None


# Longitud minima aceptada para un secreto. No se guarda ningun secreto en el
# codigo: solo se rechazan placeholders conocidos y longitudes insuficientes.
SECRET_MIN_LENGTH = 32
SECRET_PLACEHOLDERS = {
    "change-me-use-long-random",
    "changeme",
    "change-me",
    "secret",
    "jwt-secret",
}


class ConfigurationError(RuntimeError):
    """La aplicacion no debe arrancar con configuracion insegura o incompleta."""


if load_dotenv is not None:
    load_dotenv()


def _require_secret(name: str, value: str) -> str:
    """Valida un secreto obligatoriamente presente en el entorno (sin fallback)."""
    secret = (value or "").strip()
    if not secret:
        raise ConfigurationError(
            f"{name} no esta configurado. Defina la variable de entorno {name} antes "
            f"de iniciar la aplicacion (vease .env.example). No existe valor por defecto."
        )
    if secret.lower() in SECRET_PLACEHOLDERS:
        raise ConfigurationError(
            f"{name} usa un valor de ejemplo conocido. Defina un valor unico y aleatorio."
        )
    if len(secret) < SECRET_MIN_LENGTH:
        raise ConfigurationError(
            f"{name} es demasiado corto: se requieren al menos {SECRET_MIN_LENGTH} caracteres."
        )
    return secret


class Settings:
    APP_ENV: str = os.getenv("APP_ENV", "development")
    APP_HOST: str = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/soc.db")
    # Credenciales de bootstrap opcionales: solo se aplican si estan ambas configuradas.
    INITIAL_USER: str = (os.getenv("INITIAL_USER") or "").strip()
    INITIAL_PASSWORD: str = os.getenv("INITIAL_PASSWORD") or ""
    TIMEZONE: str = os.getenv("TIMEZONE", "America/Asuncion")
    MAX_UPLOAD_MB: int = int(os.getenv("MAX_UPLOAD_MB", "50"))
    MAX_ROWS: int = int(os.getenv("MAX_ROWS", "200000"))
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173")
    GEOIP_DB_PATH: str = os.getenv("GEOIP_DB_PATH", "./data/geoip/GeoLite2-City.mmdb")
    GEOIP_API_KEY: str = os.getenv("GEOIP_API_KEY", "")

    def __init__(self) -> None:
        # Validacion temprana: fallar es preferible a firmar tokens con una clave conocida.
        self.SECRET_KEY = (os.getenv("SECRET_KEY") or "").strip()
        if self.SECRET_KEY:
            self.SECRET_KEY = _require_secret("SECRET_KEY", self.SECRET_KEY)
        self.JWT_SECRET = _require_secret("JWT_SECRET", os.getenv("JWT_SECRET"))


settings = Settings()
