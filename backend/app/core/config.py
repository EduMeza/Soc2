import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - python-dotenv es opcional
    load_dotenv = None


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "output"

if load_dotenv is not None:
    load_dotenv(PROJECT_ROOT / ".env")

if os.getenv("APP_ENV") == "test" and os.getenv("SOC_TEST_OUTPUT_DIR"):
    OUTPUT_DIR = Path(os.environ["SOC_TEST_OUTPUT_DIR"]).resolve()


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
            f"{name} es demasiado corto: se requieren al menos "
            f"{SECRET_MIN_LENGTH} caracteres."
        )

    return secret


class Settings:
    APP_ENV: str = os.getenv("APP_ENV", "development")
    APP_HOST: str = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))

    DATABASE_URL: str = (
        os.getenv("DATABASE_URL")
        or f"sqlite:///{(DATA_DIR / 'soc.db').as_posix()}"
    )

    # Bootstrap opcional. No existen credenciales predeterminadas.
    INITIAL_ADMIN_USERNAME: str = (
        os.getenv("INITIAL_ADMIN_USERNAME") or ""
    ).strip()
    INITIAL_ADMIN_PASSWORD: str = os.getenv("INITIAL_ADMIN_PASSWORD") or ""

    TIMEZONE: str = os.getenv("TIMEZONE", "America/Asuncion")
    MAX_UPLOAD_MB: int = int(os.getenv("MAX_UPLOAD_MB", "50"))
    MAX_ROWS: int = int(os.getenv("MAX_ROWS", "200000"))
    CORS_ORIGINS: str = os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173",
    )
    GEOIP_DB_PATH: str = os.getenv(
        "GEOIP_DB_PATH",
        "./data/geoip/GeoLite2-City.mmdb",
    )
    GEOIP_API_KEY: str = os.getenv("GEOIP_API_KEY", "")

    def __init__(self) -> None:
        # Fallar temprano es preferible a firmar tokens con una clave insegura.
        self.SECRET_KEY = (os.getenv("SECRET_KEY") or "").strip()

        if self.SECRET_KEY:
            self.SECRET_KEY = _require_secret(
                "SECRET_KEY",
                self.SECRET_KEY,
            )

        self.JWT_SECRET = _require_secret(
            "JWT_SECRET",
            os.getenv("JWT_SECRET"),
        )


settings = Settings()


# Normaliza DATABASE_URL relativa contra PROJECT_ROOT para que el resultado
# no dependa del directorio desde el cual se inicia el backend.
if settings.DATABASE_URL.startswith("sqlite:///"):
    db_file = settings.DATABASE_URL[len("sqlite:///"):]

    if db_file != ":memory:" and not Path(db_file).is_absolute():
        settings.DATABASE_URL = (
            "sqlite:///"
            + (PROJECT_ROOT / db_file).resolve().as_posix()
        )