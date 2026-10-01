import os
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / '.env')
DATA_DIR = PROJECT_ROOT / 'data'
OUTPUT_DIR = PROJECT_ROOT / 'output'
if os.getenv('APP_ENV') == 'test' and os.getenv('SOC_TEST_OUTPUT_DIR'):
    OUTPUT_DIR = Path(os.environ['SOC_TEST_OUTPUT_DIR']).resolve()

class Settings:
    APP_ENV: str = os.getenv("APP_ENV", "development")
    APP_HOST: str = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
    DATABASE_URL: str = os.getenv("DATABASE_URL") or f"sqlite:///{(DATA_DIR / 'soc.db').as_posix()}"
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    INITIAL_ADMIN_USERNAME: str = os.getenv('INITIAL_ADMIN_USERNAME', '')
    INITIAL_ADMIN_PASSWORD: str = os.getenv('INITIAL_ADMIN_PASSWORD', '')
    TIMEZONE: str = os.getenv("TIMEZONE", "America/Asuncion")
    MAX_UPLOAD_MB: int = int(os.getenv("MAX_UPLOAD_MB", "50"))
    MAX_ROWS: int = int(os.getenv("MAX_ROWS", "200000"))
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173")
    GEOIP_DB_PATH: str = os.getenv("GEOIP_DB_PATH", "./data/geoip/GeoLite2-City.mmdb")
    GEOIP_API_KEY: str = os.getenv("GEOIP_API_KEY", "")

settings = Settings()
if settings.DATABASE_URL.startswith('sqlite:///'):
    db_file = settings.DATABASE_URL[len('sqlite:///'):]
    if db_file != ':memory:' and not Path(db_file).is_absolute():
        settings.DATABASE_URL = 'sqlite:///' + (PROJECT_ROOT / db_file).resolve().as_posix()
