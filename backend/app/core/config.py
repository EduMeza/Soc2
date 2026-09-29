import os

class Settings:
    APP_ENV: str = os.getenv("APP_ENV", "development")
    APP_HOST: str = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/soc.db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-use-long-random")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me-use-long-random")
    TIMEZONE: str = os.getenv("TIMEZONE", "America/Asuncion")
    MAX_UPLOAD_MB: int = int(os.getenv("MAX_UPLOAD_MB", "50"))
    MAX_ROWS: int = int(os.getenv("MAX_ROWS", "200000"))
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173")
    GEOIP_DB_PATH: str = os.getenv("GEOIP_DB_PATH", "./data/geoip/GeoLite2-City.mmdb")
    GEOIP_API_KEY: str = os.getenv("GEOIP_API_KEY", "")

settings = Settings()
