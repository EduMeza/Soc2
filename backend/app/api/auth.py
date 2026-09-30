from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..core import security
from ..core.config import settings
from ..core.database import get_db
from ..models.user import User
from datetime import datetime
from fastapi.security import OAuth2PasswordBearer

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    force_change: bool


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = security.decode_access_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not security.verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = security.create_access_token({"sub": user.username, "force_change": user.force_password_change})
    return {"access_token": token, "token_type": "bearer", "force_change": user.force_password_change}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"username": user.username, "force_change": user.force_password_change}


@router.post("/logout")
def logout():
    # En JWT stateless, el logout se maneja en el frontend borrando el token
    return {"message": "Logged out successfully"}


@router.post("/change-password")
def change_password(req: ChangePasswordRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not security.verify_password(req.current_password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid current password")
    current_user.password_hash = security.hash_password(req.new_password)
    current_user.force_password_change = False
    db.commit()
    return {"message": "Password changed successfully"}


# Bootstrap usuario inicial (solo si INITIAL_USER e INITIAL_PASSWORD estan configurados)
from ..core.database import Base, SessionLocal, engine


def bootstrap_initial_user() -> bool:
    """Crea el usuario inicial unicamente con configuracion explicita del entorno.

    - No se ejecuta sin INITIAL_USER e INITIAL_PASSWORD definidos.
    - No sobrescribe usuarios existentes.
    - No imprime la contrasena.
    - El usuario creado queda con force_password_change=True.
    """
    credentials = security.get_bootstrap_credentials()
    if credentials is None:
        if settings.INITIAL_USER or settings.INITIAL_PASSWORD:
            print(
                "[auth] Bootstrap omitido: se requieren INITIAL_USER e INITIAL_PASSWORD "
                "configurados de forma explicita."
            )
        return False

    username, password = credentials
    with SessionLocal() as db:
        if db.query(User).filter(User.username == username).first():
            return False
        db.add(
            User(
                username=username,
                password_hash=security.hash_password(password),
                force_password_change=True,
            )
        )
        db.commit()
    print("[auth] Usuario inicial creado desde el entorno. Se requiere cambio de contrasena en el primer acceso.")
    return True


Base.metadata.create_all(bind=engine)
bootstrap_initial_user()
