from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..core import security
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


# Bootstrap usuario inicial si no existe
from ..core.database import Base, SessionLocal, engine
Base.metadata.create_all(bind=engine)

with SessionLocal() as db:
    if not db.query(User).filter(User.username == security.INITIAL_USER).first():
        new_user = User(
            username=security.INITIAL_USER,
            password_hash=security.hash_password(security.INITIAL_PASSWORD),
            force_password_change=False
        )
        db.add(new_user)
        db.commit()