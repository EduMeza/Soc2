from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from jose import JWTError
from app.core import security
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User
from app.models.persistence import AuditLog, now
from app.services.audit import audit

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/auth/login')

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=72)

def bootstrap(db):
    if db.query(User).count() or not settings.INITIAL_ADMIN_USERNAME:
        return
    password = settings.INITIAL_ADMIN_PASSWORD
    if len(password) < 8 or len(password.encode()) > 72:
        raise ValueError('INITIAL_ADMIN_PASSWORD debe tener al menos 8 caracteres y como máximo 72 bytes')
    db.add(User(username=settings.INITIAL_ADMIN_USERNAME,
                password_hash=security.hash_password(password), force_password_change=True))
    db.commit()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = security.decode_access_token(token)
        user = db.query(User).filter_by(username=payload.get('sub')).first()
        if not user or payload.get('version') != user.token_version:
            raise HTTPException(401, 'Token inválido')
        return user
    except JWTError:
        raise HTTPException(401, 'Token inválido o expirado')

def require_soc_user(user: User = Depends(get_current_user)):
    if user.force_password_change:
        raise HTTPException(403, 'Debe cambiar su contraseña antes de acceder al SOC')
    return user

@router.post('/login')
def login(req: LoginRequest, db: Session = Depends(get_db)):
    failures = db.query(AuditLog).filter(AuditLog.username == req.username,
        AuditLog.action == 'LOGIN_FAILURE', AuditLog.timestamp > now() - timedelta(minutes=30)).count()
    if failures >= 5:
        raise HTTPException(429, 'Demasiados intentos. Espere 30 minutos.')
    user = db.query(User).filter_by(username=req.username).first()
    try:
        valid = user is not None and security.verify_password(req.password, user.password_hash)
    except ValueError:
        valid = False
    if not valid:
        audit(db, req.username, 'LOGIN_FAILURE', 'failure')
        db.commit()
        raise HTTPException(401, 'Credenciales inválidas')
    token = security.create_access_token({'sub': user.username, 'version': user.token_version})
    audit(db, user.username, 'LOGIN_SUCCESS')
    db.commit()
    return {'access_token': token, 'token_type': 'bearer', 'force_change': user.force_password_change}

@router.get('/me')
def me(user=Depends(get_current_user)):
    return {'username': user.username, 'force_change': user.force_password_change}

@router.post('/logout')
def logout(user=Depends(get_current_user), db: Session = Depends(get_db)):
    user.token_version += 1
    db.commit()
    return {'message': 'Sesión cerrada'}

@router.post('/change-password')
def change_password(req: ChangePasswordRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):
    if not security.verify_password(req.current_password, user.password_hash):
        raise HTTPException(400, 'Contraseña actual incorrecta')
    if len(req.new_password.encode()) > 72:
        raise HTTPException(422, 'Contraseña demasiado larga')
    user.password_hash = security.hash_password(req.new_password)
    user.force_password_change = False
    user.token_version += 1
    audit(db, user.username, 'PASSWORD_CHANGE')
    db.commit()
    return {'access_token': security.create_access_token({'sub': user.username, 'version': user.token_version})}
