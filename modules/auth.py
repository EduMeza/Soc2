"""Módulo de autenticación para el dashboard SOC 24x7.

Incluye:
- Hash/verify de contraseñas con bcrypt
- Gate de login (Welcome -> Login -> Dashboard)
- RBAC por roles: ADMIN, SOC_ANALYST, SOC_VIEWER, AUDITOR
- Persistencia de usuarios en data/users.json
- Reset de contraseña por admin
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import bcrypt
import streamlit as st

from modules.config import PROJECT_ROOT

# ---------------------------------------------------------------------------
# Configuración de almacenamiento
# ---------------------------------------------------------------------------
USERS_FILE = PROJECT_ROOT / "data" / "users.json"

# Roles válidos
VALID_ROLES = ["ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR"]

# Usuario por defecto (se crea al inicializar si no existe)
DEFAULT_USERS = {
    "admin": {
        "document_number": "admin",
        "name": "Administrador SOC",
        "role": "ADMIN",
        "password_hash": None,  # Se genera al inicializar
        "status": "ACTIVE",
        "must_change_password": False,
    }
}


# ---------------------------------------------------------------------------
# Utilidades de contraseña
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Genera hash bcrypt de la contraseña."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verifica contraseña contra hash bcrypt."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Gestión de usuarios (JSON local)
# ---------------------------------------------------------------------------
def _load_users() -> dict:
    """Carga usuarios desde archivo JSON."""
    if not USERS_FILE.exists():
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_users(users: dict) -> None:
    """Guarda usuarios en archivo JSON."""
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def ensure_users_initialized() -> None:
    """Crea usuario admin/admin por defecto si no existe."""
    users = _load_users()
    if "admin" not in users:
        users["admin"] = DEFAULT_USERS["admin"].copy()
        users["admin"]["password_hash"] = hash_password("admin")
        _save_users(users)


def get_user(document_number: str) -> Optional[dict]:
    """Obtiene usuario por número de documento."""
    users = _load_users()
    return users.get(document_number)


def authenticate_user(document_number: str, password: str) -> Optional[dict]:
    """Autentica usuario y devuelve sus datos si es válido."""
    user = get_user(document_number)
    if not user:
        return None
    if user.get("status") != "ACTIVE":
        return None
    if not verify_password(password, user.get("password_hash", "")):
        return None
    return user


def admin_reset_password(target_doc: str, new_password: str) -> tuple[bool, str]:
    """Admin resetea contraseña de otro usuario."""
    users = _load_users()
    if target_doc not in users:
        return False, "Usuario no encontrado"
    users[target_doc]["password_hash"] = hash_password(new_password)
    users[target_doc]["must_change_password"] = True
    users[target_doc]["status"] = "ACTIVE"
    _save_users(users)
    return True, f"Contraseña reseteada para {target_doc}"


# ---------------------------------------------------------------------------
# Gate de login (Welcome -> Login -> Dashboard)
# ---------------------------------------------------------------------------
def gate_login() -> None:
    """Muestra formulario de login y maneja autenticación.

    Flujo:
    1. Usuario ingresa document_number y password
    2. Si válido -> setea session_state y rerun para entrar al dashboard
    3. Si inválido -> muestra error
    """
    st.markdown("""
    <style>
    [data-testid="stSidebar"] { display: none; }
    [data-testid="stSidebarCollapsedControl"] { display: none; }
    </style>
    """, unsafe_allow_html=True)

    col_l, col_c, col_r = st.columns([1, 2, 1], gap="large")

    with col_c:
        st.markdown("""
        <div style='text-align:center;margin-bottom:2rem;'>
            <div class='soc-brand' style='font-size:2rem;'>
                <span class='dot'>🛡️</span> SOC 24x7
            </div>
            <p style='color:var(--muted);'>Iniciar sesión para acceder al Centro de Operaciones</p>
        </div>
        """, unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            document_number = st.text_input(
                "📄 Número de documento",
                placeholder="Ej: admin",
                autocomplete="username",
            )
            password = st.text_input(
                "🔐 Contraseña",
                type="password",
                placeholder="Ej: admin",
                autocomplete="current-password",
            )
            submitted = st.form_submit_button("INGRESAR", type="primary", width="stretch")

            if submitted:
                if not document_number or not password:
                    st.error("Completa ambos campos")
                else:
                    user = authenticate_user(document_number.strip(), password)
                    if user:
                        # Login exitoso - setear session state
                        st.session_state["authentication_status"] = True
                        st.session_state["auth_doc_manual"] = document_number.strip()
                        st.session_state["username"] = user["name"]
                        st.session_state["auth_user"] = document_number.strip()
                        st.session_state["auth_role"] = user["role"]
                        st.session_state["auth_is_admin"] = (user["role"] == "ADMIN")
                        st.session_state["_show_login"] = False  # No volver al login
                        st.toast(f"✅ Bienvenido, {user['name']} ({user['role']})", icon="🛡️")
                        st.rerun()
                    else:
                        st.error("Credenciales incorrectas o usuario inactivo")

        st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)
        st.caption("Acceso restringido a personal autorizado del SOC")


# ---------------------------------------------------------------------------
# RBAC - Control de acceso por roles
# ---------------------------------------------------------------------------
def require_role(*allowed_roles: str, view_name: str = "vista") -> None:
    """Verifica que el usuario autenticado tenga uno de los roles permitidos.

    Args:
        *allowed_roles: Roles que tienen acceso (ej: "ADMIN", "SOC_ANALYST")
        view_name: Nombre de la vista para mensaje de error

    Si no tiene permiso, muestra error y detiene renderizado (st.stop()).
    """
    # Verificar autenticación
    if not st.session_state.get("authentication_status", False):
        st.warning("🔒 Debes iniciar sesión para acceder")
        st.stop()

    user_role = st.session_state.get("auth_role", "SOC_VIEWER")

    # ADMIN tiene acceso a todo
    if user_role == "ADMIN":
        return

    # Verificar rol en permitidos
    if user_role not in allowed_roles:
        st.error(f"🚫 Acceso denegado: {view_name} requiere uno de: {', '.join(allowed_roles)}")
        st.caption(f"Tu rol actual: {user_role}")
        st.stop()


def get_current_user() -> dict:
    """Devuelve info del usuario actual desde session_state."""
    return {
        "name": st.session_state.get("username", "Usuario"),
        "document_number": st.session_state.get("auth_doc_manual", ""),
        "role": st.session_state.get("auth_role", "SOC_VIEWER"),
        "is_admin": st.session_state.get("auth_is_admin", False),
    }


def logout() -> None:
    """Cierra sesión limpiando session_state."""
    keys_to_clear = [
        "authentication_status", "auth_doc_manual", "username",
        "auth_user", "auth_role", "auth_is_admin", "_show_login"
    ]
    for key in keys_to_clear:
        st.session_state.pop(key, None)
    st.rerun()