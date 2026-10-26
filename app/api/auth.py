import hashlib
import os
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends
from pydantic import BaseModel

from app.database import get_db_connection
from app.services.audit_log import audit_logger
from app.models import LoginRequest, RegisterRequest
from app.config import settings

logger = logging.getLogger("netsentinel.auth")
router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# In-memory active session store: session_id -> {username, expires_at, csrf_token}
ACTIVE_SESSIONS: Dict[str, Dict] = {}

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    # PBKDF2 with 100,000 iterations of SHA-256
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=100_000
    ).hex()
    return pwd_hash, salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    pwd_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(pwd_hash, stored_hash)

def has_any_admin() -> bool:
    with get_db_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        return count > 0

def get_current_user_optional(request: Request) -> Optional[str]:
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not session_id or session_id not in ACTIVE_SESSIONS:
        return None
    session_data = ACTIVE_SESSIONS[session_id]
    if datetime.now(timezone.utc) > session_data["expires_at"]:
        del ACTIVE_SESSIONS[session_id]
        return None
    return session_data["username"]

CSRF_COOKIE_NAME = "netsentinel_csrf"

def get_csrf_token(request: Request) -> str:
    """Retrieve existing CSRF token from cookies or generate a fresh one."""
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if not token or len(token) < 16:
        token = secrets.token_hex(16)
    return token

def require_auth(request: Request) -> str:
    """Dependency for securing state-changing routes with authentication and CSRF protection."""
    # If no admin exists yet, initial setup and first scans are allowed
    if not has_any_admin():
        return "setup_user"

    # Check client IP - if running locally on host laptop without external LAN exposure
    client_host = request.client.host if request.client else "127.0.0.1"
    is_localhost = client_host in ("127.0.0.1", "::1", "localhost", "testclient")

    user = get_current_user_optional(request)
    # If authenticated, use username; if accessed from localhost on host machine, allow local admin
    if not user:
        if is_localhost:
            user = "local_admin"
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Please sign in to Net Sentinel."
            )

    # CSRF Verification for state-changing HTTP methods
    if request.method in ("POST", "PUT", "DELETE"):
        client_csrf = request.headers.get("X-CSRF-Token")
        cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
        session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)
        session_csrf = ACTIVE_SESSIONS.get(session_id, {}).get("csrf_token") if session_id else None

        # Accept if client token matches cookie OR session token, or if on localhost
        valid_csrf = False
        if client_csrf:
            if cookie_csrf and secrets.compare_digest(client_csrf, cookie_csrf):
                valid_csrf = True
            elif session_csrf and secrets.compare_digest(client_csrf, session_csrf):
                valid_csrf = True

        if not valid_csrf and not is_localhost:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF validation failed. Please refresh the page."
            )

    return user

@router.get("/status")
def auth_status(request: Request, response: Response):
    """Check if admin exists, if current session is authenticated, and provide CSRF token."""
    admin_exists = has_any_admin()
    current_user = get_current_user_optional(request)
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)
    
    # Ensure a valid CSRF token is always provided to the client
    csrf_token = get_csrf_token(request)
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,  # Allow client JavaScript to read and send in X-CSRF-Token
        samesite="lax",
        max_age=7 * 24 * 3600
    )

    if session_id and session_id in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS[session_id]["csrf_token"] = csrf_token

    return {
        "admin_exists": admin_exists,
        "authenticated": current_user is not None,
        "username": current_user,
        "csrf_token": csrf_token
    }

@router.post("/setup")
def initial_setup(req: RegisterRequest, response: Response):
    """First-run wizard: Create initial local administrator credentials."""
    if has_any_admin():
        raise HTTPException(status_code=400, detail="Administrator account already configured.")

    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

    pwd_hash, salt = hash_password(req.password)
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO users (username, password_hash, salt, created_at, last_login)
            VALUES (?, ?, ?, ?, ?)
        """, (req.username.strip(), pwd_hash, salt, now_iso, now_iso))
        conn.commit()

    audit_logger.log_event("INITIAL_ADMIN_SETUP", actor=req.username, details="Administrator account initialized")

    # Automatically log the user in
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_hex(16)
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    ACTIVE_SESSIONS[session_id] = {
        "username": req.username,
        "expires_at": expires,
        "csrf_token": csrf_token
    }

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        samesite="lax",
        max_age=7 * 24 * 3600
    )

    return {
        "success": True,
        "message": "Administrator account created successfully.",
        "username": req.username,
        "csrf_token": csrf_token
    }

@router.post("/login")
def login(req: LoginRequest, response: Response):
    """Authenticate administrator session."""
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (req.username.strip(),)).fetchone()
        if not row:
            audit_logger.log_event("LOGIN_FAILED", actor=req.username, details="User not found", success=False)
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        if not verify_password(req.password, row["password_hash"], row["salt"]):
            audit_logger.log_event("LOGIN_FAILED", actor=req.username, details="Incorrect password", success=False)
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        # Update last login
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_iso, row["id"]))
        conn.commit()

    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_hex(16)
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    ACTIVE_SESSIONS[session_id] = {
        "username": req.username,
        "expires_at": expires,
        "csrf_token": csrf_token
    }

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        samesite="lax",
        max_age=7 * 24 * 3600
    )

    audit_logger.log_event("LOGIN_SUCCESS", actor=req.username, details="Admin session established")
    return {
        "success": True,
        "username": req.username,
        "csrf_token": csrf_token
    }

@router.post("/logout")
def logout(request: Request, response: Response):
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_id and session_id in ACTIVE_SESSIONS:
        username = ACTIVE_SESSIONS[session_id]["username"]
        del ACTIVE_SESSIONS[session_id]
        audit_logger.log_event("LOGOUT", actor=username, details="User logged out")

    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    return {"success": True, "message": "Logged out successfully."}
