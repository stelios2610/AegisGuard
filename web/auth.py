"""AegisGuard session-based authentication (no extra dependencies)."""
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from db import database

try:
    import bcrypt as _bcrypt
    _BCRYPT_OK = True
except ImportError:
    _BCRYPT_OK = False

# In-memory session store: {token: {"user": str, "expires": datetime}}
_sessions: dict = {}

COOKIE_NAME = "aegisguard_session"
SESSION_HOURS = 8

# Routes that don't require login
PUBLIC_ROUTES = {"/login", "/favicon.ico"}

# Only the admin (settings-based) can log in — multi-user auth_users table
# entries are stored but cannot log in through the standard login flow.
# This enforces single-admin control over all GUI operations.

# ── Login rate limiting ───────────────────────────────────────────────────────
_login_attempts: dict = {}   # {ip: [datetime, ...]}
_LOGIN_MAX = 10
_LOGIN_WINDOW = 60           # seconds


def is_rate_limited(ip: str) -> bool:
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=_LOGIN_WINDOW)
    attempts = [t for t in _login_attempts.get(ip, []) if t > cutoff]
    attempts.append(now)
    _login_attempts[ip] = attempts
    return len(attempts) > _LOGIN_MAX


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    if _BCRYPT_OK:
        hashed = _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=12))
        return f"bcrypt:{hashed.decode()}"
    # Fallback to sha256 if bcrypt not available
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"sha256:{salt}:{h}"


def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash:
        return False
    try:
        if stored_hash.startswith("bcrypt:"):
            if not _BCRYPT_OK:
                return False
            stored = stored_hash[7:].encode()
            return _bcrypt.checkpw(password.encode(), stored)
        # Legacy sha256 format
        algo, salt, h = stored_hash.split(":", 2)
        return hmac.compare_digest(
            hashlib.sha256(f"{salt}{password}".encode()).hexdigest(), h
        )
    except Exception:
        return False


def ensure_default_admin():
    """Create default admin if no password is set."""
    current = database.get_setting("admin_password_hash", "")
    if not current:
        database.set_setting("admin_password_hash", hash_password("admin"))
        database.set_setting("admin_username", "admin")


# ── Session management ────────────────────────────────────────────────────────

def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        "user": username,
        "expires": datetime.utcnow() + timedelta(hours=SESSION_HOURS),
    }
    _cleanup_sessions()
    return token


def get_session_user(request: Request) -> Optional[str]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    session = _sessions.get(token)
    if not session:
        return None
    if datetime.utcnow() > session["expires"]:
        _sessions.pop(token, None)
        return None
    return session["user"]


def delete_session(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        _sessions.pop(token, None)


def _cleanup_sessions():
    now = datetime.utcnow()
    expired = [t for t, s in _sessions.items() if now > s["expires"]]
    for t in expired:
        _sessions.pop(t, None)


# ── Auth check (use as dependency or middleware) ──────────────────────────────

def require_auth(request: Request) -> Optional[RedirectResponse]:
    """Returns a redirect to /login if not authenticated, else None."""
    path = request.url.path
    if path in PUBLIC_ROUTES or path.startswith("/static"):
        return None
    if get_session_user(request) is None:
        safe_next = path if path.startswith("/") and not path.startswith("//") else "/"
        return RedirectResponse(url=f"/login?next={safe_next}", status_code=302)
    return None


# ── Login / logout logic ──────────────────────────────────────────────────────

def attempt_login(username: str, password: str) -> bool:
    stored_user = database.get_setting("admin_username", "admin")
    stored_hash = database.get_setting("admin_password_hash", "")
    if username != stored_user:
        return False
    return verify_password(password, stored_hash)
