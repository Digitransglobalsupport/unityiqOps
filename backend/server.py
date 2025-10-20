from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime, timedelta, timezone
import uuid
import os
import logging
import hashlib
import hmac
import jwt
from passlib.context import CryptContext

# --- Env & App Bootstrap ---
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ.get("MONGO_URL")
DB_NAME = os.environ.get("DB_NAME", "test_database")
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")

JWT_SECRET = os.environ.get("JWT_SECRET", None)
if not JWT_SECRET:
    # Ephemeral secret for dev if not provided; tokens will invalidate on restart
    JWT_SECRET = hashlib.sha256((os.environ.get("MONGO_URL", "") + "-dev-secret").encode()).hexdigest()

JWT_ALG = "HS256"
ACCESS_TTL_MIN = int(os.environ.get("JWT_ACCESS_TTL_MIN", "45"))
REFRESH_TTL_DAYS = int(os.environ.get("JWT_REFRESH_TTL_DAYS", "14"))

EMAIL_DELIVERY_MODE = os.environ.get("EMAIL_DELIVERY", "DEV").upper()
DEV_EMAIL_STORE_TTL_HOURS = int(os.environ.get("DEV_EMAIL_STORE_TTL_HOURS", "24"))

PASSWORD_HASHER = os.environ.get("PASSWORD_HASHER", "bcrypt").lower()  # bcrypt supported

# MongoDB connection

@app.get("/api/health")
def health():
    return {"ok": True}

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# Create indexes (async tasks executed lazily on first request)
async def ensure_indexes():
    await db.users.create_index("email", unique=True)
    await db.memberships.create_index([("org_id", 1), ("user_id", 1)], unique=True, sparse=True)
    await db.sessions.create_index("user_id")
    await db.sessions.create_index("expires_at", expireAfterSeconds=0)
    # Dev email TTL
    await db.dev_emails.create_index("created_at", expireAfterSeconds=DEV_EMAIL_STORE_TTL_HOURS * 3600)
    await db.audit_logs.create_index([("org_id", 1), ("ts", -1)])

# Security: password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Role hierarchy
ROLE_ORDER = {"VIEWER": 1, "ANALYST": 2, "ADMIN": 3, "OWNER": 4}

# --- Pydantic Models ---
class UserPublic(BaseModel):
    user_id: str
    email: EmailStr
    email_verified: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

class SignupRequest(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshRequest(BaseModel):
    refresh_token: str

class VerifyEmailRequest(BaseModel):
    token: str

class RequestResetRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class OrgCreateRequest(BaseModel):
    name: str

class InviteRequest(BaseModel):
    email: EmailStr
    role: str = Field(default="VIEWER", pattern="^(VIEWER|ANALYST|ADMIN)$")

class MemberRolePatch(BaseModel):
    role: str = Field(pattern="^(VIEWER|ANALYST|ADMIN|OWNER)$")

class AuditLog(BaseModel):
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: Optional[str] = None
    user_id: Optional[str] = None
    action: str
    resource: str
    meta: Dict[str, Any] = {}
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# --- Utils ---
async def audit_log_entry(org_id: Optional[str], user_id: Optional[str], action: str, resource: str, meta: Dict[str, Any]):
    try:
        entry = AuditLog(org_id=org_id, user_id=user_id, action=action, resource=resource, meta=meta)
        doc = entry.model_dump()
        await db.audit_logs.insert_one(doc)
    except Exception as e:
        logging.getLogger(__name__).warning(f"Audit log insert failed: {e}")

def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(p: str, hashed: str) -> bool:
    return pwd_context.verify(p, hashed)

def sign_jwt(payload: dict, ttl_seconds: int) -> str:
    exp = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    to_sign = {**payload, "exp": exp}
    return jwt.encode(to_sign, JWT_SECRET, algorithm=JWT_ALG)

def decode_jwt(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])

async def send_dev_email(to: str, subject: str, body: str, action: str, token: Optional[str] = None, url_path: Optional[str] = None):
    email_doc = {
        "email_id": str(uuid.uuid4()),
        "to": to,
        "subject": subject,
        "body": body,
        "action": action,
        "token": token,
        "url_path": url_path,
        "created_at": datetime.now(timezone.utc),
    }
    await db.dev_emails.insert_one(email_doc)

# --- Encryption Utilities (Per-org derived key from APP_ENCRYPTION_KEY) ---
import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_KEY_B64 = os.environ.get("APP_ENCRYPTION_KEY")
try:
    MASTER_KEY = base64.b64decode(MASTER_KEY_B64) if MASTER_KEY_B64 else None
except Exception:
    MASTER_KEY = None

if MASTER_KEY is None:
    # Dev fallback ephemeral
    MASTER_KEY = hashlib.sha256((os.environ.get("MONGO_URL", "") + "-enc-key").encode()).digest()

def derive_org_key(org_id: str) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=org_id.encode(), info=b"unityops-org-key")
    return hkdf.derive(MASTER_KEY)

def aesgcm_encrypt_for_org(org_id: str, plaintext: str) -> Dict[str, str]:
    key = derive_org_key(org_id)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode(), None)
    return {"alg": "AESGCM", "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ct).decode()}

def aesgcm_decrypt_for_org(org_id: str, enc: Dict[str, str]) -> str:
    key = derive_org_key(org_id)
    aes = AESGCM(key)
    nonce = base64.b64decode(enc["nonce"])  # type: ignore
    ct = base64.b64decode(enc["ciphertext"])  # type: ignore
    pt = aes.decrypt(nonce, ct, None)
    return pt.decode()

# --- Auth & Context Dependencies ---
class RequestContext(BaseModel):
    user_id: str
    org_id: Optional[str]
    role: Optional[str]

async def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = auth.split(" ", 1)[1]
    try:
        data = decode_jwt(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user_id = data.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    user = await db.users.find_one({"user_id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.get("email_verified"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")
    return user

# --- Plan limits helpers ---
async def get_plan_limits(org_id: str) -> Dict[str, Any]:
    plan = await db.plans.find_one({"org_id": org_id}) or {"tier": "FREE", "limits": {"companies": 1, "connectors": 0, "exports": False}}
    tier = plan.get("tier", "FREE")
    limits = plan.get("limits") or {}
    if tier == "FREE":
        return {"tier": tier, "companies": 1, "connectors": 0, "exports": False, "alerts": False}
    if tier == "LITE":
        return {"tier": tier, "companies": 3, "connectors": 1, "exports": True, "alerts": True}
    if tier == "PRO":
        return {"tier": tier, "companies": 10, "connectors": 3, "exports": True, "alerts": True}
    # default
    return {"tier": tier, "companies": limits.get("companies", 1), "connectors": limits.get("connectors", 0), "exports": bool(limits.get("exports", False)), "alerts": bool(limits.get("alerts", False))}


async def get_org_context(user: dict, request: Request) -> RequestContext:
    """Resolve org context from X-Org-Id header or default to first membership."""
    header_org_id = request.headers.get("X-Org-Id")
    membership = None
    if header_org_id:
        membership = await db.memberships.find_one({"user_id": user["user_id"], "org_id": header_org_id}, {"_id": 0})
        if not membership:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No membership in org")
    else:
        membership = await db.memberships.find_one({"user_id": user["user_id"], "status": {"$in": ["ACTIVE", "OWNER"]}}, {"_id": 0})
        if not membership:
            return RequestContext(user_id=user["user_id"], org_id=None, role=None)
    role = membership.get("role")
    return RequestContext(user_id=user["user_id"], org_id=membership["org_id"], role=role)

def require_role(required: str):
    # Returns a dependency that enforces the required role within current org context
    async def dependency(user: dict = Depends(get_current_user), request: Request = None):
        ctx = await get_org_context(user, request)
        if ctx.org_id is None:
            raise HTTPException(status_code=400, detail="No org selected")
        user_rank = ROLE_ORDER.get(ctx.role or "", 0)
        need_rank = ROLE_ORDER.get(required, 0)
        if user_rank < need_rank:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return ctx
    return dependency

async def authed_ctx(user: dict = Depends(get_current_user), request: Request = None) -> RequestContext:
    return await get_org_context(user, request)

# --- Rate Limit (basic in-memory) ---
_rate_state: Dict[str, Tuple[int, float]] = {}

def rate_limit(key: str, limit: int, window_seconds: int) -> None:
    now = datetime.now().timestamp()
    count, reset = _rate_state.get(key, (0, now + window_seconds))
    if now > reset:
        count, reset = 0, now + window_seconds
    count += 1
    _rate_state[key] = (count, reset)
    if count > limit:
        raise HTTPException(status_code=429, detail="Too many requests")

# --- FastAPI App & Router ---
app = FastAPI()

# Rate limit snapshot generation: 2/min per org
SNAPSHOT_RATE_LIMIT = int(os.environ.get("SNAPSHOT_RATE_LIMIT", "2"))
api = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# --- Health/Hello routes kept ---
class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

@api.get("/")
async def root():
    return {"message": "Hello World"}

@api.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_obj = StatusCheck(**input.model_dump())
    doc = status_obj.model_dump()
    doc["timestamp"] = doc["timestamp"].isoformat()
    await db.status_checks.insert_one(doc)
    return status_obj

@api.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    items = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    for it in items:
        if isinstance(it.get("timestamp"), str):
            it["timestamp"] = datetime.fromisoformat(it["timestamp"])  
    return items

@api.post("/auth/request-verify")
async def request_verify(user: dict = Depends(get_current_user)):
    # send a new email verification token to the authenticated user
    verify_token = sign_jwt({"sub": user["user_id"], "typ": "email_verify"}, ttl_seconds=24*3600)
    await send_dev_email(
        to=user["email"],
        subject="Verify your email",
        body=f"Click to verify: /api/auth/verify-email?token={verify_token}",
        action="verify_email",
        token=verify_token,
        url_path=f"/api/auth/verify-email?token={verify_token}",
    )
    await audit_log_entry(None, user["user_id"], "request_verify", "user", {})
    return {"sent": True}


# --- Auth Routes ---
@api.post("/auth/signup")
async def signup(payload: SignupRequest, request: Request):
    rate_limit(f"signup:{request.client.host}", 10, 60)
    user = {
        "user_id": str(uuid.uuid4()),
        "email": payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "email_verified": False,
        "created_at": datetime.now(timezone.utc),
        "last_login_at": None,
    }
    try:
        await db.users.insert_one(user)
    except Exception:
        # duplicate email
        raise HTTPException(status_code=400, detail="Email already registered")

    # send verification email via DEV store
    verify_token = sign_jwt({"sub": user["user_id"], "typ": "email_verify"}, ttl_seconds=24*3600)
    await send_dev_email(
        to=user["email"],
        subject="Verify your email",
        body=f"Click to verify: /api/auth/verify-email?token={verify_token}",
        action="verify_email",
        token=verify_token,
        url_path=f"/api/auth/verify-email?token={verify_token}",
    )
    await audit_log_entry(None, user["user_id"], "signup", "user", {"email": user["email"]})
    return {"message": "Signup successful. Check dev emails to verify."}

@api.post("/auth/verify-email")
async def verify_email(payload: VerifyEmailRequest):
    try:
        data = decode_jwt(payload.token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")
    if data.get("typ") != "email_verify":
        raise HTTPException(status_code=400, detail="Invalid token type")
    user_id = data.get("sub")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token payload")
    res = await db.users.update_one({"user_id": user_id}, {"$set": {"email_verified": True}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await audit_log_entry(None, user_id, "verify_email", "user", {})
    return {"message": "Email verified"}

@api.post("/auth/login", response_model=TokenResponse)
async def login(payload: LoginRequest, request: Request):
    rate_limit(f"login:{request.client.host}", 30, 60)
    user = await db.users.find_one({"email": payload.email.lower()}, {"_id": 0})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("email_verified"):
        raise HTTPException(status_code=403, detail="Email not verified")

    user_id = user["user_id"]
    access = sign_jwt({"sub": user_id, "typ": "access"}, ACCESS_TTL_MIN * 60)
    refresh_plain = str(uuid.uuid4())
    refresh_hash = hashlib.sha256(refresh_plain.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TTL_DAYS)
    await db.sessions.insert_one({
        "session_id": str(uuid.uuid4()),
        "user_id": user_id,
        "refresh_token_hash": refresh_hash,
        "expires_at": expires_at,
    })
    await db.users.update_one({"user_id": user_id}, {"$set": {"last_login_at": datetime.now(timezone.utc)}})
    await audit_log_entry(None, user_id, "login", "user", {})
    return TokenResponse(access_token=access, refresh_token=refresh_plain, expires_in=ACCESS_TTL_MIN*60)

# Convenience GET endpoint for verification via link
@api.get("/auth/verify-email")
async def verify_email_get(token: str):
    from fastapi.responses import RedirectResponse
    try:
        data = decode_jwt(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")
    if data.get("typ") != "email_verify":
        raise HTTPException(status_code=400, detail="Invalid token type")
    user_id = data.get("sub")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token payload")
    res = await db.users.update_one({"user_id": user_id}, {"$set": {"email_verified": True}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await audit_log_entry(None, user_id, "verify_email", "user", {})
    return RedirectResponse(url="/login?verified=1", status_code=302)

@api.post("/auth/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest):
    rhash = hashlib.sha256(payload.refresh_token.encode()).hexdigest()
    sess = await db.sessions.find_one({"refresh_token_hash": rhash}, {"_id": 0})
    if not sess:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if sess.get("expires_at") and sess["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")
    user_id = sess["user_id"]
    access = sign_jwt({"sub": user_id, "typ": "access"}, ACCESS_TTL_MIN * 60)
    # Rotate refresh
    new_plain = str(uuid.uuid4())
    new_hash = hashlib.sha256(new_plain.encode()).hexdigest()
    await db.sessions.update_one({"session_id": sess["session_id"]}, {"$set": {"refresh_token_hash": new_hash, "expires_at": datetime.now(timezone.utc) + timedelta(days=REFRESH_TTL_DAYS)}})
    await audit_log_entry(None, user_id, "refresh", "session", {})
    return TokenResponse(access_token=access, refresh_token=new_plain, expires_in=ACCESS_TTL_MIN*60)

@api.post("/auth/request-reset")
async def request_reset(payload: RequestResetRequest, request: Request):
    rate_limit(f"reset:{request.client.host}", 10, 60)
    user = await db.users.find_one({"email": payload.email.lower()}, {"_id": 0})
    if user:
        token = sign_jwt({"sub": user["user_id"], "typ": "password_reset"}, 3600)
        await send_dev_email(
            to=user["email"],
            subject="Reset your password",
            body=f"Click to reset: /api/auth/reset?token={token}",
            action="password_reset",
            token=token,
            url_path=f"/api/auth/reset?token={token}",
        )
        await audit_log_entry(None, user["user_id"], "request_reset", "user", {})
    # Always return success to avoid user enum
    return {"message": "If the email exists, a reset link has been sent"}

@api.post("/auth/reset")
async def reset_password(payload: ResetPasswordRequest):
    try:
        data = decode_jwt(payload.token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")
    if data.get("typ") != "password_reset":
        raise HTTPException(status_code=400, detail="Invalid token type")
    user_id = data.get("sub")
    res = await db.users.update_one({"user_id": user_id}, {"$set": {"password_hash": hash_password(payload.new_password)}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    # Invalidate all sessions
    await db.sessions.delete_many({"user_id": user_id})
    await audit_log_entry(None, user_id, "reset_password", "user", {})
    return {"message": "Password reset successful"}

# --- Me/Orgs/Memberships ---
@api.get("/me")
async def me(user: dict = Depends(get_current_user)):
    memberships = await db.memberships.find({"user_id": user["user_id"]}, {"_id": 0}).to_list(100)
    return {"user": {k: user[k] for k in ["user_id", "email", "email_verified", "created_at", "last_login_at"]}, "memberships": memberships}

@api.get("/orgs")
async def list_orgs(user: dict = Depends(get_current_user)):
    ms = await db.memberships.find({"user_id": user["user_id"], "status": {"$in": ["ACTIVE", "OWNER"]}}, {"_id": 0}).to_list(100)
    org_ids = [m["org_id"] for m in ms]
    orgs = await db.orgs.find({"org_id": {"$in": org_ids}}, {"_id": 0}).to_list(100)
    return orgs

@api.post("/orgs")
async def create_org(payload: OrgCreateRequest, user: dict = Depends(get_current_user)):
    org_id = str(uuid.uuid4())
    org = {
        "org_id": org_id,
        "name": payload.name,
        "stripe_customer_id": None,
        "created_by": user["user_id"],
        "created_at": datetime.now(timezone.utc),
    }
    await db.orgs.insert_one(org)
    await db.memberships.insert_one({
        "membership_id": str(uuid.uuid4()),
        "user_id": user["user_id"],
        "org_id": org_id,
        "role": "OWNER",
        "invited_by": user["user_id"],
        "status": "OWNER",
    })
    await audit_log_entry(org_id, user["user_id"], "create", "org", {"name": payload.name})
    return {"org_id": org_id, "name": payload.name}

@api.post("/orgs/{org_id}/invite")
async def invite_member(org_id: str, payload: InviteRequest, ctx: RequestContext = Depends(require_role("ADMIN"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    
    email = payload.email.lower()
    role = payload.role
    invited_user = await db.users.find_one({"email": email}, {"_id": 0})
    if invited_user:
        # create active membership if not exists
        existing = await db.memberships.find_one({"org_id": org_id, "user_id": invited_user["user_id"]})
        if existing:
            raise HTTPException(status_code=400, detail="User already a member or invited")
        await db.memberships.insert_one({
            "membership_id": str(uuid.uuid4()),
            "user_id": invited_user["user_id"],
            "org_id": org_id,
            "role": role,
            "invited_by": ctx.user_id,
            "status": "ACTIVE",
        })
    else:
        # pending invite (no user yet)
        await db.memberships.insert_one({
            "membership_id": str(uuid.uuid4()),
            "user_id": None,
            "invited_email": email,
            "org_id": org_id,
            "role": role,
            "invited_by": ctx.user_id,
            "status": "INVITED",
        })
    # Send invite email via DEV store
    invite_token = sign_jwt({"org_id": org_id, "email": email, "typ": "invite"}, 7*24*3600)
    # Fetch org for clarity fields
    org = await db.orgs.find_one({"org_id": org_id}, {"_id": 0, "name": 1})
    await send_dev_email(
        to=email,
        subject=f"You're invited to join {org.get('name') if org else 'an organization'}",
        body=f"Join org: /api/invites/accept?token={invite_token}",
        action="invite",
        token=invite_token,
        url_path=f"/api/invites/accept?token={invite_token}",
    )
    # Also store extra clarity fields
    await db.dev_emails.update_one({"token": invite_token}, {"$set": {"org_name": (org or {}).get("name"), "role": role}}, upsert=False)
    await audit_log_entry(org_id, ctx.user_id, "invite", "membership", {"email": email, "role": role})
    return {"message": "Invitation sent"}

# --- Mock Xero OAuth + CSV ingest scaffolding (Day 1 prep) ---
@api.post("/connections/xero/oauth/start")
async def xero_oauth_start(body: Dict[str, Any], ctx: RequestContext = Depends(require_role("ADMIN"))):
    # Return real Xero consent URL when XERO_MODE=live, else mock page
    org_id = body.get("org_id")
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    # enforce connector limit
    limits = await get_plan_limits(org_id)
    connected = await db.connections.count_documents({"org_id": org_id})
    if connected >= limits["connectors"]:
        raise HTTPException(status_code=403, detail={"code":"LIMIT_EXCEEDED", "limit":"connectors", "allowed": limits["connectors"], "current": connected})
    state = str(uuid.uuid4())
    await db.oauth_states.update_one({"state": state}, {"$set": {"state": state, "org_id": org_id, "created_at": datetime.now(timezone.utc)}}, upsert=True)
    XERO_MODE = os.environ.get("XERO_MODE", "mock").lower()
    if XERO_MODE == "live":
        client_id = os.environ.get("XERO_CLIENT_ID")
        redirect_uri = f"{APP_URL}/api/connections/xero/oauth/callback"
        scopes = "accounting.transactions.read accounting.contacts.read accounting.settings.read offline_access openid profile email"
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scopes,
            "state": state,
        }
        # Build URL
        base = "https://login.xero.com/identity/connect/authorize"
        from urllib.parse import urlencode
        auth_url = f"{base}?{urlencode(params)}"
        return {"auth_url": auth_url}
    # mock
    return {"auth_url": f"/api/mock/xero/consent?state={state}"}

@api.get("/mock/xero/consent")
async def mock_xero_consent(state: str, ctx: RequestContext = Depends(require_role("ADMIN"))):
    from fastapi.responses import HTMLResponse
    st = await db.oauth_states.find_one({"state": state})
    if not st:
        return HTMLResponse("Invalid or expired state", status_code=400)
    html = f"""
    <html><body style='font-family: sans-serif;'>
    <h3>Mock Xero Consent</h3>
    <p>State: {state}</p>
    <form method='post' action='/api/connections/xero/oauth/callback' style='margin-top:16px;'>
      <input type='hidden' name='code' value='MOCK_CODE'/>
      <input type='hidden' name='state' value='{state}'/>
      <input type='hidden' name='org_id' value='{st.get('org_id')}'/>
      <button type='submit'>Approve</button>
    </form>
    </body></html>
    """
    return HTMLResponse(content=html)


@api.get("/connections/xero/oauth/callback")
async def xero_callback_get(code: str | None = None, state: str | None = None):
    # Live callback (Xero redirects with code+state)
    XERO_MODE = os.environ.get("XERO_MODE", "mock").lower()
    if XERO_MODE != "live":
        # allow mock post handler to operate
        return RedirectResponse(url=f"/onboarding?connected=1")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code/state")
    st = await db.oauth_states.find_one({"state": state})
    if not st:
        raise HTTPException(status_code=400, detail="Invalid state")
    org_id = st.get("org_id")
    token_url = "https://identity.xero.com/connect/token"
    client_id = os.environ.get("XERO_CLIENT_ID"); client_secret = os.environ.get("XERO_CLIENT_SECRET")
    redirect_uri = f"{APP_URL}/api/connections/xero/oauth/callback"
    import httpx
    try:
        async with httpx.AsyncClient(timeout=float(os.environ.get("XERO_FETCH_TIMEOUT_SEC", "25"))) as client:
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            }
            tok = await client.post(token_url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
            tok.raise_for_status()
            td = tok.json()
            access_token = td.get("access_token"); refresh_token = td.get("refresh_token"); expires_in = int(td.get("expires_in", 1800))
            # fetch tenants
            conns = await client.get("https://api.xero.com/connections", headers={"Authorization": f"Bearer {access_token}"})
            conns.raise_for_status()
            tenants = conns.json()
            enc_access = aesgcm_encrypt_for_org(org_id, access_token)
            enc_refresh = aesgcm_encrypt_for_org(org_id, refresh_token)
            await db.connections.update_one(
                {"org_id": org_id, "vendor": "xero"},
                {"$set": {
                    "org_id": org_id,
                    "vendor": "xero",
                    "tokens": {"access": enc_access, "refresh": enc_refresh},
                    "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
                    "tenants": tenants,
                    "updated_at": datetime.now(timezone.utc)
                }},
                upsert=True
            )
            await audit_log_entry(org_id, None, "connect", "xero", {"tenants": [t.get("tenantId") for t in tenants]})
    except httpx.HTTPError as e:
        await db.connection_errors.update_one({"org_id": org_id, "vendor": "xero"}, {"$set": {"org_id": org_id, "vendor": "xero", "code": "oauth_exchange_failed", "message": str(e), "ts": datetime.now(timezone.utc)}}, upsert=True)
        raise HTTPException(status_code=400, detail="OAuth exchange failed")
    return RedirectResponse(url="/connections?connected=1", status_code=302)

@api.post("/connections/xero/tenant")
async def xero_select_tenant(payload: Dict[str, Any], ctx: RequestContext = Depends(require_role("ADMIN"))):
    org_id = payload.get("org_id"); tenant_id = payload.get("tenant_id")
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    await db.connections.update_one({"org_id": org_id, "vendor": "xero"}, {"$set": {"default_tenant_id": tenant_id, "updated_at": datetime.now(timezone.utc)}})
    return {"ok": True}

@api.post("/connections/xero/oauth/callback")
async def xero_callback(body: Dict[str, Any]):
    # Store mock tokens encrypted under org_id resolved via state
    state = body.get("state")
    st = await db.oauth_states.find_one({"state": state})
    org_id = (st or {}).get("org_id") or body.get("org_id")
    code = body.get("code") or "MOCK_CODE"
    tenant_id = "MOCK_TENANT_1"
    if not org_id:
        raise HTTPException(status_code=400, detail="org_id required")
    enc_access = aesgcm_encrypt_for_org(org_id, f"access::{code}")
    enc_refresh = aesgcm_encrypt_for_org(org_id, f"refresh::{code}")
    await db.connections.update_one(
        {"org_id": org_id, "vendor": "xero"},
        {"$set": {
            "org_id": org_id,
            "vendor": "xero",
            "tenant_id": tenant_id,
            "access_token_enc": enc_access,
            "refresh_token_enc": enc_refresh,
async def month_key(dt_str: str) -> str:
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return f"{dt.year}-{dt.month:02d}"
    except Exception:
        return None

async def compute_trends_from_lines(org_id: str, periods: int = 6):
    # Build last N month keys
    now = datetime.now(timezone.utc)
    months = []
    y, m = now.year, now.month
    for i in range(periods, 0, -1):
        mm = m - (periods - i)
        yy = y
        while mm <= 0:
            mm += 12
            yy -= 1
        months.append(f"{yy}-{mm:02d}")
    idx = {k: i for i, k in enumerate(months)}
    revenue = [0.0] * periods
    dso_list = []
    # Pull AR invoices last N months
    since = months[0] + "-01"
    cur = db.finance_lines.find({"org_id": org_id, "type": "AR", "date": {"$gte": since}})
    async for inv in cur:
        mk = await month_key(inv.get("date") or "")
        if mk in idx:
            revenue[idx[mk]] += float(inv.get("amount") or 0.0)
        # Approx DSO as (due_date - date) days if both present
        d = inv.get("date"); due = inv.get("due_date")
        try:
            if d and due:
                d0 = datetime.fromisoformat(d.replace("Z", "+00:00"))
                d1 = datetime.fromisoformat(due.replace("Z", "+00:00"))
                delta = (d1 - d0).days
                if 0 < delta < 365:
                    dso_list.append(delta)
        except Exception:
            pass
    series = [
        {"kpi": "revenue", "points": [[months[i], round(revenue[i], 2)] for i in range(periods)]},
    ]
    # If we want, we could add others as placeholders
    # Compute simple DSO as average
    dso_days = round(sum(dso_list) / len(dso_list), 1) if dso_list else None
    return {"months": months, "series": series, "dso_days": dso_days}

            "scopes": ["accounting.reports.read","accounting.transactions.read","accounting.settings.read","offline_access","openid","profile","email"],
            "updated_at": datetime.now(timezone.utc)
        }},
        upsert=True
    )
    await audit_log_entry(org_id, None, "connect", "xero", {"tenant_id": tenant_id})
    return {"connected": True, "tenant_id": tenant_id}

@api.get("/companies/discover")
async def companies_discover(org_id: str, ctx: RequestContext = Depends(require_role("ADMIN"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    # Return mock companies for now
    return [
        {"org_id": org_id, "company_id": "CO1", "name": "Acme UK", "xero_tenant_id": "MOCK_TENANT_1", "currency": "GBP"},
        {"org_id": org_id, "company_id": "CO2", "name": "Acme US", "xero_tenant_id": "MOCK_TENANT_2", "currency": "USD"},
    ]

class CompaniesSelectBody(BaseModel):
    org_id: str
    companies: List[Dict[str, Any]]
    base_currency: str = "GBP"
    fx_source: str = "ECB"

@api.post("/companies/select")
async def companies_select(body: CompaniesSelectBody, ctx: RequestContext = Depends(require_role("ADMIN"))):
    if ctx.org_id != body.org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    limits = await get_plan_limits(body.org_id)
    # enforce company count limit
    existing = await db.companies.count_documents({"org_id": body.org_id, "is_active": True})
    requested = len(body.companies)
    if existing + requested > limits["companies"]:
        raise HTTPException(status_code=403, detail={"code":"LIMIT_EXCEEDED", "limit":"companies", "allowed": limits["companies"], "current": existing + requested})
    for c in body.companies:
        await db.companies.update_one(
            {"org_id": body.org_id, "company_id": c["company_id"]},
            {"$set": {**c, "org_id": body.org_id, "is_active": True}},
            upsert=True
        )
    await audit_log_entry(body.org_id, ctx.user_id, "companies_select", "company", {"count": len(body.companies), "base": body.base_currency})
    return {"ok": True}

class FinanceRefreshBody(BaseModel):
    org_id: str
    _from: str | None = None
    to: str | None = None
    sources: List[str] | None = None

async def run_xero_backfill(org_id: str, tenant_id: str, date_from: str, date_to: str, job_id: str):
    # Update job running
    await db.sync_jobs.update_one({"org_id": org_id, "job_id": job_id}, {"$set": {"status": "running", "phase": "start", "started_at": datetime.now(timezone.utc)}}, upsert=True)
    counts = {"ar": 0, "ap": 0, "contacts": 0}
    try:
        # AR (ACCREC)
        await db.sync_jobs.update_one({"org_id": org_id, "job_id": job_id}, {"$set": {"phase": "fetch_ar"}})
        where = f"Type==\"ACCREC\" && Date>=Date(\"{date_from}\") && Date<=Date(\"{date_to}\")"
        page = 1
        while page <= 2:  # guard pages for preview
            data = await xero_request(org_id, tenant_id, "/api.xro/2.0/Invoices", params={"where": where, "page": page})
            invs = data.get("Invoices", [])
            if not invs:
                break
            docs = []
            for inv in invs:
                docs.append({
                    "org_id": org_id,
                    "vendor": "xero",
                    "type": "AR",
                    "invoice_id": inv.get("InvoiceID"),
                    "date": inv.get("DateString") or inv.get("Date"),
                    "due_date": inv.get("DueDateString") or inv.get("DueDate"),
                    "amount": inv.get("Total"),
                    "status": inv.get("Status"),
                    "contact": (inv.get("Contact") or {}).get("Name"),
                })
            if docs:
                await db.finance_lines.insert_many(docs)
                counts["ar"] += len(docs)
            page += 1
        # AP (ACCPAY)
        await db.sync_jobs.update_one({"org_id": org_id, "job_id": job_id}, {"$set": {"phase": "fetch_ap"}})
        where_ap = f"Type==\"ACCPAY\" && Date>=Date(\"{date_from}\") && Date<=Date(\"{date_to}\")"
        page = 1
        while page <= 2:
            data = await xero_request(org_id, tenant_id, "/api.xro/2.0/Invoices", params={"where": where_ap, "page": page})
            invs = data.get("Invoices", [])
            if not invs:
                break
            docs = []
            for inv in invs:
                docs.append({
                    "org_id": org_id,
                    "vendor": "xero",
                    "type": "AP",
                    "invoice_id": inv.get("InvoiceID"),
                    "date": inv.get("DateString") or inv.get("Date"),
                    "due_date": inv.get("DueDateString") or inv.get("DueDate"),
                    "amount": inv.get("Total"),
                    "status": inv.get("Status"),
                    "contact": (inv.get("Contact") or {}).get("Name"),
                })
            if docs:
                await db.finance_lines.insert_many(docs)
                counts["ap"] += len(docs)
            page += 1
        # Contacts
        await db.sync_jobs.update_one({"org_id": org_id, "job_id": job_id}, {"$set": {"phase": "fetch_contacts"}})
        page = 1
        while page <= 2:
            data = await xero_request(org_id, tenant_id, "/api.xro/2.0/Contacts", params={"page": page})
            contacts = data.get("Contacts", [])
            if not contacts:
                break
            docs = []
            for c in contacts:
                docs.append({
                    "org_id": org_id,
                    "vendor": "xero",
                    "contact_id": c.get("ContactID"),
                    "name": c.get("Name"),
                    "is_customer": c.get("IsCustomer"),
                    "is_supplier": c.get("IsSupplier"),
                    "email": c.get("EmailAddress"),
                })
            if docs:
                await db.finance_contacts.insert_many(docs)
                counts["contacts"] += len(docs)
            page += 1
        # finish
        await db.connections.update_one({"org_id": org_id, "vendor": "xero"}, {"$set": {"last_sync_at": datetime.now(timezone.utc).isoformat(), "updated_at": datetime.now(timezone.utc)}})
        await db.sync_jobs.update_one({"org_id": org_id, "job_id": job_id}, {"$set": {"status": "done", "counts": counts, "finished_at": datetime.now(timezone.utc)}})
    except HTTPException as e:
        await db.sync_jobs.update_one({"org_id": org_id, "job_id": job_id}, {"$set": {"status": "error", "error": e.detail, "finished_at": datetime.now(timezone.utc)}})
        return
    except Exception as e:
        await db.sync_jobs.update_one({"org_id": org_id, "job_id": job_id}, {"$set": {"status": "error", "error": str(e), "finished_at": datetime.now(timezone.utc)}})
        return

@api.post("/ingest/finance/refresh")
async def finance_refresh(body: FinanceRefreshBody, ctx: RequestContext = Depends(require_role("ANALYST"))):
    org_id = body.org_id
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    sources = body.sources or ["csv"]
    # If Xero selected and live connected, enqueue job and run async backfill for 3 months
    if "xero" in sources:
        conn = await db.connections.find_one({"org_id": org_id, "vendor": "xero"})
        if not conn:
            raise HTTPException(status_code=400, detail={"code":"not_connected"})
        tenant_id = conn.get("default_tenant_id") or ((conn.get("tenants") or [{}])[0].get("tenantId"))
        if not tenant_id:
            raise HTTPException(status_code=400, detail={"code":"tenant_not_found"})
        # compute last 3 full months
        today = datetime.now(timezone.utc)
        last = datetime(today.year, today.month, 1, tzinfo=timezone.utc) - timedelta(days=1)
        first = datetime(last.year, last.month, 1, tzinfo=timezone.utc) - timedelta(days=60)
        date_from = (body._from or first.date().isoformat())
        date_to = (body.to or last.date().isoformat())
        job_id = str(uuid.uuid4())
        await db.sync_jobs.update_one({"org_id": org_id, "job_id": job_id}, {"$set": {"org_id": org_id, "job_id": job_id, "type": "finance", "status": "queued", "phase": "queued", "created_at": datetime.now(timezone.utc)}}, upsert=True)
        import asyncio
        asyncio.create_task(run_xero_backfill(org_id, tenant_id, date_from, date_to, job_id))
        await audit_log_entry(org_id, ctx.user_id, "finance_refresh", "ingest", {"job_id": job_id, "source": "xero"})
        return {"job_id": job_id, "status": "queued"}
    # CSV fallback (existing)
    job_id = str(uuid.uuid4())
    await db.sync_jobs.insert_one({"org_id": org_id, "job_id": job_id, "type": "finance", "status": "ok", "started_at": datetime.now(timezone.utc), "finished_at": datetime.now(timezone.utc), "meta": body.model_dump()})
    await audit_log_entry(org_id, ctx.user_id, "finance_refresh", "ingest", {"job_id": job_id, "source": "csv"})
    return {"job_id": job_id, "status": "ok"}

@api.get("/sync-jobs/{job_id}")
async def get_sync_job(job_id: str, ctx: RequestContext = Depends(require_role("ANALYST"))):
    job = await db.sync_jobs.find_one({"org_id": ctx.org_id, "job_id": job_id}, {"_id": 0})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@api.get("/dashboard/finance/trends")
async def finance_trends(org_id: str, periods: int = 6, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    # Generate mock monthly series for last N periods
    now = datetime.now(timezone.utc)
    months = []
    y, m = now.year, now.month
    for i in range(periods, 0, -1):
        mm = m - (periods - i)
        yy = y
        while mm <= 0:
            mm += 12
            yy -= 1
        months.append(f"{yy}-{mm:02d}")
    def mk(points):
        return [[months[i], v] for i, v in enumerate(points)]
    series = [
        {"kpi": "revenue", "points": mk([410000,420000,390000,410000,420000,420000][:periods])},
        {"kpi": "gm_pct", "points": mk([39.1,40.2,38.8,41.0,41.5,41.2][:periods])},
        {"kpi": "opex", "points": mk([210000,215000,205000,208000,210000,212000][:periods])},
        {"kpi": "dso_days", "points": mk([56,54,59,51,48,47][:periods])},
    ]
    return {"org_id": org_id, "series": series}

    # Mock job and KPIs
    job_id = str(uuid.uuid4())
    await db.sync_jobs.insert_one({
        "org_id": org_id, "job_id": job_id, "type": "finance", "status": "ok",
        "started_at": datetime.now(timezone.utc), "finished_at": datetime.now(timezone.utc), "meta": body
    })
    # Write simple KPIs/synergy
    await db.synergy_scores.update_one(
        {"org_id": org_id, "period": "mock"},
        {"$set": {"org_id": org_id, "company_id": None, "period": "mock", "s_fin": 72}},
        upsert=True
    )
    await audit_log_entry(org_id, ctx.user_id, "finance_refresh", "ingest", {"job_id": job_id})
    return {"job_id": job_id, "status": "ok"}

@api.get("/dashboard/finance")
async def dashboard_finance(org_id: str, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    score = await db.synergy_scores.find_one({"org_id": org_id}, {"_id": 0})
    companies = await db.companies.find({"org_id": org_id, "is_active": True}, {"_id": 0}).to_list(50)
    # Compute trends/DSO from ingested AR/AP where available
    trends_calc = await compute_trends_from_lines(org_id, periods=6)
    # Pull data health and connection state
    health = await db.data_health.find_one({"org_id": org_id}, {"_id": 0}) or {}
    conn = await db.connections.find_one({"org_id": org_id, "vendor": "xero"}, {"_id": 0}) or {}
    conn_err = await db.connection_errors.find_one({"org_id": org_id, "vendor": "xero"}, {"_id": 0}) or {}
    conn_pill = None
    if conn:
        last = conn.get("last_sync_at") or conn.get("updated_at")
        conn_pill = {"provider": "xero", "connected": True, "last_sync_at": last}
    if conn_err:
        conn_pill = {"provider": "xero", "connected": bool(conn), "error": {"code": conn_err.get("code"), "message": conn_err.get("message")}}
    # Customer lens (if CRM data exists)
    opps_doc = await db.cross_sell_opps.find_one({"org_id": org_id}, {"_id": 0})
    masters_doc = await db.customer_master.find_one({"org_id": org_id}, {"_id": 0})
    customer_lens = None
    if opps_doc and masters_doc:
        opps = opps_doc.get("items", [])
        recent = opps[:3]
        customer_lens = {
            "shared_accounts": sum(1 for m in (masters_doc.get("items", [])) if len({c.get("company_id") for c in m.get("companies", []) if c.get("company_id")}) >= 2),
            "cross_sell_count": len(opps),
            "cross_sell_value": sum(o.get("expected_value", 0) for o in opps),
            "recent_opps": [
                {"master_id": o.get("master_id"), "name": o.get("name"), "companies": o.get("companies", []), "expected_value": o.get("expected_value"), "nba": o.get("next_best_action")}
                for o in recent
            ]
        }
    # KPIs based on trends where available
    dso_days = trends_calc.get("dso_days")
    revenue_latest = (trends_calc.get("series") or [{"points":[]}])[0]["points"][-1][1] if (trends_calc.get("series") and trends_calc["series"][0]["points"]) else None
    kpis = {"revenue": revenue_latest or 0, "gm_pct": None, "opex": None, "ebitda": None, "dso_days": dso_days or None}
    return {
        "org_id": org_id,
        "period": {"from": trends_calc.get("months", [None])[0], "to": (trends_calc.get("months") or [None])[-1]},
        "last_sync_at": (conn.get("last_sync_at") if conn else None),
        "score": {
            "s_fin": (score or {}).get("s_fin", 72),
            "weights": {"gm": 0.4, "opex": 0.4, "dso": 0.2},
            "drivers": {"gm_delta_pct": 2.7, "opex_delta_pct": -1.4, "dso_delta_days": (dso_days - 53) if dso_days else None, "notes": ["Finance updated from live data" if conn else "Mock demo data"]}
        },
        "kpis": kpis,
        "series": trends_calc.get("series", []),
        "companies": companies,
        "data_health": {"stale_days": 0, "missing_fields": [], "warnings": (health or {}).get("warnings", [])},
        "connection": conn_pill,
        "customer_lens": customer_lens
    }

@api.get("/connections/status")
async def connections_status(org_id: str, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    conn = await db.connections.find_one({"org_id": org_id, "vendor": "xero"}, {"_id": 0})
    errors = []
    err = await db.connection_errors.find_one({"org_id": org_id, "vendor": "xero"}, {"_id": 0})
    if err:
        errors.append({"code": err.get("code"), "message": err.get("message"), "ts": err.get("ts")})
    tenants = []
    if conn:
        raw = conn.get("tenants") or []
        tenants = [{"tenant_id": t.get("tenantId"), "tenant_type": t.get("tenantType"), "name": t.get("tenantName") or t.get("tenantId")} for t in raw]
    return {"xero": {"connected": bool(conn), "last_sync_at": (conn or {}).get("last_sync_at") or (conn or {}).get("updated_at"), "tenants": tenants, "default_tenant_id": (conn or {}).get("default_tenant_id"), "errors": errors}}


# --- Xero live helpers ---
async def get_xero_conn(org_id: str) -> Dict[str, Any]:
    conn = await db.connections.find_one({"org_id": org_id, "vendor": "xero"})
    if not conn:
        raise HTTPException(status_code=400, detail={"code":"not_connected"})
    return conn

async def decrypt_token(org_id: str, enc: Dict[str, Any]) -> str:
    try:
        return aesgcm_decrypt_for_org(org_id, enc)
    except Exception:
        raise HTTPException(status_code=400, detail={"code":"token_decrypt_failed"})

async def xero_refresh_tokens(org_id: str, conn: Dict[str, Any]) -> Dict[str, Any]:
    import httpx
    client_id = os.environ.get("XERO_CLIENT_ID"); client_secret = os.environ.get("XERO_CLIENT_SECRET")
    refresh_token = await decrypt_token(org_id, conn["tokens"]["refresh"])
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    async with httpx.AsyncClient(timeout=float(os.environ.get("XERO_FETCH_TIMEOUT_SEC", "25"))) as client:
        resp = await client.post("https://identity.xero.com/connect/token", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        if resp.status_code >= 400:
            await db.connection_errors.update_one({"org_id": org_id, "vendor": "xero"}, {"$set": {"org_id": org_id, "vendor": "xero", "code": "invalid_grant", "message": "Xero access expired. Click Reconnect to re-consent.", "ts": datetime.now(timezone.utc)}}, upsert=True)
            raise HTTPException(status_code=400, detail={"code":"invalid_grant"})
        td = resp.json()
        access_token = td.get("access_token"); new_refresh = td.get("refresh_token") or refresh_token; expires_in = int(td.get("expires_in", 1800))
        enc_access = aesgcm_encrypt_for_org(org_id, access_token)
        enc_refresh = aesgcm_encrypt_for_org(org_id, new_refresh)
        await db.connections.update_one({"org_id": org_id, "vendor": "xero"}, {"$set": {"tokens": {"access": enc_access, "refresh": enc_refresh}, "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(), "updated_at": datetime.now(timezone.utc)}})
        return {"access_token": access_token}

async def xero_request(org_id: str, tenant_id: str, path: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    import httpx
    conn = await get_xero_conn(org_id)
    # Refresh if expiring soon
    try:
        exp = datetime.fromisoformat(conn.get("expires_at"))
        if exp - datetime.now(timezone.utc) < timedelta(minutes=5):
            await xero_refresh_tokens(org_id, conn)
            conn = await get_xero_conn(org_id)
    except Exception:
        pass
    access_token = await decrypt_token(org_id, conn["tokens"]["access"])
    headers = {"Authorization": f"Bearer {access_token}", "xero-tenant-id": tenant_id}
    url = f"https://api.xero.com{path}"
    timeout = float(os.environ.get("XERO_FETCH_TIMEOUT_SEC", "25"))
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url, headers=headers, params=params or {})
        if r.status_code == 401:
            # try refresh once
            await xero_refresh_tokens(org_id, conn)
            conn = await get_xero_conn(org_id)
            access_token = await decrypt_token(org_id, conn["tokens"]["access"])
            headers["Authorization"] = f"Bearer {access_token}"
            r = await client.get(url, headers=headers, params=params or {})
        if r.status_code == 429:
            await db.connection_errors.update_one({"org_id": org_id, "vendor": "xero"}, {"$set": {"org_id": org_id, "vendor": "xero", "code": "rate_limit_exceeded", "message": "Xero rate limit hit. We’ll auto-retry shortly.", "ts": datetime.now(timezone.utc)}}, upsert=True)
            raise HTTPException(status_code=429, detail={"code":"rate_limit_exceeded"})
        r.raise_for_status()
        return r.json()

# CSV ingest with validation. Accepts multipart form-data files: pl, bs (optional), ar
from fastapi import UploadFile, File, Form
import csv

@api.post("/ingest/finance/csv")
async def finance_csv(org_id: str = Form(...), pl: UploadFile | None = File(None), bs: UploadFile | None = File(None), ar: UploadFile | None = File(None), ctx: RequestContext = Depends(require_role("ANALYST"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")

    warnings: List[str] = []
    ingested = {"pl": 0, "ar": 0, "bs": 0}

    def read_csv(file: UploadFile | None) -> List[Dict[str, str]]:
        if not file:
            return []
        content = file.file.read().decode("utf-8", errors="ignore")
        reader = csv.DictReader(content.splitlines())
        rows = []
        for row in reader:
            rows.append({k.strip().lower(): (v or "").strip() for k, v in row.items()})
        return rows

    def is_period(s: str) -> bool:
        try:
            if len(s) != 7 or s[4] != '-':
                return False
            y = int(s[:4]); m = int(s[5:7]); return 1 <= m <= 12 and 2000 <= y <= 2100
        except:
            return False

    pl_rows = read_csv(pl)
    bs_rows = read_csv(bs)
    ar_rows = read_csv(ar)

    # Validate and ingest PL
    for r in pl_rows:
        period = r.get('period', '')
        if not is_period(period):
            warnings.append(f"PL invalid period '{period}' - row skipped")
            continue
        try:
            revenue = float(r.get('revenue', '0') or 0)
            cogs = float(r.get('cogs', '0') or 0)
            opex = float(r.get('opex', '0') or 0)
        except:
            warnings.append("PL numeric parse failed - row skipped")
            continue
        company_id = r.get('company_id') or 'UNKNOWN'
        gm_pct = (revenue - cogs) / revenue * 100 if revenue else 0.0
        ebitda = revenue - cogs - opex
        await db.pl.update_one(
            {"org_id": org_id, "company_id": company_id, "period": period},
            {"$set": {"org_id": org_id, "company_id": company_id, "period": period, "revenue": revenue, "cogs": cogs, "opex": opex, "gm_pct": gm_pct, "ebitda": ebitda}},
            upsert=True
        )
        ingested["pl"] += 1

    # Validate and ingest BS
    receivables_map: Dict[Tuple[str, str], float] = {}
    for r in bs_rows:
        period = r.get('period', '')
        if not is_period(period):
            warnings.append(f"BS invalid period '{period}' - row skipped")
            continue
        try:
            receivables = float(r.get('receivables', '0') or 0)
        except:
            warnings.append("BS numeric parse failed - row skipped")
            continue

# --- Day 2: CRM Ingestion (Mock HubSpot + CSV fallback) ---
from rapidfuzz import fuzz

# Schemas for Day 2
# customer_master: master records from dedupe
# cross_sell_opps: opportunities inferred

@api.post("/crm/hubspot/mock/ingest")
async def hubspot_mock_ingest(body: Dict[str, Any], ctx: RequestContext = Depends(require_role("ADMIN"))):
    org_id = ctx.org_id
    # Mock arrays as if from HubSpot
    contacts = [
        {"id": "C1", "email": "alice@alphaltd.co.uk", "firstname": "Alice", "lastname": "A", "phone": "+44 20 1234 0001"},
        {"id": "C2", "email": "bob@betabv.eu", "firstname": "Bob", "lastname": "B", "phone": "+31 20 1234 0002"},
        {"id": "C3", "email": "alice@beta-bv.com", "firstname": "Alice", "lastname": "A", "phone": "+31 20 1234 0003"}
    ]
    companies = [
        {"id": "CO1", "name": "Alpha Ltd", "domain": "alphaltd.co.uk"},
        {"id": "CO2", "name": "Beta BV", "domain": "beta-bv.com"}
    ]
    deals = [
        {"id": "D1", "company_id": "CO1", "amount": 12000, "stage": "closedwon", "name": "Alpha Suite"},
        {"id": "D2", "company_id": "CO2", "amount": 0, "stage": "prospecting", "name": "Intro"}
    ]
    await db.crm_contacts.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": contacts, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await db.crm_companies.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": companies, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await db.crm_deals.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": deals, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(org_id, ctx.user_id, "crm_mock_ingest", "crm", {"counts": {"contacts": len(contacts), "companies": len(companies), "deals": len(deals)}})
    return {"ok": True, "counts": {"contacts": len(contacts), "companies": len(companies), "deals": len(deals)}}

@api.post("/crm/csv/ingest")
async def crm_csv_ingest(org_id: str = Form(...), contacts: UploadFile | None = File(None), companies: UploadFile | None = File(None), deals: UploadFile | None = File(None), ctx: RequestContext = Depends(require_role("ANALYST"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    import csv
    def read_csv(file: UploadFile | None) -> List[Dict[str, str]]:
        if not file:
            return []
        content = file.file.read().decode("utf-8", errors="ignore")
        reader = csv.DictReader(content.splitlines())
        rows = []
        for row in reader:
            rows.append({k.strip().lower(): (v or "").strip() for k, v in row.items()})
        return rows
    cts = read_csv(contacts)
    cps = read_csv(companies)
    dls = read_csv(deals)
    await db.crm_contacts.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": cts, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await db.crm_companies.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": cps, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await db.crm_deals.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": dls, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(org_id, ctx.user_id, "crm_csv_ingest", "crm", {"counts": {"contacts": len(cts), "companies": len(cps), "deals": len(dls)}})
    return {"ok": True, "counts": {"contacts": len(cts), "companies": len(cps), "deals": len(dls)}}

# Identity Resolution / Deduper
@api.post("/crm/dedupe/run")
async def crm_dedupe_run(ctx: RequestContext = Depends(require_role("ANALYST"))):
    org_id = ctx.org_id
    rec_c = await db.crm_contacts.find_one({"org_id": org_id}) or {}
    rec_cp = await db.crm_companies.find_one({"org_id": org_id}) or {}
    contacts = rec_c.get("items", [])
    companies = rec_cp.get("items", [])
    # Build domain map from companies
    domain_to_company = { (c.get("domain") or "").lower(): c for c in companies }
    master: Dict[str, Dict[str, Any]] = {}

    def norm_phone(p: str) -> str:
        return ''.join(ch for ch in (p or '') if ch.isdigit())[-10:]

    def conf_from(email: str, name_a: str, name_b: str) -> float:
        if email:
            return 1.0
        sim = fuzz.token_sort_ratio(name_a, name_b) / 100.0 if name_a and name_b else 0.8
        return min(1.0, 0.8 + 0.2*sim)

    for ct in contacts:
        email = (ct.get("email") or "").lower()
        domain = email.split("@")[-1] if "@" in email else ""
        name = f"{ct.get('firstname','').strip()} {ct.get('lastname','').strip()}".strip()
        phone = norm_phone(ct.get("phone"))
        key = email or (domain + ":" + phone)
        if not key:
            key = str(uuid.uuid4())
        if key not in master:
            master[key] = {
                "master_id": str(uuid.uuid4()),
                "canonical_name": name or (domain or "Unknown"),
                "emails": [email] if email else [],
                "domains": [domain] if domain else [],
                "companies": [],
                "confidence": conf_from(email, name, name)
            }
        else:
            # fuzzy boost if same name similar
            sim = fuzz.token_sort_ratio(master[key]["canonical_name"], name) / 100.0
            master[key]["confidence"] = max(master[key]["confidence"], min(1.0, 0.8 + 0.2*sim))
            if email and email not in master[key]["emails"]:
                master[key]["emails"].append(email)
            if domain and domain not in master[key]["domains"]:
                master[key]["domains"].append(domain)
        # attach company by domain match
        co = domain_to_company.get(domain)
        if co:
            comp_entry = {"company_id": co.get("id") or co.get("company_id"), "crm": "hubspot"}
            if comp_entry not in master[key]["companies"]:
                master[key]["companies"].append(comp_entry)

    # Build list and review_state
    master_list = list(master.values())
    for m in master_list:
        m_conf = m.get("confidence", 0)
        m["review_state"] = "auto" if m_conf >= 0.85 else ("needs_review" if m_conf >= 0.7 else "auto")

    # Compute borderline match pairs (0.7–0.85) between masters sharing a domain or similar name
    pairs: List[Dict[str, Any]] = []
    for i in range(len(master_list)):
        for j in range(i+1, len(master_list)):
            a = master_list[i]; b = master_list[j]
            # quick domain overlap
            if set(a.get("domains", [])) & set(b.get("domains", [])) or fuzz.token_sort_ratio(a.get("canonical_name",""), b.get("canonical_name","")) >= 70:
                conf = fuzz.token_sort_ratio(a.get("canonical_name",""), b.get("canonical_name","")) / 100.0
                if 0.7 <= conf < 0.85:
                    pairs.append({
                        "pair_id": str(uuid.uuid4()),
                        "left_id": a["master_id"],
                        "right_id": b["master_id"],
                        "confidence": round(conf, 2),
                        "fields": {"names": [a.get("canonical_name"), b.get("canonical_name")], "domains": [a.get("domains", []), b.get("domains", [])]},
                        "status": "pending"
                    })

    # Persist
    await db.customer_master.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": master_list, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await db.match_pairs.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": pairs, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(org_id, ctx.user_id, "crm_dedupe", "crm", {"masters": len(master_list), "pairs": len(pairs)})
    return {"ok": True, "masters": len(master_list), "pairs": len(pairs)}

# Cross-Sell Recommender
@api.post("/crm/cross-sell/run")
async def crm_cross_sell_run(ctx: RequestContext = Depends(require_role("ANALYST"))):
    org_id = ctx.org_id
    masters_doc = await db.customer_master.find_one({"org_id": org_id}) or {}
    deals_doc = await db.crm_deals.find_one({"org_id": org_id}) or {}
    masters = masters_doc.get("items", [])
    deals = deals_doc.get("items", [])

    # Index deals by company
    deals_by_company: Dict[str, List[Dict[str, Any]]] = {}
    all_amounts: List[float] = []
    for d in deals:
        cid = d.get("company_id") or d.get("company")
        try:
            amt = float(d.get("amount", 0) or 0)
        except:
            amt = 0.0
        all_amounts.append(amt)
        if cid:
            deals_by_company.setdefault(cid, []).append({**d, "amount": amt})

    def median(vals: List[float]) -> float:
        v = sorted([x for x in vals if isinstance(x, (int,float))])
        if not v:
            return 0.0
        n = len(v)
        return float(v[n//2] if n % 2 == 1 else (v[n//2-1]+v[n//2])/2)

# --- Customers Dashboard APIs ---
@api.get("/customers/master")
async def customers_master(org_id: str, q: Optional[str] = None, min_conf: float = 0.7, limit: int = 50, cursor: Optional[str] = None, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    doc = await db.customer_master.find_one({"org_id": org_id}) or {}
    items = doc.get("items", [])
    # filter
    def matches(m):
        if m.get("confidence", 0) < min_conf:
            return False
        if q:
            s = q.lower()
            fields = [m.get("canonical_name",""), *m.get("emails", []), *m.get("domains", [])]
            return any(s in (f or "").lower() for f in fields)
        return True
    filt = [m for m in items if matches(m)]
    stats = {
        "masters": len(items),
        "shared_accounts": sum(1 for m in items if len({c.get("company_id") for c in m.get("companies", []) if c.get("company_id")}) >= 2),
        "avg_conf": round(sum(m.get("confidence",0) for m in items)/len(items), 2) if items else 0
    }
    # simple cursor: page index base64
    page = int((int(cursor or "0")) or 0)
    start = page*limit
    end = start+limit
    next_cursor = str(page+1) if end < len(filt) else None
    out_items = [
        {"master_id": m.get("master_id"), "canonical_name": m.get("canonical_name"), "confidence": m.get("confidence"), "companies": [c.get("company_id") for c in m.get("companies", []) if c.get("company_id")], "emails": m.get("emails", []), "domains": m.get("domains", []), "review_state": m.get("review_state")}
        for m in filt[start:end]
    ]
    return {"stats": stats, "items": out_items, "cursor": next_cursor}

@api.get("/opps/cross-sell")
async def opps_cross_sell(org_id: str, status: str = "open", limit: int = 50, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    doc = await db.cross_sell_opps.find_one({"org_id": org_id}) or {}
    items = [o for o in doc.get("items", []) if o.get("status", "open") == status]
    items = sorted(items, key=lambda o: o.get("created_at",""), reverse=True)[:limit]
    summary = {"count": len(items), "value": sum(o.get("expected_value",0) for o in items)}
    return {"summary": summary, "items": items}

class ReviewDecision(BaseModel):
    pair_id: str
    decision: str  # merge|split
    master_id: Optional[str] = None

class ReviewPayload(BaseModel):
    org_id: str
    decisions: List[ReviewDecision]

@api.post("/crm/dedupe/review")
async def crm_dedupe_review(payload: ReviewPayload, ctx: RequestContext = Depends(require_role("ANALYST"))):
    if ctx.org_id != payload.org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    pairs_doc = await db.match_pairs.find_one({"org_id": payload.org_id}) or {"items": []}
    masters_doc = await db.customer_master.find_one({"org_id": payload.org_id}) or {"items": []}
    pairs = pairs_doc.get("items", [])
    masters = {m.get("master_id"): m for m in masters_doc.get("items", [])}
    applied = 0
    conflicts: List[str] = []
    new_items = list(masters.values())
    for d in payload.decisions:
        p = next((x for x in pairs if x.get("pair_id") == d.pair_id and x.get("status") == "pending"), None)
        if not p:
            conflicts.append(d.pair_id)
            continue
        if d.decision == "merge" and d.master_id and p.get("left_id") in masters and p.get("right_id") in masters:
            left = masters[p["left_id"]]; right = masters[p["right_id"]]
            # merge right into left
            left["emails"] = list({*left.get("emails", []), *right.get("emails", [])})
            left["domains"] = list({*left.get("domains", []), *right.get("domains", [])})
            left["companies"] = list({tuple(sorted(c.items())) for c in (left.get("companies", []) + right.get("companies", []))})
            left["companies"] = [dict(c) for c in left["companies"]]
            left["confidence"] = max(left.get("confidence",0), right.get("confidence",0))
            left["review_state"] = "human_accepted"
            # remove right
            new_items = [x for x in new_items if x.get("master_id") != right.get("master_id")]
            applied += 1
            p["status"] = "accepted"
        elif d.decision == "split":
            p["status"] = "rejected"
            applied += 1
        else:
            conflicts.append(d.pair_id)
    # persist updates
    await db.customer_master.update_one({"org_id": payload.org_id}, {"$set": {"items": new_items, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await db.match_pairs.update_one({"org_id": payload.org_id}, {"$set": {"items": pairs, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(payload.org_id, ctx.user_id, "crm_review", "crm", {"applied": applied, "conflicts": conflicts})
    return {"applied": applied, "conflicts": conflicts}

class OppStatusPayload(BaseModel):
    status: str
    note: Optional[str] = None

@api.post("/opps/{opp_id}/status")
async def opp_status_update(opp_id: str, body: OppStatusPayload, ctx: RequestContext = Depends(require_role("ADMIN"))):
    org_id = ctx.org_id
    doc = await db.cross_sell_opps.find_one({"org_id": org_id}) or {"items": []}
    updated = False
    for o in doc.get("items", []):
        if o.get("opportunity_id") == opp_id:
            o["status"] = body.status
            notes = o.get("notes", [])
            if body.note:
                notes.append({"note": body.note, "ts": datetime.now(timezone.utc), "by": ctx.user_id})
            o["notes"] = notes
            updated = True
            break
    if not updated:
        raise HTTPException(status_code=404, detail="Opportunity not found")
    await db.cross_sell_opps.update_one({"org_id": org_id}, {"$set": {"items": doc.get("items", []), "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(org_id, ctx.user_id, "opp_status", "opportunity", {"opp_id": opp_id, "status": body.status})
    return {"ok": True}


    default_proxy = median(all_amounts) if all_amounts else 10000.0
    WIN_RATE = 0.3
    DURATION = 6

    opps: List[Dict[str, Any]] = []
    for m in masters:
        comps = [c.get("company_id") for c in m.get("companies", []) if c.get("company_id")]
        uniq = list({c for c in comps})
        if len(uniq) >= 2:
            # compute avg peer spend in other companies
            peer_spends: List[float] = []
            for cid in uniq:
                # consider deals in cid
                for d in deals_by_company.get(cid, []):
                    peer_spends.append(d.get("amount", 0))
            avg_peer_spend = (sum(peer_spends)/len(peer_spends)) if peer_spends else default_proxy
            expected_value = round(avg_peer_spend * WIN_RATE * DURATION)
            nba = "Introduce account owners across companies"
            opps.append({
                "opportunity_id": str(uuid.uuid4()),
                "master_id": m["master_id"],
                "name": m.get("canonical_name",""),
                "companies": uniq,
                "rationale": "Shared buyer across companies",
                "expected_value": expected_value,
                "next_best_action": nba,
                "status": "open",
                "owner_user_id": None,
                "notes": [],
                "created_at": datetime.now(timezone.utc)
            })


# --- Alerts (quick win) ---
class AlertTestPayload(BaseModel):
    org_id: str
    text: Optional[str] = None

@api.post("/alerts/test")
async def alerts_test(body: AlertTestPayload, ctx: RequestContext = Depends(require_role("ADMIN"))):
    if ctx.org_id != body.org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    limits = await get_plan_limits(body.org_id)
    if not limits.get("alerts"):
        raise HTTPException(status_code=403, detail={"code":"PLAN_NOT_ALLOWED"})
    # Fetch org settings for Slack webhook
    settings = await db.org_settings.find_one({"org_id": body.org_id}) or {}
    text = body.text or ":link: New shared account found: Acme PLC (CO1, CO2). EV ~ £12,000. NBA: Intro Co1 → Co2."
    delivered = []
    # Slack webhook
    webhook = settings.get("slack_webhook_url")
    if webhook:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=8.0) as client:
                await client.post(webhook, json={"text": text})
            delivered.append("slack")
        except Exception as e:
            delivered.append(f"slack_error:{e}")
    else:
        delivered.append("slack_missing")
    # Email fallback to OWNER via dev store (mock)
    owner_membership = await db.memberships.find_one({"org_id": body.org_id, "role": "OWNER"})
    owner = None
    if owner_membership and owner_membership.get("user_id"):
        owner = await db.users.find_one({"user_id": owner_membership.get("user_id")}, {"_id": 0})
        if owner and owner.get("email"):
            await send_dev_email(owner.get("email"), "Alert notification", text, action="alert")
            delivered.append("email")
    
    await audit_log_entry(body.org_id, ctx.user_id, "alert_test", "alert", {"delivered": delivered})
    return {"delivered": delivered}

# --- Day 3: Vendor Optimizer (Spend → Savings) ---
from fastapi import UploadFile
import csv as _csv

CATEGORIES = {
    "SaaS": ["LICENCE", "LICENSE", "SUBSCRIPTION", "AWS", "AZURE", "GCP", "GOOGLE CLOUD", "SALESFORCE", "HUBSPOT"],
    "Vendors": ["SUPPLIER", "SERVICES"],
}

DISCOUNT_RATE_DEFAULT = 0.08

@api.post("/ingest/spend/csv")
async def ingest_spend_csv(org_id: str = Form(...), spend: UploadFile | None = File(None), saas: UploadFile | None = File(None), ctx: RequestContext = Depends(require_role("ANALYST"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    warnings: List[str] = []
    ing = {"spend": 0, "saas": 0}

    def read_rows(file: UploadFile | None):
        if not file:
            return []
        content = file.file.read().decode("utf-8", errors="ignore")
        reader = _csv.DictReader(content.splitlines())
        rows = []
        for row in reader:
            rows.append({k.strip().lower(): (v or "").strip() for k, v in row.items()})
        return rows

    spend_rows = read_rows(spend)
    saas_rows = read_rows(saas)

    # Write spend_lines
    to_insert = []
    from datetime import date as _date
    def valid_date(s: str) -> bool:
        try:
            y,m,d = [int(x) for x in (s or '').split('-')]
            _ = _date(y,m,d)
            return True
        except:
            return False
    for r in spend_rows:
        # amount validation
        try:
            amt = float(r.get("amount", 0) or 0)
        except:
            warnings.append("spend line amount parse failed – row skipped")
            continue
        # date validation
        if not valid_date(r.get("date", "")):
            warnings.append("spend line date invalid – row skipped")
            continue
        cat = None
        txt = f"{r.get('vendor','')} {r.get('description','')} {r.get('gl_code','')}".upper()
        for cat_name, kws in CATEGORIES.items():
            if any(kw in txt for kw in kws):
                cat = cat_name; break
        if not cat and not r.get("gl_code"):
            warnings.append("spend line missing gl_code – categorized via keywords")
        to_insert.append({
            "org_id": org_id,
            "company_id": r.get("company_id"),
            "date": r.get("date"),
            "vendor_raw": r.get("vendor"),
            "canonical_vendor_id": None,
            "description": r.get("description"),
            "amount": amt,
            "currency": r.get("currency") or "GBP",
            "gl_code": r.get("gl_code") or None,
            "category": cat or ("SaaS" if "SUBSCRIPTION" in txt else None),
            "iban": r.get("iban") or None,
            "vat_no": r.get("vat_no") or None,
        })
    if to_insert:
        await db.spend_lines.insert_many(to_insert)
        ing["spend"] = len(to_insert)

    # Write saas inventory
    saas_ins = []
    for r in saas_rows:
        try:
            seats = int(float(r.get("seat_count", 0) or 0))
            price = float(r.get("price_per_seat", 0) or 0)
        except:
            seats = 0; price = 0.0
        saas_ins.append({
            "org_id": org_id,
            "vendor": r.get("vendor"),
            "product": r.get("product"),
            "seat_count": seats,
            "price_per_seat": price,
            "term": r.get("term") or "monthly",
            "company_id": r.get("company_id")
        })
    if saas_ins:
        await db.saas_inventory.insert_many(saas_ins)
        ing["saas"] = len(saas_ins)

    await audit_log_entry(org_id, ctx.user_id, "spend_csv", "spend", {"ing": ing, "warnings": len(warnings)})
    return {"ok": True, "ingested": ing, "warnings": warnings}

@api.post("/ingest/spend/refresh")
async def spend_refresh(body: Dict[str, Any], ctx: RequestContext = Depends(require_role("ANALYST"))):
    org_id = body.get("org_id")
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    # Load spend lines in range
    from_dt = body.get("from"); to_dt = body.get("to")
    q = {"org_id": org_id}
    if from_dt and to_dt:
        q["date"] = {"$gte": from_dt, "$lte": to_dt}
    lines = await db.spend_lines.find(q, {"_id": 0}).to_list(50000)

    # Canonicalize vendors by alias and simple normalization
    alias_docs = await db.vendor_master.find({"org_id": org_id}, {"_id": 0}).to_list(5000)
    alias_map = {}
    for v in alias_docs:
        vid = v.get("vendor_id")
        names = [v.get("canonical_name",""), *(v.get("aliases", {}).get("names", []))]
        for n in names:
            alias_map[n.lower()] = vid
    def normalize_vendor(name: str) -> str:
        return (name or "").lower().replace(" ltd","").replace(" limited","").replace(" inc","").replace(" llc","").strip()

    # Assign canonical_vendor_id
    for ln in lines:
        raw = ln.get("vendor_raw") or ""
        nid = alias_map.get(raw.lower()) or alias_map.get(normalize_vendor(raw))
        ln["canonical_vendor_id"] = nid or f"VN-{normalize_vendor(raw)[:24]}"

    # Aggregate spend per vendor and build vendor_master
    total_spend_by_vendor: Dict[str, float] = {}
    companies_by_vendor: Dict[str, set] = {}
    category_by_vendor: Dict[str, str] = {}
    for ln in lines:
        vid = ln["canonical_vendor_id"]
        total_spend_by_vendor[vid] = total_spend_by_vendor.get(vid, 0.0) + float(ln.get("amount", 0) or 0)
        companies_by_vendor.setdefault(vid, set()).add(ln.get("company_id"))
        if not category_by_vendor.get(vid) and ln.get("category"):
            category_by_vendor[vid] = ln.get("category")

    # Annualize based on range days (approx)
    from datetime import date as _date
    def days_between(a: str, b: str) -> int:
        try:
            y1,m1,d1 = [int(x) for x in a.split('-')]; y2,m2,d2 = [int(x) for x in b.split('-')]
            return ( _date(y2,m2,d2) - _date(y1,m1,d1) ).days or 90
        except:
            return 90
    days = days_between(from_dt or "2025-07-01", to_dt or "2025-09-30")
    factor = 365.0 / max(1, days)

    vendor_items = []
    for vid, spend in total_spend_by_vendor.items():
        annual = round(spend * factor)
        # pick canonical name from any line
        any_name = next((ln.get("vendor_raw") for ln in lines if ln["canonical_vendor_id"]==vid and ln.get("vendor_raw")), vid)
        vendor_items.append({
            "org_id": org_id,
            "vendor_id": vid,
            "canonical_name": any_name,
            "aliases": {"names": [], "domains": [], "vat": []},
            "companies": sorted([c for c in companies_by_vendor.get(vid, set()) if c]),
            "category": category_by_vendor.get(vid) or "Vendors",
            "annual_spend": annual
        })

    await db.vendor_master.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": vendor_items, "updated_at": datetime.now(timezone.utc)}}, upsert=True)

    # Compute savings opportunities
    discount_rate = DISCOUNT_RATE_DEFAULT
    try:
        org_set = await db.org_settings.find_one({"org_id": org_id}) or {}
        dr = org_set.get("vendor_discount_rate")
        if dr:
            discount_rate = float(dr)
    except:
        pass
    opps: List[Dict[str, Any]] = []
    # Volume Discount
    for v in vendor_items:
        if len(v.get("companies", [])) >= 2:
            est = round(v.get("annual_spend", 0) * discount_rate)
            if est > 0:
                opps.append({
                    "opportunity_id": str(uuid.uuid4()),
                    "type": "VolumeDiscount",
                    "vendors": [v.get("vendor_id")],
                    "companies": v.get("companies", []),
                    "category": v.get("category"),
                    "est_saving": est,
                    "status": "open",
                    "owner_user_id": None,
                    "notes": [],
                    "playbook_step": f"Consolidate under {v.get('companies', [''])[0]} master; negotiate {int(discount_rate*100)}% on combined",
                    "evidence": {"annual_spend": v.get("annual_spend"), "calc": f"{v.get('annual_spend')} * {discount_rate}"},
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc)
                })
    # SaaS Consolidation
    inv = await db.saas_inventory.find({"org_id": org_id}, {"_id": 0}).to_list(5000)
    total_saas = sum((r.get("seat_count",0) or 0) * (r.get("price_per_seat",0) or 0) for r in inv)
    if total_saas > 0:
        est = max(round(total_saas * 0.15), 0)
        if est > 0:
            opps.append({
                "opportunity_id": str(uuid.uuid4()),
                "type": "Consolidation",
                "vendors": list({(r.get('vendor') or '').strip() for r in inv if r.get('vendor')}),
                "companies": list({(r.get('company_id') or '').strip() for r in inv if r.get('company_id')}),
                "category": "SaaS",
                "est_saving": est,
                "status": "open",
                "owner_user_id": None,
                "notes": [],
                "playbook_step": "Consolidate tools; negotiate 15%",
                "evidence": {"total_saas_spend": total_saas, "calc": f"{total_saas} * 0.15"},
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            })
    # Tail Cleanup
    tail_total = sum(v.get("annual_spend",0) for v in vendor_items if v.get("annual_spend",0) < 300)
    if tail_total > 0:
        opps.append({
            "opportunity_id": str(uuid.uuid4()),
            "type": "TailCleanup",
            "vendors": [v.get("vendor_id") for v in vendor_items if v.get("annual_spend",0) < 300],
            "companies": list({c for v in vendor_items if v.get("annual_spend",0) < 300 for c in v.get("companies", [])}),

            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        })

    await db.savings_opps.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": opps, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    # Annotate with org savings settings if present for transparency
    try:
        org_set = await db.org_settings.find_one({"org_id": org_id}) or {}
        savings_cfg = org_set.get("savings") or {}
        for o in opps:
            o.setdefault("assumptions", {})
            o["assumptions"].update({
                "volume_pct": savings_cfg.get("volume_pct", 8),
                "saas_pct": savings_cfg.get("saas_pct", 15),
                "tail_threshold": savings_cfg.get("tail_threshold", 300),
            })
    except Exception:
        pass
    await db.savings_opps.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": opps, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(org_id, ctx.user_id, "spend_refresh", "spend", {"opps": len(opps)})
    # return after computing
    return {"ok": True, "opps": len(opps)}

# --- Billing: Stripe Lite Checkout ---
import stripe

STRIPE_PUBLIC_KEY = os.environ.get("STRIPE_PUBLIC_KEY")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
APP_URL = os.environ.get("APP_URL", "http://localhost:3000")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

class CheckoutBody(BaseModel):
    org_id: str
    plan: str

@api.get("/plans")
async def get_plan(org_id: str, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    plan = await db.plans.find_one({"org_id": org_id}, {"_id": 0})

@api.get("/billing/public-key")
async def billing_public_key():
    # helper if frontend ever needs publishable key in future
    return {"publishable_key": STRIPE_PUBLIC_KEY}

    ent = await db.entitlements.find_one({"org_id": org_id}, {"_id": 0})
    return {"plan": plan, "entitlements": ent}

@api.post("/billing/checkout")
async def billing_checkout(body: CheckoutBody, ctx: RequestContext = Depends(require_role("OWNER"))):
    if ctx.org_id != body.org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")
    # deny if already >= LITE
    current = await db.plans.find_one({"org_id": body.org_id})
    if current and current.get("tier") in ("LITE","PRO"):
        raise HTTPException(status_code=409, detail="ERR_PLAN_ALREADY_ACTIVATED")
    try:
        # Prefer price-based if STRIPE_LITE_PRICE_ID provided
        lite_price = os.environ.get("STRIPE_LITE_PRICE_ID")
        if lite_price:
            session = stripe.checkout.Session.create(
                mode="payment",
                payment_method_types=["card"],
                line_items=[{"price": lite_price, "quantity": 1}],
                success_url=f"{APP_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{APP_URL}/billing/cancelled",
                metadata={"org_id": body.org_id, "plan": body.plan},
            )
        else:
            session = stripe.checkout.Session.create(
                mode="payment",
                payment_method_types=["card"],
                line_items=[{"price_data": {"currency": "gbp", "product_data": {"name": "UnityOps Snapshot (LITE)"}, "unit_amount": 99700}, "quantity": 1}],
                success_url=f"{APP_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{APP_URL}/billing/cancelled",
                metadata={"org_id": body.org_id, "plan": body.plan},
            )
        await audit_log_entry(body.org_id, ctx.user_id, "checkout_create", "billing", {"session_id": session.id, "plan": body.plan})
        return {"url": session.url}
    except Exception as e:
        await audit_log_entry(body.org_id, ctx.user_id, "checkout_error", "billing", {"error": str(e), "plan": body.plan})
        raise HTTPException(status_code=500, detail=f"Checkout creation failed: {str(e)}")

# Billing helper: get latest billing event for org
@api.get("/billing/last")
async def billing_last(ctx: RequestContext = Depends(require_role("VIEWER"))):
    if not ctx.org_id:
        raise HTTPException(status_code=400, detail="No org selected")
    doc = await db.billing_events.find({"org_id": ctx.org_id}, {"_id": 0}).sort("ts", -1).to_list(1)
    return doc[0] if doc else {}

from fastapi import Header

@api.post("/billing/webhook")
async def billing_webhook(request: Request, stripe_signature: str = Header(None)):
    if not STRIPE_WEBHOOK_SECRET:
        return {"ok": True}
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=stripe_signature, secret=STRIPE_WEBHOOK_SECRET)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature")
    if event.get("type") == "checkout.session.completed":
        data = event["data"]["object"]
        meta = data.get("metadata", {})
        org_id = meta.get("org_id")
        plan = meta.get("plan")
        # Hard check: metadata.org_id must exist and belong to a known org
        if not org_id:
            return {"error": "No org_id in metadata"}
        
        exists_org = await db.orgs.find_one({"org_id": org_id})
        if not exists_org:
            return {"ok": True}
        if plan == "LITE":
            # idempotency on event id
            eid = event.get("id")
            exists = await db.billing_events.find_one({"stripe_id": eid})
            if not exists:
                await db.plans.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "tier": "LITE", "limits": {"companies":3, "connectors":1, "exports": True, "alerts": True}, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
                await db.entitlements.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "snapshot_enabled": True, "activated_at": datetime.now(timezone.utc)}}, upsert=True)
                await db.orgs.update_one({"org_id": org_id}, {"$set": {"ui_prefs": {"show_snapshot_banner": False}}}, upsert=True)
                # capture payment_intent/receipt_url if present
                pi = data.get("payment_intent")
                receipt = None
                try:
                    if data.get("payment_link") and hasattr(data.get("payment_link"), 'receipt_url'):
                        receipt = data.get("payment_link").get("receipt_url")
                except Exception:
                    pass
                await db.billing_events.insert_one({"org_id": org_id, "type": "checkout.session.completed", "stripe_id": eid, "amount": data.get("amount_total"), "currency": data.get("currency"), "payment_intent": pi, "receipt_url": receipt, "ts": datetime.now(timezone.utc)})
    return {"ok": True}

@api.get("/orgs/flags")
async def get_org_flags(ctx: RequestContext = Depends(require_role("VIEWER"))):
    if not ctx.org_id:
        raise HTTPException(status_code=400, detail="No org selected")
    org = await db.orgs.find_one({"org_id": ctx.org_id}, {"_id": 0, "org_flags": 1}) or {}
    flags = org.get("org_flags") or {"demo_seeded": False}
    if "demo_seeded" not in flags:
        flags["demo_seeded"] = False
    return {"org_flags": flags}

# --- Org Settings (Savings assumptions) ---
class SavingsSettings(BaseModel):
    volume_pct: int = 8
    saas_pct: int = 15
    tail_threshold: int = 300

class OrgSettingsPut(BaseModel):
    savings: SavingsSettings

@api.get("/orgs/settings")
async def get_org_settings(ctx: RequestContext = Depends(require_role("VIEWER"))):
    if not ctx.org_id:
        raise HTTPException(status_code=400, detail="No org selected")
    doc = await db.org_settings.find_one({"org_id": ctx.org_id}, {"_id": 0}) or {}
    savings = (doc.get("savings") or {"volume_pct": 8, "saas_pct": 15, "tail_threshold": 300})
    return {"savings": savings}

@api.put("/orgs/settings")
async def put_org_settings(payload: OrgSettingsPut, ctx: RequestContext = Depends(require_role("ADMIN"))):
    if not ctx.org_id:
        raise HTTPException(status_code=400, detail="No org selected")
    s = payload.savings
    # validation
    if not (0 <= s.volume_pct <= 50):
        raise HTTPException(status_code=400, detail="volume_pct out of range")
    if not (0 <= s.saas_pct <= 50):
        raise HTTPException(status_code=400, detail="saas_pct out of range")
    if not (0 <= s.tail_threshold <= 5000):
        raise HTTPException(status_code=400, detail="tail_threshold out of range")
    await db.org_settings.update_one({"org_id": ctx.org_id}, {"$set": {"org_id": ctx.org_id, "savings": s.model_dump(), "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(ctx.org_id, ctx.user_id, "put", "org_settings", {"savings": s.model_dump()})
    return {"ok": True}



# --- Org UI Preferences ---
class OrgPrefsPut(BaseModel):
    ui_prefs: Dict[str, Any]

@api.get("/orgs/prefs")
async def get_org_prefs(ctx: RequestContext = Depends(require_role("VIEWER"))):
    if not ctx.org_id:
        raise HTTPException(status_code=400, detail="No org selected")
    org = await db.orgs.find_one({"org_id": ctx.org_id}, {"_id": 0, "ui_prefs": 1}) or {}
    existing = org.get("ui_prefs") or {}
    # defaults
    prefs = {
        "show_snapshot_banner": True,
        "show_demo_banner": True,
        **{k: v for k, v in existing.items() if k in ("show_snapshot_banner", "show_demo_banner")}
    }
    return {"ui_prefs": prefs}

@api.put("/orgs/prefs")
async def put_org_prefs(payload: OrgPrefsPut, ctx: RequestContext = Depends(require_role("ADMIN"))):
    if not ctx.org_id:
        raise HTTPException(status_code=400, detail="No org selected")
    prefs = payload.ui_prefs or {}
    await db.orgs.update_one({"org_id": ctx.org_id}, {"$set": {"ui_prefs": {"show_snapshot_banner": bool(prefs.get("show_snapshot_banner", True))}, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(ctx.org_id, ctx.user_id, "put", "org_prefs", {"ui_prefs": prefs})
    return {"ok": True}

# --- Billing Entitlements ---
@api.get("/billing/entitlements")
async def billing_entitlements(ctx: RequestContext = Depends(require_role("VIEWER"))):
    if not ctx.org_id:
        raise HTTPException(status_code=400, detail="No org selected")
    limits = await get_plan_limits(ctx.org_id)
    plan = {"tier": limits.get("tier", "FREE")}
    limits_out = {"companies": limits.get("companies", 1), "connectors": limits.get("connectors", 0), "exports": bool(limits.get("exports", False)), "alerts": bool(limits.get("alerts", False))}
    usage = {
        "companies": await db.companies.count_documents({"org_id": ctx.org_id, "is_active": True}),
        "connectors": await db.connections.count_documents({"org_id": ctx.org_id})
    }
    return {"plan": plan, "limits": limits_out, "usage": usage}

# NOTE: The block below was incorrectly appended due to a prior edit; cleaning up to fix indentation/syntax.

# --- Demo Seed ---
@api.post("/demo/seed")
async def demo_seed(ctx: RequestContext = Depends(require_role("ADMIN"))):
    if not ctx.org_id:
        raise HTTPException(status_code=400, detail="No org selected")
    org_id = ctx.org_id
    now = datetime.now(timezone.utc)
    # Seed minimal finance KPIs
    await db.synergy_scores.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "period": "demo", "s_fin": 75}}, upsert=True)
    await db.companies.update_one({"org_id": org_id, "company_id": "CO1"}, {"$set": {"org_id": org_id, "company_id": "CO1", "name": "DemoCo Ltd", "currency": "GBP", "is_active": True, "kpis": {"revenue": 650000, "gm_pct": 42.0, "opex": 240000, "ebitda": 180000, "dso_days": 45}, "score": {"s_fin": 75}, "percentile": 80}}, upsert=True)
    # Seed minimal CRM
    await db.customer_master.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": [{"master_id": str(uuid.uuid4()), "canonical_name": "Alpha Buyer", "emails": ["alpha@demo.co"], "domains": ["demo.co"], "companies": [{"company_id": "CO1", "crm": "hubspot"}], "confidence": 0.9, "review_state": "auto"}], "updated_at": now}}, upsert=True)
    await db.cross_sell_opps.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": [{"opportunity_id": str(uuid.uuid4()), "master_id": "M1", "name": "Cross-sell Alpha", "companies": ["CO1"], "expected_value": 12000, "next_best_action": "Intro", "status": "open", "owner_user_id": None, "notes": [], "created_at": now}] }}, upsert=True)
    # Seed minimal Vendors
    await db.vendor_master.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": [{"vendor_id": "VN-demosaas", "canonical_name": "Demo SaaS", "companies": ["CO1"], "category": "SaaS", "annual_spend": 18000}], "updated_at": now}}, upsert=True)
    await db.savings_opps.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": [{"opportunity_id": str(uuid.uuid4()), "type": "Consolidation", "vendors": ["Demo SaaS"], "companies": ["CO1"], "category": "SaaS", "est_saving": 2700, "status": "open", "owner_user_id": None, "notes": [], "playbook_step": "Consolidate seats", "evidence": {"annual_spend": 18000, "calc": "15%"}, "created_at": now, "updated_at": now}] }}, upsert=True)
    await db.orgs.update_one({"org_id": org_id}, {"$set": {"ui_prefs": {"show_snapshot_banner": True}, "org_flags": {"demo_seeded": True}}}, upsert=True)
    await audit_log_entry(org_id, ctx.user_id, "seed", "demo", {})
    return {"ok": True}

    try:
        settings = await db.org_settings.find_one({"org_id": org_id}) or {}
        webhook = settings.get("slack_webhook_url")
        high_value = [o for o in opps if o.get("est_saving",0) >= 5000]
        if high_value and webhook:
            import httpx
            txt = f":moneybag: Vendor savings found: {high_value[0].get('vendors', [''])[0]} across {', '.join(high_value[0].get('companies', []))}. Est £{high_value[0].get('est_saving')} /yr. Playbook: {high_value[0].get('playbook_step')}"
            async with httpx.AsyncClient(timeout=8.0) as client:
                await client.post(webhook, json={"text": txt})
            await audit_log_entry(org_id, ctx.user_id, "alert_vendor", "alert", {"count": len(high_value)})
        elif high_value:
            # email dev fallback to OWNER
            owner_membership = await db.memberships.find_one({"org_id": org_id, "role": "OWNER"})
            if owner_membership and owner_membership.get("user_id"):
                owner = await db.users.find_one({"user_id": owner_membership.get("user_id")}, {"_id": 0})
                if owner and owner.get("email"):
                    await send_dev_email(owner.get("email"), "Vendor savings", "High value savings opportunities detected", action="alert")
    except Exception:
        pass

    return {"ok": True, "opps": len(opps)}

@api.get("/vendors/categories")
async def vendors_categories(ctx: RequestContext = Depends(require_role("VIEWER"))):
    return {"categories": list(CATEGORIES.keys()), "keywords": CATEGORIES}

# --- Snapshot Orchestrator ---
class SnapshotBody(BaseModel):
    org_id: str
    _from: Optional[str] = None
    to: Optional[str] = None

@api.post("/snapshot/generate")
async def snapshot_generate(body: SnapshotBody, ctx: RequestContext = Depends(require_role("VIEWER"))):
    # per-org snapshot rate limit (2/min)
    try:
        rate_limit(f"snapshot:{ctx.org_id}", SNAPSHOT_RATE_LIMIT, 60)
    except HTTPException as e:
        if e.status_code == 429:
            raise HTTPException(status_code=429, detail={"code":"RATE_LIMITED", "limit_window_sec": 60})
        raise
    if ctx.org_id != body.org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    limits = await get_plan_limits(body.org_id)
    if not limits.get("exports"):
        raise HTTPException(status_code=403, detail={"code":"EXPORTS_NOT_ENABLED"})
    from_d = body._from or "2025-07-01"
    to_d = body.to or "2025-09-30"
    # Run pipelines sequentially (mock operations, ensure success codes)
    try:
        await finance_refresh({"org_id": body.org_id, "from": from_d, "to": to_d}, await authed_ctx())
    except Exception:
        pass
    try:
        await crm_dedupe_run(await authed_ctx())
        await crm_cross_sell_run(await authed_ctx())
    except Exception:
        pass
    try:
        await spend_refresh({"org_id": body.org_id, "from": from_d, "to": to_d, "sources": ["csv"]}, await authed_ctx())
    except Exception:
        pass
    # After successful export, auto-hide snapshot banner
    try:
        await db.orgs.update_one({"org_id": body.org_id}, {"$set": {"ui_prefs": {"show_snapshot_banner": False}}}, upsert=True)
    except Exception:
        pass
    # Export
    pdf_resp = await export_snapshot({"org_id": body.org_id, "from": from_d, "to": to_d}, await authed_ctx())
    return pdf_resp


@api.get("/vendors/master")
async def vendors_master(org_id: str, q: Optional[str] = None, category: Optional[str] = None, shared: str = "any", limit: int = 50, cursor: Optional[str] = None, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    doc = await db.vendor_master.find_one({"org_id": org_id}) or {}
    items = doc.get("items", [])
    def filt(v):
        if category and v.get("category") != category:
            return False
        if q:
            s = q.lower()
            if s not in (v.get("canonical_name","" ) or "").lower():
                return False
        if shared != "any":
            is_shared = len(v.get("companies", [])) >= 2
            if (shared == "true" and not is_shared) or (shared == "false" and is_shared):
                return False
        return True
    arr = [v for v in items if filt(v)]
    page = int((int(cursor or "0")) or 0)
    start = page*limit
    end = start+limit
    next_cursor = str(page+1) if end < len(arr) else None
    summary = {"vendors": len(items), "shared_vendors": sum(1 for v in items if len(v.get("companies", []))>=2), "annual_spend": sum(v.get("annual_spend",0) for v in items)}
    out = [{k: v.get(k) for k in ["vendor_id","canonical_name","companies","category","annual_spend"]} for v in arr[start:end]]
    return {"summary": summary, "items": out, "cursor": next_cursor}

@api.get("/opps/savings")
async def savings_opps_list(org_id: str, status: str = "open", limit: int = 50, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    doc = await db.savings_opps.find_one({"org_id": org_id}) or {}
    items = doc.get("items", [])
    if status != "any":
        items = [o for o in items if o.get("status","open") == status]
    items = sorted(items, key=lambda o: o.get("updated_at",""), reverse=True)[:limit]
    summary = {"count": len(items), "est_saving": sum(o.get("est_saving",0) for o in items)}
    return {"summary": summary, "items": items}

class SavingsStatusPayload(BaseModel):
    status: str
    note: Optional[str] = None

@api.post("/opps/savings/{opp_id}/status")
async def savings_status_update(opp_id: str, body: SavingsStatusPayload, ctx: RequestContext = Depends(require_role("ADMIN"))):
    org_id = ctx.org_id
    doc = await db.savings_opps.find_one({"org_id": org_id}) or {}
    updated = False
    for o in doc.get("items", []):
        if o.get("opportunity_id") == opp_id:
            o["status"] = body.status
            o["updated_at"] = datetime.now(timezone.utc)
            notes = o.get("notes", [])
            if body.note:
                notes.append({"note": body.note, "ts": datetime.now(timezone.utc), "by": ctx.user_id})
            o["notes"] = notes
            updated = True
            break
    if not updated:
        raise HTTPException(status_code=404, detail="Opportunity not found")
    await db.savings_opps.update_one({"org_id": org_id}, {"$set": {"items": doc.get("items", []), "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(org_id, ctx.user_id, "savings_status", "opportunity", {"opp_id": opp_id, "status": body.status})
    return {"ok": True}

class SavingsAssignPayload(BaseModel):
    owner_user_id: str

@api.post("/opps/savings/{opp_id}/assign")
async def savings_assign_update(opp_id: str, body: SavingsAssignPayload, ctx: RequestContext = Depends(require_role("ANALYST"))):
    org_id = ctx.org_id
    doc = await db.savings_opps.find_one({"org_id": org_id}) or {}
    updated = False
    for o in doc.get("items", []):
        if o.get("opportunity_id") == opp_id:
            o["owner_user_id"] = body.owner_user_id
            o["updated_at"] = datetime.now(timezone.utc)
            updated = True
            break
    if not updated:
        raise HTTPException(status_code=404, detail="Opportunity not found")
    await db.savings_opps.update_one({"org_id": org_id}, {"$set": {"items": doc.get("items", []), "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(org_id, ctx.user_id, "savings_assign", "opportunity", {"opp_id": opp_id, "owner": body.owner_user_id})
    return {"ok": True}

class VendorAliasPayload(BaseModel):
    org_id: str
    add_names: Optional[List[str]] = None
    add_domains: Optional[List[str]] = None
    add_vat: Optional[List[str]] = None

@api.post("/vendors/{vendor_id}/alias")
async def vendor_alias_add(vendor_id: str, payload: VendorAliasPayload, ctx: RequestContext = Depends(require_role("ADMIN"))):
    if ctx.org_id != payload.org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    doc = await db.vendor_master.find_one({"org_id": payload.org_id}) or {}
    items = doc.get("items", [])
    for v in items:
        if v.get("vendor_id") == vendor_id:
            aliases = v.get("aliases", {"names": [], "domains": [], "vat": []})
            if payload.add_names:
                aliases["names"] = list({*aliases.get("names", []), *payload.add_names})
            if payload.add_domains:
                aliases["domains"] = list({*aliases.get("domains", []), *payload.add_domains})
            if payload.add_vat:
                aliases["vat"] = list({*aliases.get("vat", []), *payload.add_vat})
            v["aliases"] = aliases
            break
    await db.vendor_master.update_one({"org_id": payload.org_id}, {"$set": {"items": items, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(payload.org_id, ctx.user_id, "vendor_alias_add", "vendor", {"vendor_id": vendor_id})
    return {"ok": True}

@api.get("/crm/dashboard")
async def crm_dashboard(org_id: str, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    opps_doc = await db.cross_sell_opps.find_one({"org_id": org_id}) or {}
    masters_doc = await db.customer_master.find_one({"org_id": org_id}) or {}
    kpis = {
        "shared_accounts": sum(1 for m in (masters_doc.get("items", [])) if len({c.get("company_id") for c in m.get("companies", []) if c.get("company_id")}) >= 2),
        "cross_sell_value": sum(o.get("expected_value", 0) for o in (opps_doc.get("items", []))),
        "churn_risk": 0
    }
    return {"kpis": kpis, "opps": opps_doc.get("items", []), "masters": masters_doc.get("items", [])}

    # Validate and ingest AR
    status_map = {"PAID":"PAID","AUTH":"AUTH","DUE":"DUE","VOID":"VOID"}
    for r in ar_rows:
        inv_id = r.get('invoice_id') or str(uuid.uuid4())
        company_id = r.get('company_id') or 'UNKNOWN'
        issue_date = r.get('issue_date') or None
        due_date = r.get('due_date') or None
        if not due_date and issue_date:
            try:
                # impute +30 days
                idt = datetime.fromisoformat(issue_date)
                due_date = (idt + timedelta(days=30)).date().isoformat()
                warnings.append(f"AR invoice {inv_id} missing due_date – imputed +30 days from issue_date")
            except:
                pass
        try:
            amount = float(r.get('amount', '0') or 0)
        except:
            warnings.append(f"AR invoice {inv_id} amount parse failed – skipped")
            continue
        status = r.get('status', 'DUE').upper()
        if status not in status_map:
            warnings.append(f"AR invoice {inv_id} unknown status '{status}' – mapped to DUE")
            status = 'DUE'
        await db.ar.update_one(
            {"org_id": org_id, "invoice_id": inv_id},
            {"$set": {"org_id": org_id, "invoice_id": inv_id, "company_id": company_id, "issue_date": issue_date, "due_date": due_date, "amount": amount, "status": status}},
            upsert=True
        )
        ingested["ar"] += 1

    # Update data health warnings
    await db.data_health.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "warnings": warnings, "updated_at": datetime.now(timezone.utc)}}, upsert=True)

    await audit_log_entry(org_id, ctx.user_id, "finance_csv", "ingest", {"ingested": ingested, "warnings": len(warnings)})
    return {"ok": True, "ingested": ingested, "warnings": warnings}
@api.post("/invites/accept")
async def accept_invite(payload: VerifyEmailRequest, ctx_user: dict = Depends(get_current_user)):
    # token contains org_id and email (invited)
    try:
        data = decode_jwt(payload.token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")
    if data.get("typ") != "invite":
        raise HTTPException(status_code=400, detail="Invalid token type")
    org_id = data.get("org_id")
    invited_email = (data.get("email") or "").lower()
    if ctx_user.get("email") != invited_email:
        raise HTTPException(status_code=403, detail="Token email mismatch")
    # find pending membership
    pending = await db.memberships.find_one({"org_id": org_id, "invited_email": invited_email, "status": "INVITED"})
    if not pending:
        # if not pending, maybe already active
        existing = await db.memberships.find_one({"org_id": org_id, "user_id": ctx_user["user_id"]})
        if existing:
            return {"message": "Already a member"}
        raise HTTPException(status_code=404, detail="Invite not found")
    await db.memberships.update_one({"membership_id": pending["membership_id"]}, {"$set": {"user_id": ctx_user["user_id"], "status": "ACTIVE"}})
    await audit_log_entry(org_id, ctx_user["user_id"], "accept_invite", "membership", {"membership_id": pending["membership_id"]})
    return {"message": "Invite accepted"}

@api.post("/export/snapshot")
async def export_snapshot(body: Dict[str, Any], ctx: RequestContext = Depends(require_role("VIEWER"))):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from fastapi.responses import StreamingResponse
    import io
    org_id = body.get("org_id")
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    # Feature gate: exports must be enabled
    plan = await db.plans.find_one({"org_id": org_id}) or {}
    if not plan or not (plan.get("limits", {}).get("exports") or plan.get("tier") in ("LITE","PRO")):
        raise HTTPException(status_code=403, detail={"code": "EXPORTS_NOT_ENABLED"})

    # Pull data for sections
    finance = await dashboard_finance(org_id, ctx)
    vendors_open = await savings_opps_list(org_id, "open", 10, ctx)
    cross_sell = await opps_cross_sell(org_id, "open", 5, ctx)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setFont("Helvetica-Bold", 16); c.drawString(50, 800, "Synergy Snapshot")
    c.setFont("Helvetica", 10)
    c.drawString(50, 780, f"Org: {org_id}")
    c.drawString(50, 768, f"Period: {body.get('from','-')} to {body.get('to','-')}")
    c.drawString(50, 756, f"Generated: {datetime.now(timezone.utc).isoformat()}")

    # Executive Summary
    c.setFont("Helvetica-Bold", 12); c.drawString(50, 730, "Executive Summary")
    c.setFont("Helvetica", 10)
    c.drawString(50, 715, f"Synergy Score (Finance): {finance['score']['s_fin']}")
    c.drawString(50, 703, f"Revenue: £{finance['kpis']['revenue']}  GM%: {finance['kpis']['gm_pct']}  EBITDA: £{finance['kpis']['ebitda']}")
    lens = finance.get('customer_lens')
    if lens:
      c.drawString(50, 691, f"Customer Lens: Shared {lens['shared_accounts']}, Cross-sell {lens['cross_sell_count']} (£{lens['cross_sell_value']})")

    # Vendor KPIs
    c.setFont("Helvetica-Bold", 12); c.drawString(50, 670, "Vendors")
    c.setFont("Helvetica", 10)
    c.drawString(50, 655, f"Open savings opportunities: {vendors_open['summary']['count']}  Est. Savings: £{vendors_open['summary']['est_saving']}")

    # Top Cross-Sells
    c.setFont("Helvetica-Bold", 12); c.drawString(50, 635, "Top Cross-Sell Opportunities")
    c.setFont("Helvetica", 10)
    y = 620
    for o in (cross_sell.get('items') or [])[:5]:
        c.drawString(50, y, f"{o.get('name') or o.get('master_id')} • £{o.get('expected_value')} • {', '.join(o.get('companies', []))}")
        y -= 12
        if y < 100: c.showPage(); y = 780

    # Top Vendor Savings Table
    c.setFont("Helvetica-Bold", 12); c.drawString(50, y-10, "Top Vendor Savings")
    y -= 25; c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "Vendors"); c.drawString(250, y, "Companies"); c.drawString(400, y, "Est £/yr");
    c.setFont("Helvetica", 10); y -= 14
    for o in (vendors_open.get('items') or [])[:10]:
        c.drawString(50, y, ", ".join(o.get('vendors', []))[:30])
        c.drawString(250, y, ", ".join(o.get('companies', []))[:20])
        c.drawString(400, y, str(o.get('est_saving')))
        y -= 12
        if y < 100: c.showPage(); y = 780

    # Footer with configurable assumptions
    cfg = await db.org_settings.find_one({"org_id": org_id}) or {}
    savings = cfg.get("savings") or {"volume_pct": 8, "saas_pct": 15, "tail_threshold": 300}
    c.setFont("Helvetica", 8)
    c.drawString(50, 50, f"Assumptions: Volume {savings['volume_pct']}%, SaaS {savings['saas_pct']}%, Tail threshold £{savings['tail_threshold']}.")
    c.showPage(); c.save()
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=synergy_snapshot.pdf"})

# Token consumption redirects for reset and invite accept (public GET)
@api.get("/reset/consume")
async def reset_consume(token: str):
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/reset-password?token={token}", status_code=302)

@api.get("/invites/accept")
async def invite_accept_redirect(token: str):
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/accept-invite?token={token}", status_code=302)

@api.get("/orgs/{org_id}/members")
async def list_members(org_id: str, ctx: RequestContext = Depends(require_role("ADMIN"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    members = await db.memberships.find({"org_id": org_id}, {"_id": 0}).to_list(200)
    return members


@api.patch("/members/{membership_id}")
async def patch_member_role(membership_id: str, payload: MemberRolePatch, ctx: RequestContext = Depends(require_role("ADMIN"))):
    m = await db.memberships.find_one({"membership_id": membership_id}, {"_id": 0})
    if not m or m.get("org_id") != ctx.org_id:
        raise HTTPException(status_code=404, detail="Membership not found")
    # Only OWNER can assign OWNER
    if payload.role == "OWNER" and ctx.role != "OWNER":
        raise HTTPException(status_code=403, detail="Only OWNER can grant OWNER")
    await db.memberships.update_one({"membership_id": membership_id}, {"$set": {"role": payload.role}})
    await audit_log_entry(ctx.org_id, ctx.user_id, "role_change", "membership", {"membership_id": membership_id, "role": payload.role})
    return {"message": "Role updated"}

# --- Audit & Dev Email Endpoints ---
@api.get("/audit/logs")
async def get_audit_logs(org_id: str, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        # allow owner/admin/analyst to view only the selected org
        raise HTTPException(status_code=403, detail="Forbidden")
    logs = await db.audit_logs.find({"org_id": org_id}, {"_id": 0}).sort("ts", -1).to_list(200)
    return logs

@api.get("/dev/emails")
async def dev_emails():
    # Dev helper - last 50 emails
    emails = await db.dev_emails.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    return emails

# --- Lifecycle ---
@app.on_event("startup")
async def on_startup():
    await ensure_indexes()
    logger.info("Indexes ensured; app started")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Include the API router
app.include_router(api)
