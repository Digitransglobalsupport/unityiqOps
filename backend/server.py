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

# --- Mock Xero OAuth + CSV ingest scaffolding (Day 1 prep) ---
@api.post("/connections/xero/oauth/start")
async def xero_oauth_start(body: Dict[str, Any], ctx: RequestContext = Depends(require_role("ADMIN"))):
    # Return mock consent URL that redirects back to callback with state
    org_id = body.get("org_id")
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    state = str(uuid.uuid4())
    await db.oauth_states.insert_one({"state": state, "org_id": org_id, "ts": datetime.now(timezone.utc)})
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

@api.post("/ingest/finance/refresh")
async def finance_refresh(body: Dict[str, Any], ctx: RequestContext = Depends(require_role("ANALYST"))):
    org_id = body.get("org_id")
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")

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
    # Pull data health warnings from last CSV ingest
    health = await db.data_health.find_one({"org_id": org_id}, {"_id": 0})
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
    # Add percentile banding for demo
    demo_companies = companies or [
        {"company_id": "CO1", "name": "Alpha Ltd", "currency": "GBP", "kpis": {"revenue": 650000, "gm_pct": 44.0, "opex": 240000, "ebitda": 190000, "dso_days": 42}, "score": {"s_fin": 78}, "percentile": 82},
        {"company_id": "CO2", "name": "Beta BV", "currency": "EUR", "kpis": {"revenue": 600000, "gm_pct": 38.5, "opex": 280000, "ebitda": 40000, "dso_days": 53}, "score": {"s_fin": 65}, "percentile": 55}
    ]
    return {
        "org_id": org_id,
        "period": {"from": "2025-07-01", "to": "2025-09-30"},
        "last_sync_at": datetime.now(timezone.utc).isoformat(),
        "score": {
            "s_fin": (score or {}).get("s_fin", 72),
            "weights": {"gm": 0.4, "opex": 0.4, "dso": 0.2},
            "drivers": {"gm_delta_pct": 2.7, "opex_delta_pct": -1.4, "dso_delta_days": -6, "notes": ["GM improving vs prior quarter","DSO trending down 6 days QoQ"]}
        },
        "kpis": {"revenue": 1250000, "gm_pct": 41.2, "opex": 520000, "ebitda": 230000, "dso_days": 47},
        "companies": demo_companies,
        "data_health": {"stale_days": 0, "missing_fields": [], "warnings": (health or {}).get("warnings", [])},
        "customer_lens": customer_lens
    }

@api.get("/connections/status")
async def connections_status(org_id: str, ctx: RequestContext = Depends(require_role("VIEWER"))):
    if ctx.org_id != org_id:
        raise HTTPException(status_code=400, detail="Org mismatch")
    conn = await db.connections.find_one({"org_id": org_id, "vendor": "xero"}, {"_id": 0})
    tenants = []
    if conn and conn.get("tenant_id"):
        tenants = [{"tenant_id": conn["tenant_id"], "name": "Alpha Ltd"}]
    return {"xero": {"connected": bool(conn), "last_sync_at": (conn or {}).get("updated_at"), "tenants": tenants}}

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

    # Persist
    await db.cross_sell_opps.update_one({"org_id": org_id}, {"$set": {"org_id": org_id, "items": opps, "updated_at": datetime.now(timezone.utc)}}, upsert=True)
    await audit_log_entry(org_id, ctx.user_id, "crm_cross_sell", "crm", {"opps": len(opps)})
    return {"ok": True, "opps": len(opps)}

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

        company_id = r.get('company_id') or 'UNKNOWN'
        await db.bs.update_one(
            {"org_id": org_id, "company_id": company_id, "period": period},
            {"$set": {"org_id": org_id, "company_id": company_id, "period": period, "receivables": receivables}},
            upsert=True
        )
        receivables_map[(company_id, period)] = receivables
        ingested["bs"] += 1

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
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 800, "Synergy Snapshot")
    c.setFont("Helvetica", 10)
    c.drawString(50, 780, f"Org: {org_id}")
    c.drawString(50, 768, f"Period: {body.get('period_from','-')} to {body.get('period_to','-')}")
    c.drawString(50, 750, "This is a mock PDF for demo purposes. Charts and tables will render here.")
    c.showPage()
    c.save()
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
