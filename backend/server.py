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
    async def _checker(ctx: RequestContext = Depends(lambda user=Depends(get_current_user), req: Request = None: None)):
        # This wrapper is not used directly; proper dependency defined below
        return ctx
    # We'll return a dependency function below
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
    except Exception as e:
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
    await send_dev_email(
        to=email,
        subject=f"You're invited to join org",
        body=f"Join org: /api/invites/accept?token={invite_token}",
        action="invite",
        token=invite_token,
        url_path=f"/api/invites/accept?token={invite_token}",
    )
    await audit_log_entry(org_id, ctx.user_id, "invite", "membership", {"email": email, "role": role})
    return {"message": "Invitation sent"}

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
