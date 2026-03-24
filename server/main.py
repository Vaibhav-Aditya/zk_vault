"""
ZK Authentication Vault — Server
=================================
FastAPI application implementing the Schnorr ZKP handshake and encrypted
file vault for multiple users.

Authentication flow
-------------------
1.  POST /auth/register   — store username + public key Y
2.  POST /auth/challenge  — server returns (session_id, commitment T_server,
                            and challenge c) for a ZKP round
3.  POST /auth/verify     — client sends response s; server checks ZKP and
                            issues a short-lived JWT

File vault
----------
4.  POST /vault/upload    — upload an AES-GCM encrypted file blob
5.  GET  /vault/list      — list user's files
6.  GET  /vault/download/{file_id} — download encrypted blob
7.  DELETE /vault/delete/{file_id} — delete a file
"""

import os
import sys
import uuid
import json
import time
import secrets
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jwt
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from tinydb import TinyDB, Query

from shared.schnorr import G, P, Q, generate_commitment, generate_challenge, verify

# ── Configuration ────────────────────────────────────────────────────────────
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 3600          # 1 hour
CHALLENGE_TTL_SECONDS = 120        # challenge expires in 2 min

DATA_DIR = Path(os.environ.get("DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

VAULT_DIR = DATA_DIR / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

db = TinyDB(DATA_DIR / "db.json", indent=2)
users_table    = db.table("users")
sessions_table = db.table("sessions")   # pending ZKP challenges
files_table    = db.table("files")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("zk-vault")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="ZK Authentication Vault",
    description="Zero-Knowledge Proof file vault using Schnorr Identification Protocol",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic models ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    public_key: int = Field(..., description="Y = g^x mod p")

class ChallengeRequest(BaseModel):
    username: str
    commitment: int = Field(..., description="T = g^r mod p sent by prover")

class VerifyRequest(BaseModel):
    session_id: str
    response: int = Field(..., description="s = (r - c*x) mod Q")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = JWT_EXPIRY_SECONDS

class FileMetadata(BaseModel):
    file_id: str
    filename: str
    size: int
    uploaded_at: str

# ── Auth helpers ──────────────────────────────────────────────────────────────

def issue_jwt(username: str) -> str:
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY_SECONDS,
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def require_auth(authorization: str = Header(...)) -> str:
    """Dependency: validate Bearer JWT, return username."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── Routes: Registration & Authentication ─────────────────────────────────────

@app.post("/auth/register", status_code=201, summary="Register a new user")
def register(body: RegisterRequest):
    UserQ = Query()
    if users_table.search(UserQ.username == body.username):
        raise HTTPException(status_code=409, detail="Username already taken")

    # Validate public key is in the group
    if not (1 < body.public_key < P):
        raise HTTPException(status_code=400, detail="Public key out of range")

    users_table.insert({
        "username": body.username,
        "public_key": body.public_key,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    log.info("Registered user: %s", body.username)
    return {"message": f"User '{body.username}' registered successfully"}


@app.post("/auth/challenge", summary="Start ZKP handshake — get challenge")
def challenge(body: ChallengeRequest):
    """
    Client sends its commitment T = g^r mod p.
    Server replies with a random challenge c and stores a pending session.
    """
    UserQ = Query()
    user = users_table.search(UserQ.username == body.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Validate commitment is in group
    if not (1 < body.commitment < P):
        raise HTTPException(status_code=400, detail="Commitment out of range")

    c = generate_challenge()
    session_id = secrets.token_hex(16)

    sessions_table.insert({
        "session_id": session_id,
        "username": body.username,
        "commitment": body.commitment,   # T from client
        "challenge": c,
        "expires_at": time.time() + CHALLENGE_TTL_SECONDS,
    })

    log.info("Challenge issued for user: %s  session: %s", body.username, session_id)
    return {"session_id": session_id, "challenge": c}


@app.post("/auth/verify", response_model=TokenResponse, summary="Verify ZKP response")
def verify_proof(body: VerifyRequest):
    """
    Client sends response s = (r - c*x) mod Q.
    Server verifies: g^s * Y^c ≡ T (mod P).
    """
    SessQ = Query()
    sessions = sessions_table.search(SessQ.session_id == body.session_id)
    if not sessions:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    session = sessions[0]

    # Check expiry
    if time.time() > session["expires_at"]:
        sessions_table.remove(SessQ.session_id == body.session_id)
        raise HTTPException(status_code=410, detail="Challenge expired")

    # Fetch user's public key
    UserQ = Query()
    user = users_table.search(UserQ.username == session["username"])[0]

    Y = user["public_key"]
    T = session["commitment"]
    c = session["challenge"]
    s = body.response

    # Remove session immediately (prevent replay)
    sessions_table.remove(SessQ.session_id == body.session_id)

    if not verify(Y, T, c, s):
        log.warning("ZKP verification FAILED for user: %s", session["username"])
        raise HTTPException(status_code=401, detail="Zero-knowledge proof verification failed")

    log.info("ZKP verification SUCCESS for user: %s", session["username"])
    token = issue_jwt(session["username"])
    return TokenResponse(access_token=token)


# ── Routes: File Vault ────────────────────────────────────────────────────────

@app.post("/vault/upload", summary="Upload an encrypted file to the vault")
async def upload_file(
    file: UploadFile = File(...),
    username: str = Depends(require_auth),
):
    """
    The client must encrypt the file locally before uploading.
    The server stores the raw encrypted bytes — it cannot decrypt them.
    """
    MAX_SIZE = 100 * 1024 * 1024  # 100 MB
    data = await file.read()
    if len(data) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 100 MB)")

    file_id = str(uuid.uuid4())
    user_vault = VAULT_DIR / username
    user_vault.mkdir(parents=True, exist_ok=True)

    file_path = user_vault / file_id
    file_path.write_bytes(data)

    files_table.insert({
        "file_id": file_id,
        "username": username,
        "filename": file.filename or "unnamed",
        "size": len(data),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    })

    log.info("File uploaded: %s  user: %s  size: %d bytes", file_id, username, len(data))
    return {"file_id": file_id, "filename": file.filename, "size": len(data)}


@app.get("/vault/list", response_model=list[FileMetadata], summary="List vault files")
def list_files(username: str = Depends(require_auth)):
    FileQ = Query()
    records = files_table.search(FileQ.username == username)
    return [
        FileMetadata(
            file_id=r["file_id"],
            filename=r["filename"],
            size=r["size"],
            uploaded_at=r["uploaded_at"],
        )
        for r in records
    ]


@app.get("/vault/download/{file_id}", summary="Download an encrypted file")
def download_file(file_id: str, username: str = Depends(require_auth)):
    FileQ = Query()
    records = files_table.search((FileQ.file_id == file_id) & (FileQ.username == username))
    if not records:
        raise HTTPException(status_code=404, detail="File not found")

    record = records[0]
    file_path = VAULT_DIR / username / file_id
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File data missing on server")

    data = file_path.read_bytes()
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{record["filename"]}"'},
    )


@app.delete("/vault/delete/{file_id}", summary="Delete a vault file")
def delete_file(file_id: str, username: str = Depends(require_auth)):
    FileQ = Query()
    records = files_table.search((FileQ.file_id == file_id) & (FileQ.username == username))
    if not records:
        raise HTTPException(status_code=404, detail="File not found")

    file_path = VAULT_DIR / username / file_id
    if file_path.exists():
        file_path.unlink()

    files_table.remove((FileQ.file_id == file_id) & (FileQ.username == username))
    log.info("File deleted: %s  user: %s", file_id, username)
    return {"message": "File deleted successfully"}


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/", include_in_schema=False)
def root():
    return {"message": "ZK Authentication Vault API", "docs": "/docs"}