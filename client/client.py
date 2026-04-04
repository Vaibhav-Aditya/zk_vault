"""
ZK Authentication Vault — Client CLI
======================================
Interactive command-line client for the ZK vault server.

Usage:
    python client.py --server https://zk-auth-vault.onrender.com

Commands (prompted interactively):
    register   — generate keys and register with the server
    login      — perform Schnorr ZKP login, receive JWT
    upload     — encrypt a local file and upload to vault
    list       — list files in your vault
    download   — download and decrypt a file from vault
    delete     — delete a file from vault
    logout     — clear local session
    exit       — quit
"""
import base64
import argparse
import json
import os
import secrets
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import requests
from shared.schnorr import (
    generate_keypair,
    generate_commitment,
    generate_response,
)
from shared.crypto_utils import derive_file_key, encrypt_file, decrypt_file
from shared.schnorr import dh_agree, ephemeral_keypair, P
from shared.crypto_utils import derive_envelope_key, wrap_key, unwrap_key

KEYS_DIR = Path.home() / ".zk_vault"
KEYS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

def _keys_path(username: str) -> Path:
    return KEYS_DIR / f"{username}.json"

def save_keys(username: str, private_key: int, public_key: int):
    data = {"username": username, "private_key": private_key, "public_key": public_key}
    path = _keys_path(username)
    path.write_text(json.dumps(data, indent=2))
    path.chmod(0o600)
    print(f"  Keys saved to {path}")

def load_keys(username: str) -> tuple[int, int] | None:
    path = _keys_path(username)
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return data["private_key"], data["public_key"]

SESSION_FILE = KEYS_DIR / "session.json"

def save_session(username: str, token: str):
    SESSION_FILE.write_text(json.dumps({"username": username, "token": token}))
    SESSION_FILE.chmod(0o600)

def load_session() -> tuple[str, str] | None:
    if not SESSION_FILE.exists():
        return None
    data = json.loads(SESSION_FILE.read_text())
    return data.get("username"), data.get("token")

def clear_session():
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()

def api(method: str, base_url: str, path: str, token: str | None = None, **kwargs):
    url = base_url.rstrip("/") + path
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.request(method, url, headers=headers, timeout=60, **kwargs)
    return resp

def cmd_register(base_url: str):
    username = input("  Username: ").strip()
    if not username:
        print("Username cannot be empty")
        return

    if _keys_path(username).exists():
        overwrite = input(f"Keys for '{username}' already exist. Overwrite? [y/N]: ").strip().lower()
        if overwrite != "y":
            print("Aborted.")
            return

    print("Generating Schnorr keypair (2048-bit safe prime)…")
    private_key, public_key = generate_keypair()

    resp = api("POST", base_url, "/auth/register", json={
        "username": username,
        "public_key": public_key,
    })

    if resp.status_code == 201:
        save_keys(username, private_key, public_key)
        print(f"Registered as '{username}'")
    elif resp.status_code == 409:
        print("Username already taken. Choose another.")
    else:
        print(f"Error {resp.status_code}: {resp.text}")

def cmd_login(base_url: str) -> tuple[str, str] | None:
    username = input("  Username: ").strip()
    keys = load_keys(username)
    if keys is None:
        print(f"No local keys found for '{username}'. Register first.")
        return None

    private_key, public_key = keys

    r, T = generate_commitment()

    resp = api("POST", base_url, "/auth/challenge", json={
        "username": username,
        "commitment": T,
    })
    if resp.status_code != 200:
        print(f"Challenge error {resp.status_code}: {resp.text}")
        return None

    data = resp.json()
    session_id = data["session_id"]
    c = data["challenge"]

    s = generate_response(r, c, private_key)

    resp = api("POST", base_url, "/auth/verify", json={
        "session_id": session_id,
        "response": s,
    })
    if resp.status_code == 200:
        token = resp.json()["access_token"]
        save_session(username, token)
        print(f"Logged in as '{username}'")
        return username, token
    elif resp.status_code == 401:
        print("ZKP verification failed — proof rejected by server")
    else:
        print(f"Error {resp.status_code}: {resp.text}")
    return None


def cmd_upload(base_url: str, token: str, public_key: int):
    file_path = input("  Local file path: ").strip()
    path = Path(file_path).expanduser()
    if not path.exists():
        print(f"File not found: {path}")
        return

    raw = path.read_bytes()
    print(f"Encrypting '{path.name}' ({len(raw):,} bytes)…")

    salt = secrets.token_bytes(32)
    file_key = derive_file_key(public_key, salt)
    nonce, ciphertext = encrypt_file(raw, file_key)
    bundle = salt + nonce + ciphertext
    print(f"Uploading encrypted bundle ({len(bundle):,} bytes)…")

    resp = api(
        "POST", base_url, "/vault/upload",
        token=token,
        files={"file": (path.name, bundle, "application/octet-stream")},
    )
    if resp.status_code == 200:
        result = resp.json()
        print(f"Uploaded — file_id: {result['file_id']}")
    else:
        print(f"Upload error {resp.status_code}: {resp.text}")


def cmd_list(base_url: str, token: str):
    resp = api("GET", base_url, "/vault/list", token=token)
    if resp.status_code != 200:
        print(f"Error {resp.status_code}: {resp.text}")
        return

    files = resp.json()
    if not files:
        print("(vault is empty)")
        return

    print(f"\n{'FILE ID':<38}  {'NAME':<30}  {'SIZE':>10}  UPLOADED")
    print("  " + "─" * 96)
    for f in files:
        size_str = f"{f['size']:,} B"
        print(f"{f['file_id']:<38}  {f['filename']:<30}  {size_str:>10}  {f['uploaded_at'][:19]}")


def cmd_download(base_url: str, token: str, public_key: int):
    file_id = input("File ID to download: ").strip()
    out_path = input("Save decrypted file to: ").strip()
    out = Path(out_path).expanduser()

    resp = api("GET", base_url, f"/vault/download/{file_id}", token=token)
    if resp.status_code != 200:
        print(f"Download error {resp.status_code}: {resp.text}")
        return

    bundle = resp.content
    print(f"Received {len(bundle):,} bytes — decrypting…")

    try:
        salt = bundle[:32]
        nonce = bundle[32:44]
        ciphertext = bundle[44:]
        file_key = derive_file_key(public_key, salt)
        plaintext = decrypt_file(nonce, ciphertext, file_key)
        out.write_bytes(plaintext)
        print(f"Decrypted file saved to: {out}  ({len(plaintext):,} bytes)")
    except Exception as e:
        print(f"Decryption failed: {e}")


def cmd_delete(base_url: str, token: str):
    file_id = input("  File ID to delete: ").strip()
    confirm = input(f"  Delete file '{file_id}'? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    resp = api("DELETE", base_url, f"/vault/delete/{file_id}", token=token)
    if resp.status_code == 200:
        print("File deleted")
    else:
        print(f"Error {resp.status_code}: {resp.text}")


def cmd_share(base_url: str, username: str, token: str):
    file_id   = input("  File ID to share: ").strip()
    recipient = input("  Recipient username: ").strip()

    if not file_id or not recipient:
        print("File ID and recipient are required")
        return

    resp = api("GET", base_url, f"/users/{recipient}/pubkey", token=token)
    if resp.status_code != 200:
        print(f"Could not fetch recipient's public key: {resp.text}")
        return
    Y_recipient = resp.json()["public_key"]

    resp = api("GET", base_url, f"/vault/download/{file_id}", token=token)
    if resp.status_code != 200:
        print(f"Could not download file: {resp.text}")
        return

    bundle = resp.content
    salt       = bundle[:32]
    nonce      = bundle[32:44]
    ciphertext = bundle[44:]

    keys = load_keys(username)
    if keys is None:
        print("Local keys not found")
        return
    _, my_public_key = keys

    file_key = derive_file_key(my_public_key, salt)

    try:
        decrypt_file(nonce, ciphertext, file_key)
    except Exception:
        print("Could not decrypt file — key mismatch")
        return

    r_eph, R_eph = ephemeral_keypair()

    shared_secret = dh_agree(r_eph, Y_recipient)
    envelope_key  = derive_envelope_key(shared_secret)

    wrap_nonce, wrapped_key = wrap_key(file_key, envelope_key)

    payload = {
        "recipient":         recipient,
        "file_id":           file_id,
        "ephemeral_pubkey":  R_eph,
        "wrapped_key_nonce": base64.b64encode(wrap_nonce).decode(),
        "wrapped_key":       base64.b64encode(wrapped_key).decode(),
        "wrapped_key_salt":  base64.b64encode(salt).decode(),
    }

    resp = api("POST", base_url, "/vault/share", token=token, json=payload)
    if resp.status_code == 200:
        print(f"File shared with '{recipient}'")
        print(f"Share ID: {resp.json()['share_id']}")
    else:
        print(f"Error {resp.status_code}: {resp.text}")


def cmd_shared_with_me(base_url: str, token: str, private_key: int):
    resp = api("GET", base_url, "/vault/shared-with-me", token=token)
    if resp.status_code != 200:
        print(f"Error {resp.status_code}: {resp.text}")
        return

    shares = resp.json()
    if not shares:
        print("(no files shared with you)")
        return

    print(f"\n  {'SHARE ID':<38}  {'FILE':<28}  {'FROM':<16}  SHARED AT")
    print("  " + "─" * 100)
    for s in shares:
        print(
            f"  {s['share_id']:<38}  {s['filename']:<28}  "
            f"{s['owner']:<16}  {s['shared_at'][:19]}"
        )

    print()
    action = input("Download a file? Enter share_id (or blank to skip): ").strip()
    if not action:
        return

    share = next((s for s in shares if s["share_id"] == action), None)
    if share is None:
        print("Share ID not found in list")
        return

    out_path = input("Save decrypted file to: ").strip()
    out      = Path(out_path).expanduser()

    resp = api("GET", base_url, f"/vault/download/{share['file_id']}", token=token)
    if resp.status_code != 200:
        print(f"Download error: {resp.text}")
        return

    bundle = resp.content

    try:
        R_eph        = share["ephemeral_pubkey"]
        wrap_nonce   = base64.b64decode(share["wrapped_key_nonce"])
        wrapped_key  = base64.b64decode(share["wrapped_key"])
        nonce        = bundle[32:44]
        ciphertext   = bundle[44:]

        shared_secret = dh_agree(private_key, R_eph)
        envelope_key  = derive_envelope_key(shared_secret)
        file_key      = unwrap_key(wrap_nonce, wrapped_key, envelope_key)
        plaintext     = decrypt_file(nonce, ciphertext, file_key)

        out.write_bytes(plaintext)
        print(f"Decrypted and saved to: {out}  ({len(plaintext):,} bytes)")
    except Exception as e:
        print(f"Decryption failed: {e}")


def cmd_revoke_share(base_url: str, token: str):
    resp = api("GET", base_url, "/vault/my-shares", token=token)
    if resp.status_code != 200:
        print(f"Error fetching shares: {resp.text}")
        return

    shares = resp.json()
    if not shares:
        print("(you have not shared any files)")
        return

    print(f"\n  {'SHARE ID':<38}  {'FILE':<28}  {'SHARED WITH':<16}  SHARED AT")
    print("  " + "─" * 100)
    for s in shares:
        print(
            f"  {s['share_id']:<38}  {s['filename']:<28}  "
            f"{s['recipient']:<16}  {s['shared_at'][:19]}"
        )

    print()
    share_id = input("  Share ID to revoke (or blank to cancel): ").strip()
    if not share_id:
        return

    confirm = input(f"  Revoke share '{share_id}'? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    resp = api("DELETE", base_url, f"/vault/share/{share_id}", token=token)
    if resp.status_code == 200:
        print("Share revoked")
    else:
        print(f"Error {resp.status_code}: {resp.text}")

BANNER = """
╔══════════════════════════════════════════╗
║   ZK Authentication Vault (Schnorr ZKP)  ║
╚══════════════════════════════════════════╝
Commands: register | login | upload | list | download | delete | share | shared | revoke | logout | exit
"""

MENU = """
  register   — create account (generates keypair)
  login      — ZKP authentication
  upload     — encrypt & upload file
  list       — list vault files
  download   — download & decrypt file
  delete     — delete a vault file
  logout     — clear local session
  share      — share a file
  shared     — see files shared with me
  revoke     — revoke a shared file
  exit       — quit
"""

def main():
    parser = argparse.ArgumentParser(description="ZK Vault Client")
    parser.add_argument(
        "--server",
        default=os.environ.get("ZK_VAULT_SERVER", "http://localhost:8000"),
        help="Server base URL (default: http://localhost:8000)",
    )
    args = parser.parse_args()
    base_url = args.server.rstrip("/")

    print(BANNER)
    print(f"  Server: {base_url}\n")

    session = load_session()
    current_user: str | None = None
    current_token: str | None = None

    if session:
        current_user, current_token = session
        print(f"Session restored for '{current_user}' (may have expired)")

    while True:
        logged = f"[{current_user}]" if current_user else "[not logged in]"
        try:
            cmd = input(f"\nzk-vault {logged}> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if cmd in ("exit", "quit", "q"):
            break

        elif cmd == "help":
            print(MENU)

        elif cmd == "register":
            cmd_register(base_url)

        elif cmd == "login":
            result = cmd_login(base_url)
            if result:
                current_user, current_token = result

        elif cmd == "logout":
            clear_session()
            current_user = None
            current_token = None
            print("Logged out")

        elif cmd in ("upload", "list", "download", "delete", "share", "shared", "revoke"):
            if not current_user or not current_token:
                print("Please login first")
                continue
            keys = load_keys(current_user)
            if keys is None:
                print("Local keys not found — please re-register")
                continue
            private_key, public_key = keys

            if cmd == "upload":
                cmd_upload(base_url, current_token, public_key)
            elif cmd == "list":
                cmd_list(base_url, current_token)
            elif cmd == "download":
                cmd_download(base_url, current_token, public_key)
            elif cmd == "delete":
                cmd_delete(base_url, current_token)
            elif cmd == "share":
                cmd_share(base_url, current_user, current_token)
            elif cmd == "shared":
                cmd_shared_with_me(base_url, current_token, private_key)
            elif cmd == "revoke":
                cmd_revoke_share(base_url, current_token)

        elif cmd == "":
            pass

        else:
            print(f"  Unknown command: '{cmd}'. Type 'help' for options.")

if __name__ == "__main__":
    main()