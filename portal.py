import os
import sys
import re
import time
import json
import uuid
import base64
import socket
import ssl
import concurrent.futures
import sqlite3
import datetime
import subprocess
import threading
import secrets
import string
import hashlib
import gzip
import shutil
from typing import Optional, Dict, Any, List
from urllib.parse import quote

import requests
import qrcode
import io
from fastapi import FastAPI, Request, Response, Form, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, FileResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

# ----------------- Configuration & Paths ----------------- #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
XUI_DIR = os.path.join(BASE_DIR, "3x-ui", "x-ui")
XUI_EXE = os.path.join(XUI_DIR, "3x-ui.exe")
DB_PATH = os.path.join(XUI_DIR, "x-ui.db")
PORTAL_DB = os.path.join(BASE_DIR, "portal.db")
CLOUDFLARED_EXE = os.path.join(BASE_DIR, "cloudflared.exe")
RULES_DIR = os.path.join(BASE_DIR, "rules")

AUTH_FILE = os.path.join(BASE_DIR, "admin_auth.json")
DOMAINS_FILE = os.path.join(BASE_DIR, "custom_direct_domains.json")
TELEGRAM_FILE = os.path.join(BASE_DIR, "telegram_config.json")

# Log paths
LOG_DIR = os.path.join(XUI_DIR, "log")
ARCHIVE_DIR = os.path.join(LOG_DIR, "archive")
ACCESS_LOG = os.path.join(LOG_DIR, "access.log")
ERROR_LOG = os.path.join(LOG_DIR, "error.log")

CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
portal_config: Dict[str, Any] = {}
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            portal_config = json.load(f)
    except Exception as e:
        print(f"[Config Load Error] {e}")

PORTAL_TITLE = os.environ.get("PORTAL_TITLE") or portal_config.get("PORTAL_TITLE") or "Family Home VPN"
PORTAL_PORT = int(os.environ.get("PORTAL_PORT") or portal_config.get("PORTAL_PORT") or 8080)
XUI_PORT = int(os.environ.get("XUI_PORT") or portal_config.get("XUI_PORT") or 2053)
VPN_PORT = int(os.environ.get("VPN_PORT") or portal_config.get("VPN_PORT") or 10000)

API_TOKEN = os.environ.get("XUI_API_TOKEN") or portal_config.get("XUI_API_TOKEN") or "hUNP2ShXYRwWigG7zvKFoAwC7edTVAAv9hBuh93FMyJdY0zt"
XUI_BASE = f"http://127.0.0.1:{XUI_PORT}"

def get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# Curated pool of 24 verified Cloudflare Anycast CIDR edge IPs across 6 major prefixes
CLOUDFLARE_EDGE_IP_POOL = [
    # 104.16.0.0/16
    "104.16.132.229", "104.16.133.229", "104.16.249.249", "104.16.85.20",
    # 104.17.0.0/16
    "104.17.209.9", "104.17.210.9", "104.17.175.22", "104.17.176.22",
    # 104.18.0.0/16
    "104.18.2.161", "104.18.3.161", "104.18.15.240", "104.18.43.147",
    # 104.21.0.0/16
    "104.21.48.84", "104.21.75.123", "104.21.19.140", "104.21.32.189",
    # 172.67.0.0/16
    "172.67.188.112", "172.67.135.150", "172.67.74.152", "172.67.199.234",
    # 162.159.0.0/16
    "162.159.135.42", "162.159.136.42", "162.159.36.1", "162.159.38.1"
]

# Cloudflare Anycast Clean IPs fallback
DEFAULT_CLEAN_IPS = [
    ("104.16.132.229", "Clean Anycast IP 1 (Verified Low-Latency)"),
    ("172.67.188.112", "Clean Anycast IP 2"),
    ("104.21.48.84", "Clean Anycast IP 3"),
    ("104.18.2.161", "Clean Anycast IP 4"),
    ("162.159.135.42", "Clean Anycast IP 5")
]
CLEAN_IPS = DEFAULT_CLEAN_IPS

# Major Iranian banking & domestic services for direct split-tunneling
DEFAULT_IRAN_DIRECT_DOMAINS = [
    "blubank.com", "sb24.ir", "bmi.ir", "mellatbank.ir", "tejaratbank.ir",
    "saderat.ir", "shaparak.ir", "snapp.ir", "digikala.com", "divar.ir",
    "torob.com", "arvancloud.ir", "cafebazaar.ir", "tapsi.ir", "rubika.ir"
]

# Active session tokens: token -> {"user_id": ..., "username": ..., "email": ..., "role": ..., "expires": ...}
active_sessions: Dict[str, Dict[str, Any]] = {}

# Quota alert tracking to prevent spamming
notified_quota_users = set()

# Tunnel state & watchdog tracking
tunnel_state = {
    "vpn_url": "",
    "vpn_host": "",
    "sub_url": "",
    "sub_host": "",
    "portal_url": "",
    "portal_host": "",
    "vpn_process": None,
    "sub_process": None,
    "xui_process": None,
    "last_sync": "Never",
    "last_watchdog_check": "Never",
    "watchdog_status": "Healthy & Self-Healing Active"
}

# ----------------- SQLite Database Management (portal.db) ----------------- #

def hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()

def get_db():
    conn = sqlite3.connect(PORTAL_DB, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_portal_db():
    """Initializes portal.db, creates tables, sets default invite code, and syncs admin."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            sub_id TEXT NOT NULL,
            uuid TEXT NOT NULL,
            limit_gb REAL DEFAULT 0,
            expiry_days INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    conn.commit()

    # Ensure invite_code exists in settings
    cur.execute("SELECT value FROM settings WHERE key = 'invite_code'")
    row = cur.fetchone()
    if not row:
        cur.execute("INSERT INTO settings (key, value) VALUES ('invite_code', 'IR-FAMILY')")
        conn.commit()

    # Load or initialize admin from admin_auth.json
    admin_auth = init_admin_auth()
    admin_user = admin_auth.get("username", "admin")
    admin_salt = admin_auth.get("salt", "")
    admin_hash = admin_auth.get("password_hash", "")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("SELECT id FROM users WHERE email = ? OR role = 'admin'", (admin_user,))
    admin_row = cur.fetchone()
    if not admin_row:
        cur.execute("""
            INSERT INTO users (name, email, password_hash, salt, role, sub_id, uuid, created_at)
            VALUES (?, ?, ?, ?, 'admin', 'admin-sub', ?, ?)
        """, ("Admin (Tohid)", admin_user, admin_hash, admin_salt, str(uuid.uuid4()), now_str))
        conn.commit()
    else:
        # Keep admin credentials in sync
        cur.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", (admin_hash, admin_salt, admin_row["id"]))
        conn.commit()

    conn.close()

def get_invite_code() -> str:
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'invite_code'")
        row = cur.fetchone()
        conn.close()
        if row and row["value"]:
            return row["value"]
    except Exception as e:
        print(f"[DB Error get_invite_code] {e}")
    return "IR-FAMILY"

def set_invite_code(code: str) -> bool:
    try:
        code_clean = code.strip()
        if not code_clean:
            return False
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('invite_code', ?)", (code_clean,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[DB Error set_invite_code] {e}")
        return False

def get_cf_optimizer_state() -> dict:
    state = {
        "auto_optimize": True,
        "active_edge_ip": "104.16.132.229",
        "latency_ms": 0.0,
        "last_scan_time": "Never",
        "top_5_ips": [ip for ip, _ in DEFAULT_CLEAN_IPS],
        "override_ip": ""
    }
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM settings WHERE key IN ('cf_auto_optimize', 'cf_active_edge_ip', 'cf_scan_latency_ms', 'cf_last_scan_time', 'cf_top_5_ips', 'cf_ip_override')")
        rows = cur.fetchall()
        conn.close()
        db_map = {row["key"]: row["value"] for row in rows}

        if "cf_auto_optimize" in db_map:
            state["auto_optimize"] = (db_map["cf_auto_optimize"] == "1")
        if "cf_active_edge_ip" in db_map and db_map["cf_active_edge_ip"]:
            state["active_edge_ip"] = db_map["cf_active_edge_ip"].strip()
        if "cf_scan_latency_ms" in db_map and db_map["cf_scan_latency_ms"]:
            try:
                state["latency_ms"] = float(db_map["cf_scan_latency_ms"])
            except ValueError:
                pass
        if "cf_last_scan_time" in db_map and db_map["cf_last_scan_time"]:
            state["last_scan_time"] = db_map["cf_last_scan_time"]
        if "cf_top_5_ips" in db_map and db_map["cf_top_5_ips"]:
            try:
                loaded = json.loads(db_map["cf_top_5_ips"])
                if isinstance(loaded, list) and len(loaded) > 0:
                    state["top_5_ips"] = loaded
            except Exception:
                pass
        if "cf_ip_override" in db_map:
            state["override_ip"] = db_map["cf_ip_override"].strip()
    except Exception as e:
        print(f"[DB Error get_cf_optimizer_state] {e}")

    return state

def save_cf_optimizer_state(data: dict) -> bool:
    try:
        conn = get_db()
        cur = conn.cursor()
        if "auto_optimize" in data:
            val = "1" if data["auto_optimize"] else "0"
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_auto_optimize', ?)", (val,))
        if "active_edge_ip" in data:
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_active_edge_ip', ?)", (data["active_edge_ip"].strip(),))
        if "latency_ms" in data:
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_scan_latency_ms', ?)", (str(data["latency_ms"]),))
        if "last_scan_time" in data:
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_last_scan_time', ?)", (data["last_scan_time"],))
        if "top_5_ips" in data:
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_top_5_ips', ?)", (json.dumps(data["top_5_ips"]),))
        if "override_ip" in data:
            cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_ip_override', ?)", (data["override_ip"].strip(),))
        conn.commit()
        conn.close()

        # Sync to config.json
        try:
            cfg = {}
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            if "auto_optimize" in data:
                cfg["CF_AUTO_OPTIMIZE"] = data["auto_optimize"]
            if "active_edge_ip" in data:
                cfg["CF_ACTIVE_EDGE_IP"] = data["active_edge_ip"]
            if "latency_ms" in data:
                cfg["CF_LATENCY_MS"] = data["latency_ms"]
            if "last_scan_time" in data:
                cfg["CF_LAST_SCAN_TIME"] = data["last_scan_time"]
            if "top_5_ips" in data:
                cfg["CF_TOP_5_IPS"] = data["top_5_ips"]
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass

        return True
    except Exception as e:
        print(f"[DB Error save_cf_optimizer_state] {e}")
        return False

def get_cf_ip_override() -> str:
    return get_cf_optimizer_state().get("override_ip", "")

def set_cf_ip_override(ip: str) -> bool:
    clean = ip.strip()
    return save_cf_optimizer_state({"override_ip": clean, "auto_optimize": False if clean else True})

def set_cf_auto_optimize(enabled: bool) -> bool:
    return save_cf_optimizer_state({"auto_optimize": enabled})

def test_single_cf_ip(ip: str, sni: str, timeout: float = 2.5) -> tuple[str, Optional[float]]:
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=sni or "trycloudflare.com"):
            latency = (time.monotonic() - t0) * 1000.0
            return ip, round(latency, 1)
    except Exception:
        return ip, None

def run_cloudflare_ip_scan() -> dict:
    sni = tunnel_state.get("vpn_host") or tunnel_state.get("portal_host") or "trycloudflare.com"
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(test_single_cf_ip, ip, sni) for ip in CLOUDFLARE_EDGE_IP_POOL]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    responsive = [(ip, lat) for ip, lat in results if lat is not None]
    responsive.sort(key=lambda x: x[1])
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not responsive:
        return {
            "success": False,
            "timestamp": now_str,
            "active_ip": DEFAULT_CLEAN_IPS[0][0],
            "latency_ms": 0.0,
            "top_5": [ip for ip, _ in DEFAULT_CLEAN_IPS]
        }

    top_5 = responsive[:5]
    best_ip, best_lat = top_5[0]
    top_5_ips = [ip for ip, _ in top_5]

    save_cf_optimizer_state({
        "active_edge_ip": best_ip,
        "latency_ms": best_lat,
        "last_scan_time": now_str,
        "top_5_ips": top_5_ips
    })

    return {
        "success": True,
        "timestamp": now_str,
        "active_ip": best_ip,
        "latency_ms": best_lat,
        "top_5": top_5_ips
    }

def get_active_clean_ips() -> List[tuple[str, str]]:
    state = get_cf_optimizer_state()
    auto_enabled = state.get("auto_optimize", True)
    override = state.get("override_ip", "")

    if not auto_enabled and override:
        res = [(override, f"Manual Override ({override})")]
        for ip, label in DEFAULT_CLEAN_IPS:
            if ip != override:
                res.append((ip, label))
        return res[:5]

    top_5 = state.get("top_5_ips", [])
    lat = state.get("latency_ms", 0.0)
    lat_str = f" ({lat}ms)" if lat > 0 else ""
    if top_5:
        primary = top_5[0]
        res = [(primary, f"Auto-Promoted Fastest IP{lat_str}")]
        for idx, ip in enumerate(top_5[1:], start=2):
            res.append((ip, f"Clean Anycast IP #{idx} ({ip})"))
        return res

    return DEFAULT_CLEAN_IPS

# ----------------- Admin Auth File Sync ----------------- #

def init_admin_auth() -> dict:
    os.makedirs(BASE_DIR, exist_ok=True)
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "username" in data and "password_hash" in data:
                    return data
        except Exception as e:
            print(f"[Auth Init Error] {e}")

    salt_hex = secrets.token_hex(16)
    initial_pwd = os.environ.get("PORTAL_ADMIN_PASS") or ("Admin-" + secrets.token_hex(4))
    user = os.environ.get("PORTAL_ADMIN_USER") or "admin"
    pwd_hash = hash_password(initial_pwd, salt_hex)

    auth_data = {
        "username": user,
        "salt": salt_hex,
        "password_hash": pwd_hash,
        "initial_password": initial_pwd,
        "is_custom": False,
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(auth_data, f, indent=2)

    return auth_data

def verify_credentials(username: str, password: str) -> bool:
    if not os.path.exists(AUTH_FILE):
        init_admin_auth()
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if username.strip() != data.get("username", "admin"):
            return False
        calc = hash_password(password, data.get("salt", ""))
        return secrets.compare_digest(calc, data.get("password_hash", ""))
    except Exception as e:
        print(f"[Auth Verify Error] {e}")
        return False

def update_admin_password(old_pwd: str, new_pwd: str) -> tuple[bool, str]:
    if not os.path.exists(AUTH_FILE):
        init_admin_auth()
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        calc = hash_password(old_pwd, data.get("salt", ""))
        if not secrets.compare_digest(calc, data.get("password_hash", "")) and not (data.get("initial_password") == old_pwd):
            return False, "Current password does not match"
        if len(new_pwd) < 6:
            return False, "New password must be at least 6 characters"

        new_salt = secrets.token_hex(16)
        data["salt"] = new_salt
        data["password_hash"] = hash_password(new_pwd, new_salt)
        data["initial_password"] = new_pwd
        data["is_custom"] = True
        data["updated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        # Sync with portal.db
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash = ?, salt = ? WHERE role = 'admin'", (data["password_hash"], new_salt))
        conn.commit()
        conn.close()

        return True, "Password updated successfully"
    except Exception as e:
        return False, f"Failed to update password: {e}"

def get_current_credentials_display() -> dict:
    if not os.path.exists(AUTH_FILE):
        init_admin_auth()
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "username": data.get("username", "admin"),
            "password": data.get("initial_password", "********"),
            "is_custom": data.get("is_custom", False)
        }
    except Exception:
        return {"username": "admin", "password": "********", "is_custom": False}

# Initialize DB on load
init_admin_auth()
init_portal_db()

# ----------------- User Authentication & Registration ----------------- #

def authenticate_user_or_admin(username_or_email: str, password: str) -> Optional[dict]:
    identifier = username_or_email.strip()
    pwd = password.strip()

    # 1. Check Admin auth
    if verify_credentials(identifier, pwd):
        admin_data = get_current_credentials_display()
        return {
            "id": 0,
            "name": "Admin (Tohid)",
            "username": admin_data.get("username", "admin"),
            "email": admin_data.get("username", "admin"),
            "role": "admin",
            "sub_id": "admin-sub",
            "uuid": "admin-uuid"
        }

    # 2. Check portal.db users
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE lower(email) = ? OR lower(name) = ?", (identifier.lower(), identifier.lower()))
        row = cur.fetchone()
        if row:
            calc = hash_password(pwd, row["salt"])
            if secrets.compare_digest(calc, row["password_hash"]):
                now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_str, row["id"]))
                conn.commit()
                user_dict = {
                    "id": row["id"],
                    "name": row["name"],
                    "username": row["email"],
                    "email": row["email"],
                    "role": row["role"],
                    "sub_id": row["sub_id"],
                    "uuid": row["uuid"]
                }
                conn.close()
                return user_dict
        conn.close()
    except Exception as e:
        print(f"[Auth DB Error] {e}")

    return None

def register_family_member(name: str, email: str, password: str, invite_code: str) -> tuple[bool, str, Optional[dict]]:
    name_clean = name.strip()
    email_clean = email.strip()
    pwd_clean = password.strip()
    invite_clean = invite_code.strip()

    if not name_clean:
        return False, "Please enter your name / لطفاً نام خود را وارد کنید", None
    if not email_clean:
        return False, "Please enter an email or username / لطفاً ایمیل یا نام کاربری را وارد کنید", None
    if len(pwd_clean) < 6:
        return False, "Password must be at least 6 characters / رمز عبور باید حداقل ۶ کاراکتر باشد", None

    current_code = get_invite_code()
    if invite_clean.upper() != current_code.upper():
        return False, f"Invalid family invite code. Please ask Tohid for the correct code / کد دعوت نادرست است. لطفاً کد معتبر را از توحید دریافت کنید", None

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE lower(email) = ?", (email_clean.lower(),))
    if cur.fetchone():
        conn.close()
        return False, "This email/username is already registered. Please sign in / این حساب قبلاً ثبت‌نام شده است. لطفاً وارد شوید", None

    # Check if client already exists in 3x-ui
    s, base_url = get_3xui_auth_session()
    ib = get_inbound_and_clients(session=s, base_url=base_url)
    existing_c = None
    if ib:
        raw_settings = ib.get("settings")
        if isinstance(raw_settings, str):
            try:
                raw_settings = json.loads(raw_settings)
            except Exception:
                raw_settings = {}
        if isinstance(raw_settings, dict):
            for c in raw_settings.get("clients", []):
                if c.get("email", "").lower() == email_clean.lower() or c.get("email", "").lower() == name_clean.lower():
                    existing_c = c
                    break

    if existing_c:
        client_uuid = existing_c.get("id")
        sub_id = existing_c.get("subId", email_clean)
        print(f"[Register] Linked with existing 3x-ui client for {email_clean}")
    else:
        # Provision fresh 3x-ui client
        client_uuid = str(uuid.uuid4())
        alphabet = string.ascii_lowercase + string.digits
        sub_id = "".join(secrets.choice(alphabet) for _ in range(16))

        inbound_id = ib.get("id", 1) if ib else 1
        client_payload = {
            "id": client_uuid,
            "flow": "",
            "email": email_clean,
            "limitIp": 0,
            "totalGB": 0, # Unlimited by default for family
            "expiryTime": 0,
            "enable": True,
            "tgId": 0,
            "subId": sub_id
        }
        modern_payload = {"client": client_payload, "inboundIds": [inbound_id]}
        legacy_payload = {"id": inbound_id, "settings": json.dumps({"clients": [client_payload]})}

        r = s.post(f"{base_url}/panel/api/clients/add", json=modern_payload, timeout=5)
        if r.status_code == 404:
            r = s.post(f"{base_url}/panel/api/inbounds/addClient", json=legacy_payload, timeout=5)
        if r.status_code == 404:
            r = s.post(f"{base_url}/panel/inbound/addClient", json=legacy_payload, timeout=5)

        if r.status_code != 200 or not r.json().get("success"):
            print(f"[3x-ui Provision Error] Status {r.status_code}: {r.text}")
            conn.close()
            return False, f"Failed to provision VPN engine client: {r.text}", None

    salt_hex = secrets.token_hex(16)
    pwd_hash = hash_password(pwd_clean, salt_hex)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        INSERT INTO users (name, email, password_hash, salt, role, sub_id, uuid, created_at, last_login)
        VALUES (?, ?, ?, ?, 'user', ?, ?, ?, ?)
    """, (name_clean, email_clean, pwd_hash, salt_hex, sub_id, client_uuid, now_str, now_str))
    conn.commit()
    user_id = cur.lastrowid
    conn.close()

    send_telegram_alert_async(
        f"🎉 <b>New Family Member Registered!</b>\n"
        f"Name: <b>{name_clean}</b>\n"
        f"Account: <code>{email_clean}</code>\n"
        f"VPN client provisioned and ready."
    )

    user_dict = {
        "id": user_id,
        "name": name_clean,
        "username": email_clean,
        "email": email_clean,
        "role": "user",
        "sub_id": sub_id,
        "uuid": client_uuid
    }
    return True, "Account created successfully", user_dict

# ----------------- Dynamic Iran Direct Domains ----------------- #

def load_direct_domains() -> List[str]:
    domains = list(DEFAULT_IRAN_DIRECT_DOMAINS)
    if os.path.exists(DOMAINS_FILE):
        try:
            with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if isinstance(saved, list):
                    for d in saved:
                        d_clean = d.strip().lower()
                        if d_clean and d_clean not in domains:
                            domains.append(d_clean)
        except Exception as e:
            print(f"[Direct Domains Load Error] {e}")
    return domains

def save_direct_domains(domain_list: List[str]):
    cleaned = []
    for d in domain_list:
        d_str = d.strip().lower()
        if d_str and d_str not in cleaned:
            cleaned.append(d_str)
    with open(DOMAINS_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=2)
    return cleaned

if not os.path.exists(DOMAINS_FILE):
    save_direct_domains(DEFAULT_IRAN_DIRECT_DOMAINS)

# ----------------- Telegram Bot Alerting ----------------- #

def load_telegram_config() -> dict:
    if os.path.exists(TELEGRAM_FILE):
        try:
            with open(TELEGRAM_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"enabled": False, "bot_token": "", "chat_id": ""}

def save_telegram_config(cfg: dict):
    with open(TELEGRAM_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

def send_telegram_alert_async(message: str):
    def _send():
        cfg = load_telegram_config()
        if not cfg.get("enabled"):
            return
        token = cfg.get("bot_token", "").strip()
        chat_id = cfg.get("chat_id", "").strip()
        if not token or not chat_id:
            return
        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            }
            requests.post(url, json=payload, timeout=6)
        except Exception as e:
            print(f"[Telegram Alert Error] {e}")

    threading.Thread(target=_send, daemon=True).start()

# ----------------- 3x-ui API Client & Base Path ----------------- #

def get_xui_base_path() -> str:
    env_path = os.environ.get("WEB_BASE_PATH") or os.environ.get("XUI_BASE_PATH")
    if env_path and env_path.strip():
        val = env_path.strip()
        if not val.startswith("/"):
            val = "/" + val
        return val.rstrip("/")
    try:
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT value FROM settings WHERE key='webBasePath'")
            row = cur.fetchone()
            conn.close()
            if row and row[0]:
                val = str(row[0]).strip()
                if val and val != "/":
                    if not val.startswith("/"):
                        val = "/" + val
                    return val.rstrip("/")
    except Exception as e:
        print(f"[3x-ui Path Error] {e}")
    return ""

def get_xui_base_url() -> str:
    base_path = get_xui_base_path()
    return f"http://127.0.0.1:2053{base_path}"

def get_3xui_auth_session() -> tuple[requests.Session, str]:
    base_url = get_xui_base_url()
    s = requests.Session()
    csrf_token = ""
    try:
        r_csrf = s.get(f"{base_url}/csrf-token", timeout=4)
        if r_csrf.status_code == 200:
            data = r_csrf.json()
            csrf_token = data.get("obj") or data.get("token") or ""
    except Exception as e:
        print(f"[3x-ui Auth CSRF Warning] {e}")

    username = os.environ.get("XUI_USER", "admin")
    password = os.environ.get("XUI_PASS", "admin")
    login_payload = {"username": username, "password": password}
    login_headers = {
        "Origin": "http://127.0.0.1:2053",
        "Referer": f"{base_url}/",
        "User-Agent": "HomeVPN-Portal/3.0"
    }
    if csrf_token:
        login_headers["X-CSRF-Token"] = csrf_token

    try:
        r_login = s.post(f"{base_url}/login", data=login_payload, headers=login_headers, timeout=4)
        if r_login.status_code != 200 or not r_login.json().get("success"):
            print(f"[3x-ui Auth Notice] status={r_login.status_code}, text={r_login.text}")
    except Exception as e:
        print(f"[3x-ui Auth Error] {e}")

    s.headers.update({
        "Authorization": f"Bearer {API_TOKEN}",
        "Origin": "http://127.0.0.1:2053",
        "Referer": f"{base_url}/",
        "Content-Type": "application/json"
    })
    if csrf_token:
        s.headers["X-CSRF-Token"] = csrf_token
    return s, base_url

def get_inbound_and_clients(session=None, base_url=None):
    if session is None or base_url is None:
        session, base_url = get_3xui_auth_session()
    try:
        r = session.get(f"{base_url}/panel/api/inbounds/list", timeout=4)
        if r.status_code == 200:
            inbounds = r.json().get("obj", [])
            for ib in inbounds:
                if ib.get("port") == 10000:
                    return ib
            if inbounds:
                return inbounds[0]
        else:
            print(f"[3x-ui API Error] list inbounds: Status {r.status_code}, Body {r.text}")
    except Exception as e:
        print(f"[3x-ui API Error] fetch error: {e}")
    return None

# ----------------- Xray Logging & Rotation ----------------- #

def ensure_xray_logging():
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        s, base_url = get_3xui_auth_session()
        r = s.get(f"{base_url}/panel/api/xray/getDefaultJsonConfig", timeout=4)
        if r.status_code == 200:
            template = r.json().get("obj", {})
            current_log = template.get("log", {})
            needs_update = (
                current_log.get("loglevel") != "info" or
                not current_log.get("dnsLog") or
                "access.log" not in current_log.get("access", "")
            )
            if needs_update:
                template["log"] = {
                    "access": "/var/log/x-ui/access.log",
                    "error": "/var/log/x-ui/error.log",
                    "loglevel": "info",
                    "dnsLog": True,
                    "maskAddress": ""
                }
                upd_payload = {"xraySetting": json.dumps(template, indent=2)}
                r_upd = s.post(f"{base_url}/panel/api/xray/update", data=upd_payload, timeout=5)
                if r_upd.status_code == 200 and r_upd.json().get("success"):
                    s.post(f"{base_url}/panel/api/server/restartXrayService", timeout=5)
                    print("[Xray Config] Successfully configured persistent logging with info loglevel and dnsLog.")
    except Exception as e:
        print(f"[Xray Log Config Error] {e}")

def rotate_logs_if_needed():
    try:
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        now_str = datetime.datetime.now().strftime("%Y%m%d_%H")
        for log_name in ["access.log", "error.log"]:
            src = os.path.join(LOG_DIR, log_name)
            if os.path.exists(src) and os.path.getsize(src) > 500 * 1024:
                dst = os.path.join(ARCHIVE_DIR, f"{log_name.split('.')[0]}_{now_str}.log")
                if not os.path.exists(dst):
                    shutil.copyfile(src, dst)
                    with open(src, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    with open(src, "w", encoding="utf-8") as f:
                        f.writelines(lines[-500:])

        cutoff = time.time() - (7 * 86400)
        for fname in os.listdir(ARCHIVE_DIR):
            fpath = os.path.join(ARCHIVE_DIR, fname)
            if os.path.isfile(fpath) and os.path.getmtime(fpath) < cutoff:
                os.remove(fpath)
    except Exception as e:
        print(f"[Log Rotation Error] {e}")

# ----------------- User Activity, Connection Status & Failing Domains Inspector ----------------- #

def get_all_users_activity() -> Dict[str, dict]:
    """Scans recent access.log lines and computes live online status (last 15m) and last seen timestamp."""
    activity = {}
    now = datetime.datetime.now()
    if os.path.exists(ACCESS_LOG):
        try:
            with open(ACCESS_LOG, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-8000:]
            for line in reversed(lines):
                line_str = line.strip()
                if not line_str:
                    continue
                m_email = re.search(r"email:\s*([^\s]+)", line_str)
                if not m_email:
                    continue
                email = m_email.group(1).strip()
                if email in activity:
                    continue

                m_time = re.match(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line_str)
                if m_time:
                    try:
                        dt = datetime.datetime.strptime(m_time.group(1), "%Y/%m/%d %H:%M:%S")
                        diff_sec = (now - dt).total_seconds()
                        is_online = (diff_sec >= -60 and diff_sec < 900)

                        if diff_sec < 60:
                            rel_en = "Just now"
                            rel_fa = "همین الان"
                        elif diff_sec < 3600:
                            mins = max(1, int(diff_sec // 60))
                            rel_en = f"{mins} mins ago"
                            rel_fa = f"{mins} دقیقه پیش"
                        elif diff_sec < 86400:
                            hrs = int(diff_sec // 3600)
                            rel_en = f"{hrs} hrs ago"
                            rel_fa = f"{hrs} ساعت پیش"
                        else:
                            days = int(diff_sec // 86400)
                            rel_en = f"{days} days ago"
                            rel_fa = f"{days} روز پیش"

                        activity[email] = {
                            "last_seen_str": m_time.group(1),
                            "last_seen_en": rel_en,
                            "last_seen_fa": rel_fa,
                            "is_online": is_online
                        }
                    except Exception:
                        pass
        except Exception as e:
            print(f"[Activity Parse Error] {e}")
    return activity

def get_failing_and_leaked_domains(limit: int = 100) -> List[dict]:
    """
    Parses access.log and error.log to identify:
    1. Iranian domains accidentally routing through Ireland proxy (leaks).
    2. Domains with connection failures, rejections, or timeouts.
    """
    direct_domains = set(d.lower() for d in load_direct_domains())
    records = {}

    if os.path.exists(ACCESS_LOG):
        try:
            with open(ACCESS_LOG, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-8000:]
            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue

                m_dst = re.search(r"(?:accepted|rejected)\s+(?:tcp:|udp:)?([a-zA-Z0-9_.-]+)(?::[0-9]+)?", line_str)
                if not m_dst:
                    continue
                raw_domain = m_dst.group(1).lower().strip()
                if raw_domain.startswith("127.") or raw_domain.startswith("192.168.") or raw_domain.startswith("10.") or "." not in raw_domain:
                    continue

                m_email = re.search(r"email:\s*([^\s]+)", line_str)
                user = m_email.group(1).strip() if m_email else "Client"

                m_route = re.search(r"\[([^\]]+)\]", line_str)
                route_str = m_route.group(1).lower() if m_route else ""
                is_proxy = "proxy" in route_str or "10000" in route_str

                is_iran_domain = raw_domain.endswith(".ir") or any(raw_domain == d or raw_domain.endswith("." + d) for d in direct_domains)
                is_rejected = "rejected" in line_str

                reason_code = None
                if is_iran_domain and is_proxy:
                    reason_code = "iran_leak"
                elif is_rejected:
                    reason_code = "rejected"

                if reason_code:
                    if raw_domain not in records:
                        records[raw_domain] = {
                            "domain": raw_domain,
                            "hits": 0,
                            "users": set(),
                            "reasons": set(),
                            "is_direct": raw_domain in direct_domains or any(raw_domain.endswith("." + d) for d in direct_domains)
                        }
                    records[raw_domain]["hits"] += 1
                    records[raw_domain]["users"].add(user)
                    records[raw_domain]["reasons"].add(reason_code)
        except Exception as e:
            print(f"[Failing Domains Access Parse Error] {e}")

    if os.path.exists(ERROR_LOG):
        try:
            with open(ERROR_LOG, "r", encoding="utf-8", errors="ignore") as f:
                err_lines = f.readlines()[-2000:]
            for eline in err_lines:
                if "[Warning]" not in eline and "[Error]" not in eline:
                    continue
                m_dom = re.search(r"(?:dial|handshake|connection).*(?:to|tcp:)\s*([a-zA-Z0-9_.-]+)(?::[0-9]+)?", eline, re.IGNORECASE)
                if m_dom:
                    dom = m_dom.group(1).lower().strip()
                    if len(dom) > 3 and "." in dom and not dom.startswith("127."):
                        if dom not in records:
                            records[dom] = {
                                "domain": dom,
                                "hits": 0,
                                "users": set(["Engine"]),
                                "reasons": set(["timeout"]),
                                "is_direct": dom in direct_domains or any(dom.endswith("." + d) for d in direct_domains)
                            }
                        records[dom]["hits"] += 1
                        records[dom]["reasons"].add("timeout")
        except Exception as e:
            print(f"[Failing Domains Error Parse Error] {e}")

    result = []
    for dom, item in records.items():
        reasons_list = []
        for r in item["reasons"]:
            if r == "iran_leak":
                reasons_list.append("Iranian Traffic Leaked to Ireland (نشتی ایران به خارج)")
            elif r == "rejected":
                reasons_list.append("Connection Rejected (مسدود یا رد شده)")
            elif r == "timeout":
                reasons_list.append("Connection Timeout (خطای تایم‌اوت شبکه)")
            else:
                reasons_list.append(r)

        result.append({
            "domain": dom,
            "hits": item["hits"],
            "users": list(item["users"])[:5],
            "reasons": reasons_list,
            "is_direct": item["is_direct"]
        })

    result.sort(key=lambda x: x["hits"], reverse=True)
    return result[:limit]

def get_diagnostics_logs(filter_user: Optional[str] = None, limit: int = 150) -> dict:
    entries = []
    direct_domains = load_direct_domains()
    leak_count = 0

    if os.path.exists(ACCESS_LOG):
        try:
            with open(ACCESS_LOG, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-limit * 3:]
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue

                m_email = re.search(r"email:\s*([^\s]+)", line)
                email = m_email.group(1) if m_email else "System"

                if filter_user and filter_user.lower() != "all" and email.lower() != filter_user.lower():
                    continue

                m_time = re.match(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
                timestamp = m_time.group(1) if m_time else datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")

                m_dst = re.search(r"(?:accepted|rejected)\s+(?:tcp:|udp:)?([a-zA-Z0-9_.-]+:[0-9]+)", line)
                dst = m_dst.group(1) if m_dst else "-"

                m_route = re.search(r"\[([^\]]+)\]", line)
                route_str = m_route.group(1) if m_route else "direct"
                route_taken = "Proxy (Laptop VPN)" if "proxy" in route_str or "10000" in route_str else "Direct (Iran/Local)"

                status = "Connected"
                if "rejected" in line:
                    status = "Rejected"

                is_iran_domain = (
                    ".ir:" in dst.lower() or
                    dst.lower().endswith(".ir") or
                    any(d in dst.lower() for d in direct_domains)
                )
                is_leak = False
                if is_iran_domain and "Proxy" in route_taken:
                    is_leak = True
                    leak_count += 1

                entries.append({
                    "timestamp": timestamp,
                    "email": email,
                    "destination": dst,
                    "route": route_taken,
                    "status": status,
                    "is_leak": is_leak,
                    "raw": line
                })
                if len(entries) >= limit:
                    break
        except Exception as e:
            print(f"[Access Log Parse Error] {e}")

    return {
        "entries": entries[:limit],
        "total_leaks": leak_count,
        "logging_active": os.path.exists(ACCESS_LOG),
        "log_path": ACCESS_LOG
    }

def generate_redacted_diagnostic_report() -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    vpn_host = tunnel_state.get("vpn_host", "Unknown")
    portal_host = tunnel_state.get("portal_host", "Unknown")

    diag = get_diagnostics_logs(limit=50)
    entries = diag.get("entries", [])
    leaks = diag.get("total_leaks", 0)

    lines = [
        "=== HOME VPN DIAGNOSTIC REPORT (REDACTED) ===",
        f"Generated: {now}",
        f"VPN Host: {vpn_host}",
        f"Portal Host: {portal_host}",
        "Anti-DPI: TLS Fragmentation Enabled (10-30 / 10-20), uTLS firefox fingerprint",
        "Iran Rules Loaded: geoip-ir.srs, geosite-ir.srs, geoip.dat, geosite.dat",
        f"Detected Iranian Leaks to Ireland: {leaks}",
        f"Watchdog Status: {tunnel_state.get('watchdog_status', 'Healthy')}",
        "",
        "--- RECENT CONNECTION EVENTS ---"
    ]
    for e in entries[:25]:
        leak_flag = " [!IR_LEAK_TO_IRELAND!]" if e.get("is_leak") else ""
        lines.append(f"[{e['timestamp']}] User: {e['email']} | Dest: {e['destination']} | Route: {e['route']} | Status: {e['status']}{leak_flag}")

    lines.append("")
    lines.append("=== END OF REPORT ===")
    return "\n".join(lines)

# ----------------- Tunnel & Process Management & 60-Second Watchdog ----------------- #

def is_port_open(port: int, host="127.0.0.1") -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False

def stream_reader(proc, name, is_vpn=True):
    for line in iter(proc.stderr.readline, ''):
        if not line:
            break
        m = re.search(r"https://([a-zA-Z0-9-]+\.trycloudflare\.com)", line)
        if m:
            host = m.group(1)
            url = f"https://{host}"
            if is_vpn:
                old_host = tunnel_state.get("vpn_host")
                tunnel_state["vpn_url"] = url
                tunnel_state["vpn_host"] = host
                print(f"[TUNNEL] VPN Tunnel Active: {url}")
                if old_host and old_host != host:
                    send_telegram_alert_async(f"🚨 <b>Home VPN Tunnel Updated!</b>\nNew VPN Server: <code>{host}</code>\nSubscription links auto-updated.")
            else:
                old_sub = tunnel_state.get("portal_host")
                tunnel_state["sub_url"] = url
                tunnel_state["sub_host"] = host
                tunnel_state["portal_url"] = url
                tunnel_state["portal_host"] = host
                print(f"[TUNNEL] Admin Portal & Sub Tunnel Active: {url}")
                if old_sub and old_sub != host:
                    send_telegram_alert_async(f"🌐 <b>Family VPN Portal Updated!</b>\nNew Remote URL: {url}")

            tunnel_state["last_sync"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            sync_3xui_with_tunnels()

def ensure_services():
    # 1. 3x-ui Engine check
    if not is_port_open(XUI_PORT):
        print(f"[Service] Starting 3x-ui engine on port {XUI_PORT}...")
        if os.path.exists(XUI_EXE):
            p = subprocess.Popen([XUI_EXE, "run"], cwd=XUI_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tunnel_state["xui_process"] = p
            time.sleep(2)

    # 2. Cloudflare VPN Tunnel (Port VPN_PORT)
    if os.path.exists(CLOUDFLARED_EXE):
        if not tunnel_state.get("vpn_process") or tunnel_state["vpn_process"].poll() is not None:
            print(f"[Service] Launching Cloudflare VPN Tunnel (port {VPN_PORT}) with HTTP/2 protocol...")
            p_vpn = subprocess.Popen(
                [CLOUDFLARED_EXE, "tunnel", "--protocol", "http2", "--no-autoupdate", "--url", f"http://127.0.0.1:{VPN_PORT}"],
                stderr=subprocess.PIPE, text=True, bufsize=1
            )
            tunnel_state["vpn_process"] = p_vpn
            threading.Thread(target=stream_reader, args=(p_vpn, "cf-vpn", True), daemon=True).start()

        # 3. Cloudflare Admin Portal & Subscription Tunnel (Port PORTAL_PORT)
        if not tunnel_state.get("sub_process") or tunnel_state["sub_process"].poll() is not None:
            print(f"[Service] Launching Cloudflare Admin Portal & Sub Tunnel (port {PORTAL_PORT}) with HTTP/2 protocol...")
            p_sub = subprocess.Popen(
                [CLOUDFLARED_EXE, "tunnel", "--protocol", "http2", "--no-autoupdate", "--url", f"http://127.0.0.1:{PORTAL_PORT}"],
                stderr=subprocess.PIPE, text=True, bufsize=1
            )
            tunnel_state["sub_process"] = p_sub
            threading.Thread(target=stream_reader, args=(p_sub, "cf-sub", False), daemon=True).start()

def sync_3xui_with_tunnels():
    vpn_host = tunnel_state.get("vpn_host")
    if not vpn_host:
        return
    try:
        s, base_url = get_3xui_auth_session()
        r = s.get(f"{base_url}/panel/api/inbounds/list", timeout=4)
        if r.status_code == 200:
            data = r.json()
            inbounds = data.get("obj", [])
            inbound = next((ib for ib in inbounds if ib.get("port") == VPN_PORT or ib.get("port") == 10000), None)
            if inbound:
                stream_settings = inbound.get("streamSettings")
                if isinstance(stream_settings, str):
                    stream_settings = json.loads(stream_settings)

                ws = stream_settings.get("wsSettings", {})
                current_headers = ws.get("headers", {})
                current_host = current_headers.get("Host", "")
                if current_host != vpn_host or inbound.get("shareAddr") != vpn_host:
                    ws["headers"] = {"Host": vpn_host}
                    stream_settings["wsSettings"] = ws
                    inbound["streamSettings"] = json.dumps(stream_settings)
                    inbound["shareAddr"] = vpn_host
                    if isinstance(inbound.get("settings"), dict):
                        inbound["settings"] = json.dumps(inbound["settings"])
                    if isinstance(inbound.get("sniffing"), dict):
                        inbound["sniffing"] = json.dumps(inbound["sniffing"])
                    r_upd = s.post(f"{base_url}/panel/api/inbounds/update/{inbound['id']}", json=inbound, timeout=4)
                    if r_upd.status_code == 200:
                        print(f"[3x-ui Sync] Inbound 10000 updated with Host={vpn_host}")
    except Exception as e:
        print(f"[3x-ui Sync Error] {e}")

def check_user_quotas_for_alerts():
    try:
        ib = get_inbound_and_clients()
        if not ib:
            return
        settings = ib.get("settings", {})
        if isinstance(settings, str):
            settings = json.loads(settings)
        raw_clients = settings.get("clients", [])
        client_stats = ib.get("clientStats") or []
        stats_map = {cs.get("email"): cs for cs in client_stats if cs.get("email")}

        for c in raw_clients:
            email = c.get("email", "")
            limit_bytes = c.get("totalGB", 0)
            if limit_bytes > 0:
                stat = stats_map.get(email, {})
                used = stat.get("up", 0) + stat.get("down", 0)
                pct = (used / limit_bytes) * 100
                if pct >= 80 and email not in notified_quota_users:
                    notified_quota_users.add(email)
                    used_gb = used / (1024 ** 3)
                    total_gb = limit_bytes / (1024 ** 3)
                    send_telegram_alert_async(
                        f"⚠️ <b>Quota Alert: {email}</b>\n"
                        f"Has used <b>{pct:.1f}%</b> of data limit ({used_gb:.2f} GB / {total_gb:.1f} GB)."
                    )
    except Exception as e:
        print(f"[Quota Check Error] {e}")

def watchdog_loop():
    while True:
        try:
            ensure_services()
            sync_3xui_with_tunnels()
            ensure_xray_logging()
            rotate_logs_if_needed()
            check_user_quotas_for_alerts()

            vpn_proc_alive = tunnel_state.get("vpn_process") and tunnel_state["vpn_process"].poll() is None
            sub_proc_alive = tunnel_state.get("sub_process") and tunnel_state["sub_process"].poll() is None

            tunnel_state["last_watchdog_check"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if vpn_proc_alive and sub_proc_alive:
                tunnel_state["watchdog_status"] = "Healthy & Self-Healing Active"
            else:
                tunnel_state["watchdog_status"] = "Recovering Disconnected Tunnels..."
        except Exception as e:
            print(f"[Watchdog Exception] {e}")
        time.sleep(60)

threading.Thread(target=watchdog_loop, daemon=True).start()

def cf_optimizer_scheduler():
    time.sleep(3)  # Initial grace period to allow tunnel and network to stabilize
    while True:
        try:
            state = get_cf_optimizer_state()
            if state.get("auto_optimize", True):
                print("[CF Optimizer] Running automated edge IP latency scan across 24 Anycast candidates...")
                scan_res = run_cloudflare_ip_scan()
                active_ips = get_active_clean_ips()
                print(f"[CF Optimizer] Scan complete. Primary Edge IP promoted: {active_ips[0][0]} ({scan_res.get('latency_ms', 0)} ms)")
        except Exception as e:
            print(f"[CF Optimizer Scheduler Exception] {e}")
        time.sleep(900)  # Repeat every 15 minutes

threading.Thread(target=cf_optimizer_scheduler, daemon=True).start()

# ----------------- Subscription Generation & Profile Builder ----------------- #

def format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"

def generate_qr_b64(text: str) -> str:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

def build_sub_link(sub_id: str, format_type: str = "smart") -> str:
    portal_host = tunnel_state.get("portal_host") or tunnel_state.get("sub_host")
    base = f"https://{portal_host}" if portal_host else "http://127.0.0.1:8080"
    if format_type == "json":
        return f"{base}/sub/json/{sub_id}"
    elif format_type == "vless":
        return f"{base}/sub/vless/{sub_id}"
    return f"{base}/sub/{sub_id}"

def build_resilient_vless_links(client_uuid: str, client_name: str, vpn_host: str) -> List[str]:
    if not vpn_host:
        vpn_host = "127.0.0.1"

    clean_ips = get_active_clean_ips()
    uris = []

    # 1. Clean Anycast Cloudflare IPs FIRST (First profile is the low-latency Anycast IP / Override)
    for idx, (ip, label) in enumerate(clean_ips):
        tag_icon = "%E2%9A%A1" if idx == 0 else "%F0%9F%9B%A1%EF%B8%8F"
        tag_desc = "Fastest%20Route" if idx == 0 else quote(label)
        uris.append(
            f"vless://{client_uuid}@{ip}:443?type=ws&security=tls&path=%2Fvpn-ws&host={vpn_host}&sni={vpn_host}&fp=firefox&alpn=http%2F1.1&mux=true&concurrency=8&xudpConcurrency=8&fragment=50-100%2C10-20#{client_name}%20{tag_icon}%20{tag_desc}%20({ip})"
        )

    # 2. Raw TryCloudflare DNS Hostname fallback
    uris.append(
        f"vless://{client_uuid}@{vpn_host}:443?type=ws&security=tls&path=%2Fvpn-ws&host={vpn_host}&sni={vpn_host}&fp=firefox&alpn=http%2F1.1&mux=true&concurrency=8&xudpConcurrency=8&fragment=50-100%2C10-20#{client_name}%20%F0%9F%8C%90%20Direct%20Cloudflare%20DNS"
    )

    # 3. HTTPUpgrade Line fallback
    uris.append(
        f"vless://{client_uuid}@{vpn_host}:443?type=httpupgrade&security=tls&path=%2Fvpn-ws&host={vpn_host}&sni={vpn_host}&fp=firefox&alpn=http%2F1.1&mux=true&concurrency=8&xudpConcurrency=8&fragment=50-100%2C10-20#{client_name}%20%F0%9F%9A%80%20HTTPUpgrade%20Line"
    )

    return uris

def build_resilient_singbox_profile(client_uuid: str, client_name: str, vpn_host: str, sub_host: str = "") -> dict:
    if not vpn_host:
        vpn_host = "127.0.0.1"

    direct_domains = load_direct_domains()
    geoip_url = "https://cdn.jsdelivr.net/gh/chocolate4u/Iran-sing-box-rules@rule-set/geoip-ir.srs"
    geosite_url = "https://cdn.jsdelivr.net/gh/chocolate4u/Iran-sing-box-rules@rule-set/geosite-ir.srs"

    clean_ips = get_active_clean_ips()

    def make_vless_outbound(tag: str, server_addr: str):
        return {
            "type": "vless",
            "tag": tag,
            "server": server_addr,
            "server_port": 443,
            "uuid": client_uuid,
            "tls": {
                "enabled": True,
                "server_name": vpn_host,
                "insecure": False,
                "alpn": ["http/1.1"],
                "utls": {
                    "enabled": True,
                    "fingerprint": "firefox"
                },
                "fragment": {
                    "enabled": True,
                    "length": "50-100",
                    "interval": "10-20"
                }
            },
            "transport": {
                "type": "ws",
                "path": "/vpn-ws",
                "headers": {
                    "Host": vpn_host
                }
            },
            "mux": {
                "enabled": True,
                "concurrency": 8,
                "xudpConcurrency": 8
            },
            "multiplex": {
                "enabled": True,
                "protocol": "h2mux",
                "max_connections": 8
            }
        }

    def make_vless_xhttp_outbound(tag: str, server_addr: str):
        return {
            "type": "vless",
            "tag": tag,
            "server": server_addr,
            "server_port": 443,
            "uuid": client_uuid,
            "tls": {
                "enabled": True,
                "server_name": vpn_host,
                "insecure": False,
                "alpn": ["http/1.1"],
                "utls": {
                    "enabled": True,
                    "fingerprint": "firefox"
                },
                "fragment": {
                    "enabled": True,
                    "length": "50-100",
                    "interval": "10-20"
                }
            },
            "transport": {
                "type": "httpupgrade",
                "path": "/vpn-ws",
                "host": vpn_host
            },
            "mux": {
                "enabled": True,
                "concurrency": 8,
                "xudpConcurrency": 8
            },
            "multiplex": {
                "enabled": True,
                "protocol": "h2mux",
                "max_connections": 8
            }
        }

    clean_outbounds = []
    outbound_tags = []
    for idx, (ip, label) in enumerate(clean_ips):
        tag = "proxy-fastest-clean" if idx == 0 else f"proxy-clean-{idx+1}"
        outbound_tags.append(tag)
        clean_outbounds.append(make_vless_outbound(tag, ip))

    outbound_tags.append("proxy-direct-dns")
    outbound_tags.append("proxy-httpupgrade")

    outbounds = [
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["auto-best"] + outbound_tags,
            "default": "auto-best"
        },
        {
            "type": "urltest",
            "tag": "auto-best",
            "outbounds": outbound_tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
            "tolerance": 50
        }
    ]
    outbounds.extend(clean_outbounds)
    outbounds.append(make_vless_outbound("proxy-direct-dns", vpn_host))
    outbounds.append(make_vless_xhttp_outbound("proxy-httpupgrade", vpn_host))
    outbounds.extend([
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
        {"type": "dns", "tag": "dns-out"}
    ])

    profile = {
        "version": 1,
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "https://1.1.1.1/dns-query",
                    "address_resolver": "dns-iran",
                    "strategy": "ipv4_only",
                    "detour": "proxy"
                },
                {
                    "tag": "dns-iran",
                    "address": "178.22.122.100",
                    "address_resolver": "dns-direct",
                    "strategy": "ipv4_only",
                    "detour": "direct"
                },
                {
                    "tag": "dns-direct",
                    "address": "local",
                    "detour": "direct"
                }
            ],
            "rules": [
                {"outbound": "any", "server": "dns-iran"},
                {"rule_set": ["geosite-ir"], "server": "dns-iran"},
                {"domain_suffix": [".ir"], "server": "dns-iran"},
                {"domain": direct_domains, "server": "dns-iran"}
            ],
            "final": "dns-remote",
            "independent_cache": True
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
                "sniff": True
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"ip_is_private": True, "outbound": "direct"},
                {"domain_suffix": [".ir"], "outbound": "direct"},
                {"domain": direct_domains, "outbound": "direct"},
                {"rule_set": ["geoip-ir", "geosite-ir"], "outbound": "direct"}
            ],
            "rule_set": [
                {
                    "tag": "geoip-ir",
                    "type": "remote",
                    "format": "binary",
                    "url": geoip_url,
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-ir",
                    "type": "remote",
                    "format": "binary",
                    "url": geosite_url,
                    "download_detour": "direct"
                }
            ],
            "final": "proxy",
            "auto_detect_interface": True
        }
    }
    return profile

def build_farsi_instructions(email: str, sub_url: str) -> str:
    return f"""🌟 راهنمای اتصال به اینترنت آزاد و پرسرعت برای {email}

🔗 لینک اشتراک هوشمند اختصاصی شما:
{sub_url}

📱 راهنمای راه‌اندازی بسیار آسان:

۱. اندروید (Android) - پیشنهادی Hiddify یا v2rayNG:
• برنامه Hiddify را از Google Play یا GitHub نصب کنید.
• دکمه «کپی لینک اشتراک» را در پورتال لمس کنید.
• برنامه را باز کرده و دکمه «+» یا «افزودن از کلیپ‌بورد» (Import) را بزنید.
• دکمه دایره‌ای اتصال را لمس کنید تا متصل شوید.

۲. آیفون و آیپد (iOS) - پیشنهادی Streisand یا V2Box:
• برنامه Streisand یا V2Box را از App Store دانلود کنید.
• در برنامه دکمه «+» و سپس گزینه «Add Subscription» را انتخاب کرده و لینک بالا را Paste کنید.
• اشتراک ذخیره شده را انتخاب و متصل شوید.

✨ امکانات و بهینه‌سازی ویژه (بدون نیاز به تنظیم دستی):
• دور زدن خودکار سایت‌ها و بانک‌های ایرانی (Iran Split-Tunneling): تمامی سایت‌های با پسوند .ir، برنامه‌های اسنپ، تپسی، دیجی‌کالا و اپ‌های بانکی به صورت مستقیم و بدون مصرف حجم فیلترشکن باز می‌شوند.
• قابلیت ضد اختلال (Anti-DPI): مجهز به تکه‌تکه‌سازی پکت‌های TLS (Fragmentation) و ۴ مسیر پشتیبان ابری Clean Anycast جهت دور زدن قطعی‌ها.
• نکته همراه بانک: در تنظیمات برنامه Hiddify یا v2rayNG در صورت تمایل می‌توانید گزینه Per-App Proxy را فعال کرده و اپلیکیشن‌های بانکی را تیک نزنید تا کلاً خارج از تونل کار کنند."""

# ----------------- Session & Middleware ----------------- #

def get_session(request: Request) -> Optional[dict]:
    token = request.cookies.get("vpn_session") or request.cookies.get("vpn_admin_session")
    if token and token in active_sessions:
        sess = active_sessions[token]
        if sess.get("expires", 0) > time.time():
            return sess
    return None

app = FastAPI(title=PORTAL_TITLE)

if not os.path.exists(RULES_DIR):
    os.makedirs(RULES_DIR, exist_ok=True)
app.mount("/rules", StaticFiles(directory=RULES_DIR), name="rules")

class UnifiedAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # 1. Public Paths
        if (
            path == "/" or
            path.startswith("/sub/") or
            path.startswith("/rules/") or
            path.startswith("/static/") or
            path in ["/login", "/register", "/favicon.ico", "/help"] or
            path.startswith("/api/public/") or
            path in ["/api/register", "/api/login", "/api/logout", "/api/status"]
        ):
            return await call_next(request)

        # 2. Session Check
        session = get_session(request)

        # 3. Admin-only paths
        if path == "/admin" or path.startswith("/admin/") or path.startswith("/api/admin/") or path.startswith("/api/clients"):
            if not session:
                if path.startswith("/api/"):
                    return JSONResponse(status_code=401, content={"detail": "Authentication required", "authenticated": False})
                return RedirectResponse("/?mode=login&need=admin", status_code=303)
            if session.get("role") != "admin":
                if path.startswith("/api/"):
                    return JSONResponse(status_code=403, content={"detail": "Admin access required"})
                return RedirectResponse("/dashboard", status_code=303)

        # 4. End-User Protected paths
        if path == "/dashboard" or path.startswith("/dashboard/") or path.startswith("/api/user/"):
            if not session:
                if path.startswith("/api/"):
                    return JSONResponse(status_code=401, content={"detail": "Authentication required", "authenticated": False})
                return RedirectResponse("/?mode=login", status_code=303)

        return await call_next(request)

app.add_middleware(UnifiedAuthMiddleware)

# ----------------- Public Subscription Endpoints ----------------- #

@app.get("/sub/json/{sub_id}", response_class=JSONResponse)
def get_singbox_subscription(sub_id: str):
    ib = get_inbound_and_clients()
    if not ib:
        raise HTTPException(status_code=503, detail="3x-ui server is offline")
    settings = ib.get("settings", {})
    if isinstance(settings, str):
        settings = json.loads(settings)
    clients = settings.get("clients", [])
    target = next((c for c in clients if c.get("subId") == sub_id or c.get("email") == sub_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Subscription not found")

    vpn_host = tunnel_state.get("vpn_host") or "127.0.0.1"
    sub_host = tunnel_state.get("portal_host") or "127.0.0.1"
    profile = build_resilient_singbox_profile(target.get("id"), target.get("email", "VPN"), vpn_host, sub_host)
    return JSONResponse(content=profile, headers={
        "Content-Disposition": f'attachment; filename="{target.get("email", "vpn")}-singbox.json"',
        "Profile-Title": f'{target.get("email", "Family-VPN")}',
        "Subscription-Userinfo": f"upload={target.get('up', 0)}; download={target.get('down', 0)}; total={target.get('totalGB', 0)}"
    })

@app.get("/sub/vless/{sub_id}", response_class=PlainTextResponse)
def get_vless_subscription(sub_id: str):
    ib = get_inbound_and_clients()
    if not ib:
        raise HTTPException(status_code=503, detail="3x-ui server is offline")
    settings = ib.get("settings", {})
    if isinstance(settings, str):
        settings = json.loads(settings)
    clients = settings.get("clients", [])
    target = next((c for c in clients if c.get("subId") == sub_id or c.get("email") == sub_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Subscription not found")

    vpn_host = tunnel_state.get("vpn_host") or "127.0.0.1"
    uris = build_resilient_vless_links(target.get("id"), target.get("email", "VPN"), vpn_host)
    joined = "\n".join(uris)
    b64 = base64.b64encode(joined.encode("utf-8")).decode("utf-8")
    return PlainTextResponse(b64, headers={"Profile-Title": target.get("email", "Family-VPN")})

@app.get("/sub/{sub_id}")
def get_smart_subscription(sub_id: str, request: Request, format: Optional[str] = None):
    ua = request.headers.get("user-agent", "").lower()
    accept = request.headers.get("accept", "").lower()

    if format == "json" or format == "singbox":
        return get_singbox_subscription(sub_id)
    elif format == "vless" or format == "base64":
        return get_vless_subscription(sub_id)

    if any(k in ua for k in ["hiddify", "sing-box", "foxray", "box"]) or "application/json" in accept:
        return get_singbox_subscription(sub_id)
    else:
        return get_vless_subscription(sub_id)

# ----------------- Auth API Endpoints (Login, Register, Logout) ----------------- #

class RegisterReq(BaseModel):
    name: str
    email: str
    password: str
    invite_code: str

@app.post("/api/register")
def api_register(req: RegisterReq, response: Response):
    success, msg, user = register_family_member(req.name, req.email, req.password, req.invite_code)
    if not success or not user:
        raise HTTPException(status_code=400, detail=msg)

    token = secrets.token_urlsafe(32)
    active_sessions[token] = {
        "user_id": user["id"],
        "name": user["name"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "sub_id": user["sub_id"],
        "uuid": user["uuid"],
        "expires": time.time() + (14 * 86400)
    }

    response.set_cookie(
        key="vpn_session",
        value=token,
        max_age=14 * 86400,
        httponly=True,
        samesite="lax",
        path="/"
    )
    return {"success": True, "message": msg, "redirect": "/dashboard"}

class LoginReq(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def api_login(request: Request, response: Response):
    content_type = request.headers.get("content-type", "")
    username = ""
    password = ""

    if "application/json" in content_type:
        try:
            body = await request.json()
            username = body.get("username", "")
            password = body.get("password", "")
        except Exception:
            pass
    else:
        try:
            form = await request.form()
            username = form.get("username", "")
            password = form.get("password", "")
        except Exception:
            pass

        if not username and not password:
            try:
                raw_bytes = await request.body()
                import urllib.parse
                qs = urllib.parse.parse_qs(raw_bytes.decode("utf-8", errors="ignore"))
                username = qs.get("username", [""])[0]
                password = qs.get("password", [""])[0]
            except Exception:
                pass

    user = authenticate_user_or_admin(str(username), str(password))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password / نام کاربری یا رمز عبور اشتباه است")

    token = secrets.token_urlsafe(32)
    active_sessions[token] = {
        "user_id": user["id"],
        "name": user["name"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "sub_id": user["sub_id"],
        "uuid": user["uuid"],
        "expires": time.time() + (14 * 86400)
    }

    redirect_url = "/admin" if user["role"] == "admin" else "/dashboard"
    res = JSONResponse({"success": True, "role": user["role"], "redirect": redirect_url})
    res.set_cookie(
        key="vpn_session",
        value=token,
        max_age=14 * 86400,
        httponly=True,
        samesite="lax",
        path="/"
    )
    if user["role"] == "admin":
        res.set_cookie(
            key="vpn_admin_session",
            value=token,
            max_age=14 * 86400,
            httponly=True,
            samesite="lax",
            path="/"
        )
    return res

@app.get("/logout")
@app.post("/logout")
@app.get("/api/logout")
@app.post("/api/logout")
def handle_logout(request: Request):
    token = request.cookies.get("vpn_session") or request.cookies.get("vpn_admin_session")
    if token and token in active_sessions:
        del active_sessions[token]
    resp = RedirectResponse("/?mode=login", status_code=303)
    resp.delete_cookie("vpn_session", path="/")
    resp.delete_cookie("vpn_admin_session", path="/")
    return resp

# ----------------- User API Endpoints ----------------- #

@app.get("/api/user/me")
def api_get_my_info(request: Request):
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    email = session.get("email", "")
    sub_id = session.get("sub_id", "")
    client_uuid = session.get("uuid", "")
    user_name = session.get("name", email)

    # Fetch fresh client stats from 3x-ui
    ib = get_inbound_and_clients()
    target_c = None
    up = 0
    down = 0
    limit_bytes = 0
    expiry_ms = 0
    status = "Active"

    if ib:
        settings = ib.get("settings", {})
        if isinstance(settings, str):
            try:
                settings = json.loads(settings)
            except Exception:
                settings = {}
        clients = settings.get("clients", [])
        target_c = next((c for c in clients if c.get("email", "").lower() == email.lower() or c.get("id") == client_uuid or c.get("subId") == sub_id), None)
        if target_c:
            client_uuid = target_c.get("id", client_uuid)
            sub_id = target_c.get("subId", sub_id)
            limit_bytes = target_c.get("totalGB", 0)
            expiry_ms = target_c.get("expiryTime", 0)

        client_stats = ib.get("clientStats") or []
        for cs in client_stats:
            if cs.get("email", "").lower() == email.lower() or cs.get("id") == client_uuid:
                up = cs.get("up", 0)
                down = cs.get("down", 0)
                break

    total_used = up + down
    now_ms = int(time.time() * 1000)
    if expiry_ms > 0 and now_ms > expiry_ms:
        status = "Expired"
    elif limit_bytes > 0 and total_used >= limit_bytes:
        status = "Over Quota"

    # Activity & online status
    activity_map = get_all_users_activity()
    user_act = activity_map.get(email, {})
    is_online = user_act.get("is_online", False)
    last_seen_en = user_act.get("last_seen_en", "Never")
    last_seen_fa = user_act.get("last_seen_fa", "تاکنون متصل نشده")

    smart_sub_link = build_sub_link(sub_id, "smart")
    json_sub_link = build_sub_link(sub_id, "json")
    vless_sub_link = build_sub_link(sub_id, "vless")
    qr_b64 = generate_qr_b64(json_sub_link)

    vpn_host = tunnel_state.get("vpn_host") or "127.0.0.1"
    vless_links = build_resilient_vless_links(client_uuid, email, vpn_host)

    expiry_str = "Never (دائمی)"
    if expiry_ms > 0:
        expiry_str = datetime.datetime.fromtimestamp(expiry_ms / 1000.0).strftime("%Y-%m-%d")

    return {
        "name": user_name,
        "email": email,
        "role": session.get("role", "user"),
        "sub_id": sub_id,
        "uuid": client_uuid,
        "is_online": is_online,
        "last_seen_en": last_seen_en,
        "last_seen_fa": last_seen_fa,
        "status": status,
        "up_bytes": up,
        "down_bytes": down,
        "total_used_bytes": total_used,
        "limit_bytes": limit_bytes,
        "up_str": format_bytes(up),
        "down_str": format_bytes(down),
        "total_used_str": format_bytes(total_used),
        "limit_str": format_bytes(limit_bytes) if limit_bytes > 0 else "Unlimited (نامحدود)",
        "percent_used": round((total_used / limit_bytes) * 100, 1) if limit_bytes > 0 else 0,
        "expiry_str": expiry_str,
        "smart_sub_link": smart_sub_link,
        "json_sub_link": json_sub_link,
        "vless_sub_link": vless_sub_link,
        "qr_b64": qr_b64,
        "vless_links": vless_links,
        "farsi_instructions": build_farsi_instructions(email, json_sub_link)
    }

@app.get("/api/status")
def get_api_status():
    admin_info = get_current_credentials_display()
    return {
        "xui_running": is_port_open(2053),
        "inbound_running": is_port_open(10000),
        "vpn_url": tunnel_state.get("vpn_url") or "Initializing...",
        "vpn_host": tunnel_state.get("vpn_host") or "Pending...",
        "sub_url": tunnel_state.get("sub_url") or "Initializing...",
        "sub_host": tunnel_state.get("sub_host") or "Pending...",
        "portal_url": tunnel_state.get("portal_url") or "Initializing...",
        "portal_host": tunnel_state.get("portal_host") or "Pending...",
        "local_portal_url": "http://127.0.0.1:8080",
        "engine_url": "http://127.0.0.1:2053",
        "admin_username": admin_info.get("username", "admin"),
        "admin_password": admin_info.get("password", "********"),
        "is_custom_password": admin_info.get("is_custom", False),
        "iran_rules_loaded": True,
        "watchdog_status": tunnel_state.get("watchdog_status", "Healthy"),
        "last_sync": tunnel_state.get("last_sync", "Never")
    }

# ----------------- Admin API Endpoints ----------------- #

@app.get("/api/admin/overview")
def api_admin_overview():
    invite_code = get_invite_code()
    portal_host = tunnel_state.get("portal_host") or tunnel_state.get("sub_host")
    shareable_invite_url = f"https://{portal_host}/?invite={invite_code}" if portal_host else f"http://127.0.0.1:{PORTAL_PORT}/?invite={invite_code}"
    lan_ip = get_lan_ip()
    lan_portal_url = f"http://{lan_ip}:{PORTAL_PORT}"
    local_portal_url = f"http://127.0.0.1:{PORTAL_PORT}"

    # Query all users & clients
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE role != 'admin'")
    total_db_users = cur.fetchone()[0]
    conn.close()

    ib = get_inbound_and_clients()
    total_up = 0
    total_down = 0
    client_count = 0
    if ib:
        stats = ib.get("clientStats") or []
        for s in stats:
            total_up += s.get("up", 0)
            total_down += s.get("down", 0)
        settings = ib.get("settings", {})
        if isinstance(settings, str):
            try:
                settings = json.loads(settings)
            except Exception:
                settings = {}
        client_count = len(settings.get("clients", []))

    total_users_count = max(total_db_users, client_count)

    # Online users
    activity_map = get_all_users_activity()
    online_count = sum(1 for v in activity_map.values() if v.get("is_online"))

    # Failing / leaked domains count
    failing_domains = get_failing_and_leaked_domains(limit=50)

    return {
        "total_users": total_users_count,
        "online_users": online_count,
        "total_bandwidth_bytes": total_up + total_down,
        "total_bandwidth_str": format_bytes(total_up + total_down),
        "total_up_str": format_bytes(total_up),
        "total_down_str": format_bytes(total_down),
        "invite_code": invite_code,
        "shareable_invite_url": shareable_invite_url,
        "lan_ip": lan_ip,
        "lan_portal_url": lan_portal_url,
        "local_portal_url": local_portal_url,
        "portal_port": PORTAL_PORT,
        "failing_domains_count": len(failing_domains),
        "watchdog_status": tunnel_state.get("watchdog_status", "Healthy"),
        "vpn_url": tunnel_state.get("vpn_url") or "Connecting...",
        "vpn_host": tunnel_state.get("vpn_host") or "Pending...",
        "portal_url": tunnel_state.get("portal_url") or "Connecting...",
        "portal_host": tunnel_state.get("portal_host") or "Pending...",
        "cf_auto_optimize": get_cf_optimizer_state().get("auto_optimize", True),
        "cf_ip_override": get_cf_ip_override(),
        "cf_active_edge_ip": get_active_clean_ips()[0][0],
        "cf_latency_ms": get_cf_optimizer_state().get("latency_ms", 0.0),
        "cf_last_scan_time": get_cf_optimizer_state().get("last_scan_time", "Never"),
        "cf_top_5": [ip for ip, _ in get_active_clean_ips()],
        "last_sync": tunnel_state.get("last_sync", "Never")
    }

@app.get("/api/admin/failing-domains")
def api_get_failing_domains():
    return {"domains": get_failing_and_leaked_domains(limit=100)}

@app.post("/api/admin/direct-domains/add")
def api_add_single_direct_domain(req: Dict[str, str]):
    domain = req.get("domain", "").strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")
    if ":" in domain:
        domain = domain.split(":")[0]
    domains = load_direct_domains()
    if domain not in domains:
        domains.append(domain)
        save_direct_domains(domains)
        send_telegram_alert_async(f"⚡ <b>Direct Bypass Domain Added:</b> <code>{domain}</code>\nSubscription profiles auto-updated.")
    return {"success": True, "domain": domain, "total_domains": len(domains)}

@app.get("/api/admin/invite-code")
def api_get_invite_code():
    return {"invite_code": get_invite_code()}

class InviteCodeReq(BaseModel):
    invite_code: str

@app.post("/api/admin/invite-code")
def api_set_invite_code(req: InviteCodeReq):
    success = set_invite_code(req.invite_code)
    if success:
        return {"success": True, "invite_code": req.invite_code.strip()}
    raise HTTPException(status_code=400, detail="Invalid invite code")

# ----------------- Automated Cloudflare Optimizer Endpoints ----------------- #

@app.get("/api/admin/cf-optimizer")
def api_get_cf_optimizer():
    state = get_cf_optimizer_state()
    active_ips = get_active_clean_ips()
    return {
        "auto_optimize": state.get("auto_optimize", True),
        "active_ip": active_ips[0][0],
        "latency_ms": state.get("latency_ms", 0.0),
        "last_scan_time": state.get("last_scan_time", "Never"),
        "top_5": [ip for ip, _ in active_ips],
        "override_ip": state.get("override_ip", ""),
        "pool_size": len(CLOUDFLARE_EDGE_IP_POOL)
    }

class CfOptimizerToggleReq(BaseModel):
    auto_optimize: Optional[bool] = None
    override_ip: Optional[str] = None

@app.post("/api/admin/cf-optimizer")
def api_set_cf_optimizer(req: CfOptimizerToggleReq):
    if req.auto_optimize is not None:
        set_cf_auto_optimize(req.auto_optimize)
    if req.override_ip is not None:
        set_cf_ip_override(req.override_ip)

    if req.auto_optimize:
        threading.Thread(target=run_cloudflare_ip_scan, daemon=True).start()

    return api_get_cf_optimizer()

@app.post("/api/admin/cf-optimizer/scan")
def api_scan_cf_optimizer():
    result = run_cloudflare_ip_scan()
    best_ip = result.get("active_ip")
    lat = result.get("latency_ms", 0.0)
    send_telegram_alert_async(
        f"⚡ <b>Fastest Cloudflare Edge IP Promoted!</b>\n"
        f"Promoted IP: <code>{best_ip}</code> ({lat} ms)\n"
        f"All family subscription links updated."
    )
    return api_get_cf_optimizer()

@app.get("/api/admin/cf-ip-override")
def api_get_cf_ip_override():
    state = get_cf_optimizer_state()
    active_ips = get_active_clean_ips()
    return {
        "ip": state.get("override_ip", ""),
        "default_ip": "104.16.132.229",
        "active_ip": active_ips[0][0]
    }

class CfIpOverrideReq(BaseModel):
    ip: str

@app.post("/api/admin/cf-ip-override")
def api_set_cf_ip_override(req: CfIpOverrideReq):
    clean_ip = req.ip.strip()
    set_cf_ip_override(clean_ip)
    if clean_ip:
        send_telegram_alert_async(
            f"⚡ <b>Fastest Cloudflare IP Updated!</b>\n"
            f"Active Anycast IP: <code>{clean_ip}</code>\n"
            f"All family subscription links auto-updated."
        )
    return {"success": True, "ip": clean_ip, "active_ip": get_active_clean_ips()[0][0]}

@app.get("/api/clients")
def list_clients():
    ib = get_inbound_and_clients()
    if not ib:
        return {"clients": [], "total_up": 0, "total_down": 0}

    settings = ib.get("settings", {})
    if isinstance(settings, str):
        settings = json.loads(settings)
    raw_clients = settings.get("clients", [])
    client_stats = ib.get("clientStats") or []
    stats_map = {cs.get("email"): cs for cs in client_stats if cs.get("email")}

    activity_map = get_all_users_activity()

    result = []
    total_up = 0
    total_down = 0
    now_ms = int(time.time() * 1000)
    vpn_host = tunnel_state.get("vpn_host") or "127.0.0.1"

    for c in raw_clients:
        email = c.get("email", "Unknown")
        stat = stats_map.get(email, {})
        up = stat.get("up", 0)
        down = stat.get("down", 0)
        total_used = up + down
        total_up += up
        total_down += down

        limit_bytes = c.get("totalGB", 0)
        expiry_ms = c.get("expiryTime", 0)

        status = "Active"
        if not c.get("enable", True):
            status = "Disabled"
        elif expiry_ms > 0 and now_ms > expiry_ms:
            status = "Expired"
        elif limit_bytes > 0 and total_used >= limit_bytes:
            status = "Over Quota"

        act = activity_map.get(email, {})
        is_online = act.get("is_online", False)
        last_seen_en = act.get("last_seen_en", "Never")
        last_seen_fa = act.get("last_seen_fa", "تاکنون")

        sub_id = c.get("subId", email)
        client_uuid = c.get("id")

        smart_sub_link = build_sub_link(sub_id, "smart")
        json_sub_link = build_sub_link(sub_id, "json")
        vless_sub_link = build_sub_link(sub_id, "vless")
        vless_links = build_resilient_vless_links(client_uuid, email, vpn_host)
        smart_qr_b64 = generate_qr_b64(json_sub_link)

        expiry_str = "Never"
        if expiry_ms > 0:
            expiry_str = datetime.datetime.fromtimestamp(expiry_ms / 1000.0).strftime("%Y-%m-%d")

        result.append({
            "id": client_uuid,
            "email": email,
            "subId": sub_id,
            "up": up,
            "down": down,
            "total_used": total_used,
            "limit_bytes": limit_bytes,
            "up_str": format_bytes(up),
            "down_str": format_bytes(down),
            "total_used_str": format_bytes(total_used),
            "limit_str": format_bytes(limit_bytes) if limit_bytes > 0 else "Unlimited",
            "percent_used": round((total_used / limit_bytes) * 100, 1) if limit_bytes > 0 else 0,
            "expiry_time": expiry_ms,
            "expiry_str": expiry_str,
            "status": status,
            "is_online": is_online,
            "last_seen_en": last_seen_en,
            "last_seen_fa": last_seen_fa,
            "enable": c.get("enable", True),
            "smart_sub_link": smart_sub_link,
            "json_sub_link": json_sub_link,
            "vless_sub_link": vless_sub_link,
            "vless_links": vless_links,
            "smart_qr_b64": smart_qr_b64,
            "farsi_instructions": build_farsi_instructions(email, json_sub_link)
        })

    return {
        "clients": result,
        "total_up": total_up,
        "total_down": total_down,
        "total_used_str": format_bytes(total_up + total_down),
        "total_up_str": format_bytes(total_up),
        "total_down_str": format_bytes(total_down)
    }

class ClientCreateReq(BaseModel):
    name: str
    limit_gb: float = 0.0
    expiry_days: int = 0

@app.post("/api/clients")
def create_client(req: ClientCreateReq):
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")

    client_uuid = str(uuid.uuid4())
    alphabet = string.ascii_lowercase + string.digits
    sub_id = "".join(secrets.choice(alphabet) for _ in range(16))

    total_bytes = int(req.limit_gb * 1024 * 1024 * 1024) if req.limit_gb > 0 else 0
    expiry_ms = int((time.time() + req.expiry_days * 86400) * 1000) if req.expiry_days > 0 else 0

    client_payload = {
        "id": client_uuid,
        "flow": "",
        "email": name,
        "limitIp": 0,
        "totalGB": total_bytes,
        "expiryTime": expiry_ms,
        "enable": True,
        "tgId": 0,
        "subId": sub_id
    }

    s, base_url = get_3xui_auth_session()
    inbound_id = 1
    ib = get_inbound_and_clients(session=s, base_url=base_url)
    if ib and ib.get("id"):
        inbound_id = ib.get("id")

    modern_payload = {"client": client_payload, "inboundIds": [inbound_id]}
    legacy_payload = {"id": inbound_id, "settings": json.dumps({"clients": [client_payload]})}

    r = s.post(f"{base_url}/panel/api/clients/add", json=modern_payload, timeout=5)
    if r.status_code == 404:
        r = s.post(f"{base_url}/panel/api/inbounds/addClient", json=legacy_payload, timeout=5)
    if r.status_code == 404:
        r = s.post(f"{base_url}/panel/inbound/addClient", json=legacy_payload, timeout=5)

    if r.status_code == 200 and r.json().get("success"):
        # Save to portal.db as well
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE email = ?", (name,))
            if not cur.fetchone():
                default_salt = secrets.token_hex(16)
                default_hash = hash_password("Family123!", default_salt)
                now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute("""
                    INSERT INTO users (name, email, password_hash, salt, role, sub_id, uuid, limit_gb, expiry_days, created_at)
                    VALUES (?, ?, ?, ?, 'user', ?, ?, ?, ?, ?)
                """, (name, name, default_hash, default_salt, sub_id, client_uuid, req.limit_gb, req.expiry_days, now_str))
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Create Client DB Error] {e}")

        return {"success": True, "uuid": client_uuid, "subId": sub_id, "email": name}
    else:
        raise HTTPException(status_code=500, detail=f"Failed to add client: {r.text}")

@app.delete("/api/clients/{client_id}")
def delete_client(client_id: str):
    s, base_url = get_3xui_auth_session()
    email_to_delete = client_id
    ib = get_inbound_and_clients(session=s, base_url=base_url)
    if ib:
        settings = ib.get("settings", {})
        if isinstance(settings, str):
            try:
                settings = json.loads(settings)
            except Exception:
                pass
        if isinstance(settings, dict):
            for c in settings.get("clients", []):
                if c.get("id") == client_id:
                    email_to_delete = c.get("email", client_id)
                    break

    r = s.post(f"{base_url}/panel/api/clients/del/{email_to_delete}", timeout=5)
    if r.status_code == 200 and r.json().get("success"):
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("DELETE FROM users WHERE email = ? OR uuid = ?", (email_to_delete, client_id))
            conn.commit()
            conn.close()
        except Exception:
            pass
        return {"success": True}

    if email_to_delete != client_id:
        r2 = s.post(f"{base_url}/panel/api/clients/del/{client_id}", timeout=5)
        if r2.status_code == 200 and r2.json().get("success"):
            return {"success": True}

    r_leg = s.post(f"{base_url}/panel/api/inbounds/delClient/{client_id}", timeout=5)
    if r_leg.status_code == 200:
        return {"success": True}

    raise HTTPException(status_code=500, detail=f"Failed to delete client: {r.text}")

@app.post("/api/clients/{email}/reset")
def reset_traffic(email: str):
    s, base_url = get_3xui_auth_session()
    r = s.post(f"{base_url}/panel/api/clients/resetTraffic/{email}", timeout=5)
    if r.status_code == 200 and r.json().get("success"):
        return {"success": True}
    r_leg = s.post(f"{base_url}/panel/api/inbounds/resetClientTraffic/{email}", timeout=5)
    if r_leg.status_code == 200:
        return {"success": True}
    return {"success": False, "error": r.text}

@app.get("/api/diagnostics/logs")
def api_diagnostics_logs(user: Optional[str] = None, limit: int = 100):
    return get_diagnostics_logs(filter_user=user, limit=limit)

@app.get("/api/diagnostics/report", response_class=PlainTextResponse)
def api_diagnostics_report():
    return PlainTextResponse(generate_redacted_diagnostic_report())

@app.get("/api/direct-domains")
def api_get_direct_domains():
    return {"domains": load_direct_domains()}

class DirectDomainsReq(BaseModel):
    domains: List[str]

@app.post("/api/direct-domains")
def api_save_direct_domains(req: DirectDomainsReq):
    updated = save_direct_domains(req.domains)
    return {"success": True, "domains": updated}

@app.get("/api/telegram")
def api_get_telegram():
    cfg = load_telegram_config()
    token = cfg.get("bot_token", "")
    masked = token[:6] + "..." + token[-4:] if len(token) > 10 else ("Set" if token else "Not Set")
    return {
        "enabled": cfg.get("enabled", False),
        "bot_token_masked": masked,
        "chat_id": cfg.get("chat_id", ""),
        "has_token": bool(token)
    }

class TelegramConfigReq(BaseModel):
    enabled: bool
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None

@app.post("/api/telegram")
def api_save_telegram(req: TelegramConfigReq):
    cfg = load_telegram_config()
    cfg["enabled"] = req.enabled
    if req.bot_token is not None and req.bot_token.strip():
        cfg["bot_token"] = req.bot_token.strip()
    if req.chat_id is not None and req.chat_id.strip():
        cfg["chat_id"] = req.chat_id.strip()
    save_telegram_config(cfg)
    return {"success": True}

@app.post("/api/telegram/test")
def api_test_telegram():
    cfg = load_telegram_config()
    token = cfg.get("bot_token", "").strip()
    chat_id = cfg.get("chat_id", "").strip()
    if not token or not chat_id:
        raise HTTPException(status_code=400, detail="Telegram Bot Token and Chat ID must be configured first.")
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": "✅ <b>Home VPN Alert Test Successful!</b>\nYour Telegram alerts are connected to your family VPN server.",
            "parse_mode": "HTML"
        }
        r = requests.post(url, json=payload, timeout=6)
        if r.status_code == 200:
            return {"success": True, "message": "Test alert sent to Telegram successfully"}
        return {"success": False, "detail": r.text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ChangePasswordReq(BaseModel):
    old_password: str
    new_password: str

@app.post("/api/admin/change-password")
def api_change_password(req: ChangePasswordReq):
    success, msg = update_admin_password(req.old_password, req.new_password)
    if success:
        return {"success": True, "message": msg}
    raise HTTPException(status_code=400, detail=msg)

@app.get("/api/admin/credentials")
def api_get_credentials():
    return get_current_credentials_display()

# ----------------- Public QR and Backup/Restore APIs ----------------- #

@app.get("/api/public/qr")
def api_get_public_qr(text: str):
    if not text:
        raise HTTPException(status_code=400, detail="Text required")
    b64 = generate_qr_b64(text)
    return Response(content=base64.b64decode(b64), media_type="image/png")

@app.get("/api/admin/backup")
def api_admin_backup():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, password_hash, salt, role, sub_id, uuid, limit_gb, expiry_days, created_at, last_login FROM users WHERE role != 'admin'")
    users_rows = cur.fetchall()
    users = []
    for r in users_rows:
        users.append({
            "name": r[1],
            "email": r[2],
            "password_hash": r[3],
            "salt": r[4],
            "role": r[5],
            "sub_id": r[6],
            "uuid": r[7],
            "limit_gb": r[8],
            "expiry_days": r[9],
            "created_at": r[10],
            "last_login": r[11]
        })
    cur.execute("SELECT key, value FROM settings")
    settings = dict(cur.fetchall())
    conn.close()

    direct_domains = load_direct_domains()
    tg_config = load_telegram_config()

    backup_data = {
        "format": "home-vpn-backup-v1",
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "invite_code": get_invite_code(),
        "settings": settings,
        "users": users,
        "custom_direct_domains": direct_domains,
        "telegram_config": tg_config,
        "ports": {
            "portal": PORTAL_PORT,
            "xui": XUI_PORT,
            "vpn": VPN_PORT
        }
    }
    content_str = json.dumps(backup_data, indent=2, ensure_ascii=False)
    filename = f"home-vpn-backup-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    return Response(
        content=content_str,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

class RestorePayload(BaseModel):
    backup_json: str

@app.post("/api/admin/restore")
def api_admin_restore(payload: RestorePayload):
    try:
        data = json.loads(payload.backup_json)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid backup file structure")

    restored_users = 0
    if "invite_code" in data:
        set_invite_code(str(data["invite_code"]))
    if "settings" in data and isinstance(data["settings"], dict):
        for k, v in data["settings"].items():
            if k == "invite_code":
                set_invite_code(str(v))

    if "custom_direct_domains" in data and isinstance(data["custom_direct_domains"], list):
        save_direct_domains(data["custom_direct_domains"])

    if "telegram_config" in data and isinstance(data["telegram_config"], dict):
        save_telegram_config(data["telegram_config"])

    users = data.get("users", [])
    if isinstance(users, list):
        conn = get_db()
        cur = conn.cursor()
        for u in users:
            if not u.get("email") or u.get("role") == "admin":
                continue
            cur.execute("SELECT id FROM users WHERE email = ?", (u["email"],))
            existing = cur.fetchone()
            if not existing:
                cur.execute('''
                    INSERT INTO users (name, email, password_hash, salt, role, sub_id, uuid, limit_gb, expiry_days, created_at, last_login)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    u.get("name", "User"),
                    u["email"],
                    u.get("password_hash", ""),
                    u.get("salt", ""),
                    u.get("role", "user"),
                    u.get("sub_id", secrets.token_hex(8)),
                    u.get("uuid", str(uuid.uuid4())),
                    u.get("limit_gb", 0),
                    u.get("expiry_days", 0),
                    u.get("created_at", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    u.get("last_login")
                ))
                restored_users += 1
                try:
                    expiry_ms = int((time.time() + (u.get("expiry_days", 30) or 30) * 86400) * 1000) if u.get("expiry_days") else 0
                    total_bytes = int((u.get("limit_gb", 0) or 0) * (1024 ** 3))
                    add_client_to_3xui(u.get("name", u["email"]), total_bytes, expiry_ms, client_uuid=u.get("uuid"), client_sub_id=u.get("sub_id"))
                except Exception as ex:
                    print(f"[Restore 3x-ui sync error] {ex}")
        conn.commit()
        conn.close()

    return {
        "success": True,
        "message": f"Backup restored successfully! {restored_users} users imported.",
        "restored_users": restored_users
    }

# ----------------- HTML Pages (Landing, Dashboard, Admin) ----------------- #

COMMON_HEADER_HTML = """
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          fontFamily: {
            sans: ['Vazirmatn', 'Inter', 'system-ui', 'sans-serif'],
          },
          colors: {
            brand: { 500: '#6366f1', 600: '#4f46e5', 700: '#4338ca' }
          }
        }
      }
    }
  </script>
  <style>
    body { font-family: 'Vazirmatn', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Tahoma, sans-serif; }
    .glass-card { background: rgba(15, 23, 42, 0.78); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); }
    [dir="rtl"] .ltr-only { direction: ltr; text-align: left; }
    [dir="ltr"] .rtl-only { direction: rtl; text-align: right; }
    html.light body { background-color: #f8fafc !important; color: #0f172a !important; }
    html.light .glass-card { background: rgba(255, 255, 255, 0.92) !important; border-color: #e2e8f0 !important; color: #0f172a !important; }
    html.light header { background-color: rgba(255, 255, 255, 0.85) !important; border-color: #e2e8f0 !important; }
    html.light .text-white { color: #0f172a !important; }
    html.light .text-slate-400 { color: #64748b !important; }
    html.light .text-slate-300 { color: #475569 !important; }
    html.light .text-slate-200 { color: #334155 !important; }
    html.light .bg-slate-900, html.light [class*="bg-slate-900"], html.light .bg-slate-950 { background-color: #ffffff !important; }
    html.light .bg-slate-800, html.light [class*="bg-slate-800"] { background-color: #f1f5f9 !important; border-color: #cbd5e1 !important; color: #1e293b !important; }
    html.light .border-slate-800, html.light [class*="border-slate-800"], html.light .border-slate-700 { border-color: #e2e8f0 !important; }
  </style>
  <script>
    function initTheme() {
      const saved = localStorage.getItem('portal_theme') || 'dark';
      if (saved === 'light') {
        document.documentElement.classList.remove('dark');
        document.documentElement.classList.add('light');
      } else {
        document.documentElement.classList.remove('light');
        document.documentElement.classList.add('dark');
      }
    }
    function toggleTheme() {
      const isLight = document.documentElement.classList.contains('light');
      if (isLight) {
        document.documentElement.classList.remove('light');
        document.documentElement.classList.add('dark');
        localStorage.setItem('portal_theme', 'dark');
      } else {
        document.documentElement.classList.remove('dark');
        document.documentElement.classList.add('light');
        localStorage.setItem('portal_theme', 'light');
      }
    }
    initTheme();
  </script>
"""

# ----------------- 1. LANDING & REGISTRATION PAGE (BILINGUAL) ----------------- #

LANDING_PAGE_HTML = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>فیلترشکن اختصاصی خانواده | Home VPN Platform</title>
  {COMMON_HEADER_HTML}
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen selection:bg-indigo-500 selection:text-white flex flex-col justify-between">
  <!-- Top Bar -->
  <header class="border-b border-slate-800/80 bg-slate-900/60 sticky top-0 z-40 backdrop-blur-md">
    <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center space-x-3 space-x-reverse">
        <div class="p-2.5 rounded-2xl bg-gradient-to-tr from-indigo-600 via-indigo-500 to-cyan-400 text-white shadow-lg shadow-indigo-500/25">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
        </div>
        <div>
          <h1 class="font-extrabold text-base tracking-tight text-white flex items-center gap-2">
            <span id="txtLogoTitle">سامانه فیلترشکن خانواده</span>
            <span class="px-2 py-0.5 text-[10px] rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">v3.0</span>
          </h1>
          <p id="txtLogoSub" class="text-xs text-slate-400">سریع، امن و مجهز به سیستم تفکیک ترافیک ایران</p>
        </div>
      </div>

      <div class="flex items-center gap-3">
        <!-- Help & Guide Link -->
        <a href="/help" class="px-3 py-1.5 rounded-xl bg-slate-800/90 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>
          <span>راهنما / Help</span>
        </a>

        <!-- Theme Toggle -->
        <button onclick="toggleTheme()" class="px-2.5 py-1.5 rounded-xl bg-slate-800/90 hover:bg-slate-700 border border-slate-700 text-slate-200 transition" title="Toggle Theme">
          <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
        </button>

        <!-- Language Switcher -->
        <button onclick="toggleLang()" class="px-3.5 py-1.5 rounded-xl bg-slate-800/90 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition flex items-center gap-2 shadow-sm">
          <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"/></svg>
          <span id="langSwitchLabel">English</span>
        </button>

        <!-- Admin Login Link -->
        <a href="#authCard" onclick="switchAuthTab('login')" class="hidden sm:inline-flex px-3.5 py-1.5 rounded-xl bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 text-xs font-semibold transition items-center gap-1.5">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
          <span id="txtAdminBtn">ورود مدیر</span>
        </a>
      </div>
    </div>
  </header>

  <!-- Hero Section -->
  <main class="max-w-6xl mx-auto px-4 py-8 lg:py-12 flex-1 w-full grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
    
    <!-- Left / Content (7 Cols) -->
    <div class="lg:col-span-7 space-y-6">
      <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-indigo-950/80 border border-indigo-800/80 text-xs font-medium text-indigo-300 shadow-inner">
        <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
        <span id="txtBadge">سرور اختصاصی اروپا | بدون قطعی و کاملاً رایگان</span>
      </div>

      <h2 id="txtHeroTitle" class="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-white leading-tight">
        اینترنت آزاد، امن و پرسرعت برای <span class="bg-gradient-to-r from-indigo-400 via-purple-300 to-cyan-400 bg-clip-text text-transparent">تمام اعضای خانواده</span>
      </h2>

      <p id="txtHeroDesc" class="text-sm sm:text-base text-slate-300 leading-relaxed max-w-xl">
        یک اتصال پایدار و مطمئن مجهز به تفکیک خودکار سایت‌ها و بانک‌های ایرانی (Iran Split-Tunneling) و فناوری ضد اختلال TLS Fragmentation تا بدون دردسر و بدون مصرف بی‌رویه حجم، به دنیای آزاد وصل شوید.
      </p>

      <!-- Feature Badges Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 max-w-xl">
        <div class="p-3.5 rounded-2xl bg-slate-900/80 border border-slate-800 flex items-start gap-3">
          <div class="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
          </div>
          <div>
            <h4 id="feat1Title" class="font-bold text-xs text-white">تفکیک خودکار ترافیک ایران</h4>
            <p id="feat1Desc" class="text-[11px] text-slate-400 mt-0.5">بانک‌ها، اسنپ، دیجی‌کالا و سایت‌های .ir مستقیم و بدون مصرف حجم باز می‌شوند.</p>
          </div>
        </div>

        <div class="p-3.5 rounded-2xl bg-slate-900/80 border border-slate-800 flex items-start gap-3">
          <div class="p-2 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shrink-0">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
          </div>
          <div>
            <h4 id="feat2Title" class="font-bold text-xs text-white">فناوری ضد فیلترینگ Anti-DPI</h4>
            <p id="feat2Desc" class="text-[11px] text-slate-400 mt-0.5">تکه‌تکه‌سازی پکت‌های TLS برای عبور از شدیدترین محدودیت‌های اینترنت.</p>
          </div>
        </div>

        <div class="p-3.5 rounded-2xl bg-slate-900/80 border border-slate-800 flex items-start gap-3">
          <div class="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shrink-0">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064"/></svg>
          </div>
          <div>
            <h4 id="feat3Title" class="font-bold text-xs text-white">۴ مسیر پشتیبان ابری</h4>
            <p id="feat3Desc" class="text-[11px] text-slate-400 mt-0.5">سوییچ خودکار روی Clean Anycast IP کلودفلر در صورت قطعی هر سرور.</p>
          </div>
        </div>

        <div class="p-3.5 rounded-2xl bg-slate-900/80 border border-slate-800 flex items-start gap-3">
          <div class="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20 shrink-0">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
          </div>
          <div>
            <h4 id="feat4Title" class="font-bold text-xs text-white">راه‌اندازی با یک کلیک</h4>
            <p id="feat4Desc" class="text-[11px] text-slate-400 mt-0.5">سازگار با اندروید (Hiddify, v2rayNG) و آیفون (Streisand, V2Box).</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Right / Interactive Form Card (5 Cols) -->
    <div id="authCard" class="lg:col-span-5">
      <div class="glass-card p-6 sm:p-8 rounded-3xl border border-slate-800 shadow-2xl relative overflow-hidden">
        
        <!-- Tab Switcher (Register vs Login) -->
        <div class="grid grid-cols-2 p-1 bg-slate-950/80 rounded-2xl border border-slate-800 mb-6">
          <button id="tabBtnRegister" onclick="switchAuthTab('register')" class="py-2.5 text-xs font-bold rounded-xl transition bg-indigo-600 text-white shadow-md">
            ثبت‌نام با کد دعوت
          </button>
          <button id="tabBtnLogin" onclick="switchAuthTab('login')" class="py-2.5 text-xs font-bold rounded-xl transition text-slate-400 hover:text-white">
            ورود به حساب
          </button>
        </div>

        <!-- Alert Box -->
        <div id="authAlert" class="hidden p-3.5 mb-5 text-xs rounded-xl border"></div>

        <!-- 1. REGISTRATION FORM -->
        <form id="formRegister" onsubmit="handleRegister(event)" class="space-y-4">
          <div>
            <label id="lblRegName" class="block text-xs font-semibold text-slate-300 mb-1">نام یا نام مستعار شما</label>
            <input type="text" id="regName" required placeholder="مثال: جواد، علی، سارا" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500 transition">
          </div>

          <div>
            <label id="lblRegEmail" class="block text-xs font-semibold text-slate-300 mb-1">ایمیل یا نام کاربری</label>
            <input type="text" id="regEmail" required placeholder="مثال: javad یا javad@gmail.com" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500 transition ltr-only">
          </div>

          <div>
            <label id="lblRegPassword" class="block text-xs font-semibold text-slate-300 mb-1">رمز عبور دلخواه (حداقل ۶ کاراکتر)</label>
            <input type="password" id="regPassword" required minlength="6" placeholder="••••••••" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500 transition ltr-only">
          </div>

          <div>
            <div class="flex items-center justify-between mb-1">
              <label id="lblRegInvite" class="block text-xs font-semibold text-slate-300">کد دعوت خانواده (Family Invite Code)</label>
              <span class="text-[10px] text-indigo-400 font-mono">الزامی</span>
            </div>
            <input type="text" id="regInvite" required placeholder="کد دعوت را از توحید بگیرید" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-indigo-700/60 text-sm text-indigo-200 font-mono focus:outline-none focus:border-indigo-400 transition ltr-only">
            <p id="lblRegInviteHint" class="text-[11px] text-slate-400 mt-1">جهت جلوگیری از عضویت غریبه‌ها، عضویت تنها با کد دعوت خانواده امکان‌پذیر است.</p>
          </div>

          <button type="submit" id="btnSubmitRegister" class="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white font-bold text-sm shadow-lg shadow-indigo-600/30 transition flex items-center justify-center gap-2">
            <span>ثبت‌نام و دریافت فیلترشکن</span>
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
          </button>
        </form>

        <!-- 2. LOGIN FORM -->
        <form id="formLogin" onsubmit="handleLogin(event)" class="space-y-4 hidden">
          <div>
            <label id="lblLoginUser" class="block text-xs font-semibold text-slate-300 mb-1">ایمیل یا نام کاربری</label>
            <input type="text" id="loginUsername" required placeholder="ایمیل شما یا نام کاربری مدیر" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500 transition ltr-only">
          </div>

          <div>
            <label id="lblLoginPwd" class="block text-xs font-semibold text-slate-300 mb-1">رمز عبور</label>
            <input type="password" id="loginPassword" required placeholder="••••••••" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500 transition ltr-only">
          </div>

          <button type="submit" id="btnSubmitLogin" class="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white font-bold text-sm shadow-lg shadow-indigo-600/30 transition flex items-center justify-center gap-2">
            <span>ورود به حساب کاربری</span>
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/></svg>
          </button>

          <div class="text-center pt-2">
            <span id="txtLoginHint" class="text-xs text-slate-400">مدیر سیستم نیز می‌تواند مستقیماً با اطلاعات ادمین وارد شود.</span>
          </div>
        </form>

      </div>
    </div>

  </main>

  <!-- Footer -->
  <footer class="border-t border-slate-800/80 bg-slate-900/40 py-4 text-center text-xs text-slate-400">
    <div class="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
      <span id="txtFooter">سامانه فیلترشکن خانواده • میزبانی اختصاصی در اروپا</span>
      <span class="text-slate-400 font-mono text-[11px]">TLS Packet Fragmentation & Split-Tunneling Active</span>
    </div>
  </footer>

  <script>
    // Bilingual Dictionary
    const i18n = {{
      fa: {{
        docTitle: 'فیلترشکن اختصاصی خانواده | Home VPN Platform',
        logoTitle: 'سامانه فیلترشکن خانواده',
        logoSub: 'سریع، امن و مجهز به سیستم تفکیک ترافیک ایران',
        langSwitch: 'English',
        adminBtn: 'ورود مدیر',
        badge: 'سرور اختصاصی اروپا | بدون قطعی و کاملاً رایگان',
        heroTitle: 'اینترنت آزاد، امن و پرسرعت برای <span class="bg-gradient-to-r from-indigo-400 via-purple-300 to-cyan-400 bg-clip-text text-transparent">تمام اعضای خانواده</span>',
        heroDesc: 'یک اتصال پایدار و مطمئن مجهز به تفکیک خودکار سایت‌ها و بانک‌های ایرانی (Iran Split-Tunneling) و فناوری ضد اختلال TLS Fragmentation تا بدون دردسر و بدون مصرف بی‌رویه حجم، به دنیای آزاد وصل شوید.',
        feat1Title: 'تفکیک خودکار ترافیک ایران',
        feat1Desc: 'بانک‌ها، اسنپ، دیجی‌کالا و سایت‌های .ir مستقیم و بدون مصرف حجم باز می‌شوند.',
        feat2Title: 'فناوری ضد فیلترینگ Anti-DPI',
        feat2Desc: 'تکه‌تکه‌سازی پکت‌های TLS برای عبور از شدیدترین محدودیت‌های اینترنت.',
        feat3Title: '۴ مسیر پشتیبان ابری',
        feat3Desc: 'سوییچ خودکار روی Clean Anycast IP کلودفلر در صورت قطعی هر سرور.',
        feat4Title: 'راه‌اندازی با یک کلیک',
        feat4Desc: 'سازگار با اندروید (Hiddify, v2rayNG) و آیفون (Streisand, V2Box).',
        tabRegister: 'ثبت‌نام با کد دعوت',
        tabLogin: 'ورود به حساب',
        lblRegName: 'نام یا نام مستعار شما',
        phRegName: 'مثال: جواد، علی، سارا',
        lblRegEmail: 'ایمیل یا نام کاربری',
        phRegEmail: 'مثال: javad یا javad@gmail.com',
        lblRegPassword: 'رمز عبور دلخواه (حداقل ۶ کاراکتر)',
        lblRegInvite: 'کد دعوت خانواده (Family Invite Code)',
        phRegInvite: 'کد دعوت را از توحید بگیرید',
        lblRegInviteHint: 'جهت جلوگیری از عضویت غریبه‌ها، عضویت تنها با کد دعوت خانواده امکان‌پذیر است.',
        btnRegister: 'ثبت‌نام و دریافت فیلترشکن',
        lblLoginUser: 'ایمیل یا نام کاربری',
        phLoginUser: 'ایمیل شما یا نام کاربری مدیر',
        lblLoginPwd: 'رمز عبور',
        btnLogin: 'ورود به حساب کاربری',
        loginHint: 'مدیر سیستم نیز می‌تواند مستقیماً با اطلاعات ادمین وارد شود.',
        footer: 'سامانه فیلترشکن خانواده • میزبانی اختصاصی در اروپا'
      }},
      en: {{
        docTitle: 'Family VPN Platform | High-Speed & Secure',
        logoTitle: 'Home VPN Platform',
        logoSub: 'Fast, secure with automatic Iran split-tunneling',
        langSwitch: 'فارسی',
        adminBtn: 'Admin Login',
        badge: 'Dedicated European Server | High Availability & Free',
        heroTitle: 'Fast, Secure & Private Internet for <span class="bg-gradient-to-r from-indigo-400 via-purple-300 to-cyan-400 bg-clip-text text-transparent">All Family Members</span>',
        heroDesc: 'A resilient private VPN featuring automatic split-tunneling for Iranian banking/domestic services and Anti-DPI TLS packet fragmentation to browse freely without restrictions.',
        feat1Title: 'Automatic Iran Split-Tunneling',
        feat1Desc: 'Iranian banks, Snapp, Digikala and .ir sites route directly without using VPN data.',
        feat2Title: 'Anti-DPI TLS Fragmentation',
        feat2Desc: 'Packet fragmentation bypasses aggressive censorship and firewall throttling.',
        feat3Title: '4-Line Anycast Fallback',
        feat3Desc: 'Clean Cloudflare Anycast edge IPs guarantee continuous failover connectivity.',
        feat4Title: 'One-Tap Setup in Apps',
        feat4Desc: 'Seamless setup in Hiddify / v2rayNG (Android) & Streisand / V2Box (iOS).',
        tabRegister: 'Register with Invite Code',
        tabLogin: 'Sign In to Account',
        lblRegName: 'Your Name or Nickname',
        phRegName: 'e.g. Javad, Sarah, Ali',
        lblRegEmail: 'Email or Username',
        phRegEmail: 'e.g. javad or javad@gmail.com',
        lblRegPassword: 'Password (min 6 characters)',
        lblRegInvite: 'Family Invite Code',
        phRegInvite: 'Ask Tohid for your invite code',
        lblRegInviteHint: 'To keep this service private for family, registration requires an invite code.',
        btnRegister: 'Register & Get VPN',
        lblLoginUser: 'Email or Username',
        phLoginUser: 'Your email or admin username',
        lblLoginPwd: 'Password',
        btnLogin: 'Sign In to Account',
        loginHint: 'Administrators can also log in directly using admin credentials.',
        footer: 'Home VPN Platform • Dedicated European Gateway'
      }}
    }};

    let currentLang = localStorage.getItem('vpn_lang') || 'fa';

    function setLanguage(lang) {{
      currentLang = lang;
      localStorage.setItem('vpn_lang', lang);
      const isRtl = (lang === 'fa');

      document.documentElement.setAttribute('lang', lang);
      document.documentElement.setAttribute('dir', isRtl ? 'rtl' : 'ltr');

      const dict = i18n[lang];
      document.title = dict.docTitle;
      document.getElementById('txtLogoTitle').textContent = dict.logoTitle;
      document.getElementById('txtLogoSub').textContent = dict.logoSub;
      document.getElementById('langSwitchLabel').textContent = dict.langSwitch;
      document.getElementById('txtAdminBtn').textContent = dict.adminBtn;
      document.getElementById('txtBadge').textContent = dict.badge;
      document.getElementById('txtHeroTitle').innerHTML = dict.heroTitle;
      document.getElementById('txtHeroDesc').textContent = dict.heroDesc;

      document.getElementById('feat1Title').textContent = dict.feat1Title;
      document.getElementById('feat1Desc').textContent = dict.feat1Desc;
      document.getElementById('feat2Title').textContent = dict.feat2Title;
      document.getElementById('feat2Desc').textContent = dict.feat2Desc;
      document.getElementById('feat3Title').textContent = dict.feat3Title;
      document.getElementById('feat3Desc').textContent = dict.feat3Desc;
      document.getElementById('feat4Title').textContent = dict.feat4Title;
      document.getElementById('feat4Desc').textContent = dict.feat4Desc;

      document.getElementById('tabBtnRegister').textContent = dict.tabRegister;
      document.getElementById('tabBtnLogin').textContent = dict.tabLogin;

      document.getElementById('lblRegName').textContent = dict.lblRegName;
      document.getElementById('regName').placeholder = dict.phRegName;
      document.getElementById('lblRegEmail').textContent = dict.lblRegEmail;
      document.getElementById('regEmail').placeholder = dict.phRegEmail;
      document.getElementById('lblRegPassword').textContent = dict.lblRegPassword;
      document.getElementById('lblRegInvite').textContent = dict.lblRegInvite;
      document.getElementById('regInvite').placeholder = dict.phRegInvite;
      document.getElementById('lblRegInviteHint').textContent = dict.lblRegInviteHint;
      document.querySelector('#btnSubmitRegister span').textContent = dict.btnRegister;

      document.getElementById('lblLoginUser').textContent = dict.lblLoginUser;
      document.getElementById('loginUsername').placeholder = dict.phLoginUser;
      document.getElementById('lblLoginPwd').textContent = dict.lblLoginPwd;
      document.querySelector('#btnSubmitLogin span').textContent = dict.btnLogin;
      document.getElementById('txtLoginHint').textContent = dict.loginHint;
      document.getElementById('txtFooter').textContent = dict.footer;
    }}

    function toggleLang() {{
      const nextLang = (currentLang === 'fa') ? 'en' : 'fa';
      setLanguage(nextLang);
      try {{
        const url = new URL(window.location);
        url.searchParams.set('lang', nextLang);
        window.history.replaceState({{}}, '', url);
      }} catch (e) {{}}
    }}

    function switchAuthTab(tab) {{
      const alertBox = document.getElementById('authAlert');
      alertBox.classList.add('hidden');

      const btnReg = document.getElementById('tabBtnRegister');
      const btnLog = document.getElementById('tabBtnLogin');
      const fReg = document.getElementById('formRegister');
      const fLog = document.getElementById('formLogin');

      if (tab === 'register') {{
        btnReg.className = 'py-2.5 text-xs font-bold rounded-xl transition bg-indigo-600 text-white shadow-md';
        btnLog.className = 'py-2.5 text-xs font-bold rounded-xl transition text-slate-400 hover:text-white';
        fReg.classList.remove('hidden');
        fLog.classList.add('hidden');
      }} else {{
        btnLog.className = 'py-2.5 text-xs font-bold rounded-xl transition bg-indigo-600 text-white shadow-md';
        btnReg.className = 'py-2.5 text-xs font-bold rounded-xl transition text-slate-400 hover:text-white';
        fLog.classList.remove('hidden');
        fReg.classList.add('hidden');
      }}
    }}

    function showAlert(msg, isError = true) {{
      const box = document.getElementById('authAlert');
      box.textContent = msg;
      box.className = isError
        ? 'p-3.5 mb-5 text-xs rounded-xl border bg-rose-950/80 text-rose-300 border-rose-800'
        : 'p-3.5 mb-5 text-xs rounded-xl border bg-emerald-950/80 text-emerald-300 border-emerald-800';
      box.classList.remove('hidden');
    }}

    async function handleRegister(e) {{
      e.preventDefault();
      const btn = document.getElementById('btnSubmitRegister');
      btn.disabled = true;
      btn.style.opacity = '0.7';

      const payload = {{
        name: document.getElementById('regName').value,
        email: document.getElementById('regEmail').value,
        password: document.getElementById('regPassword').value,
        invite_code: document.getElementById('regInvite').value
      }};

      try {{
        const res = await fetch('/api/register', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(payload)
        }});
        const data = await res.json();
        if (res.ok && data.success) {{
          showAlert(currentLang === 'fa' ? 'ثبت‌نام با موفقیت انجام شد! در حال انتقال به داشبورد...' : 'Registered successfully! Redirecting to dashboard...', false);
          setTimeout(() => {{ window.location.href = data.redirect || '/dashboard'; }}, 1000);
        }} else {{
          showAlert(data.detail || 'Failed to register', true);
        }}
      }} catch (err) {{
        showAlert(String(err), true);
      }} finally {{
        btn.disabled = false;
        btn.style.opacity = '1';
      }}
    }}

    async function handleLogin(e) {{
      e.preventDefault();
      const btn = document.getElementById('btnSubmitLogin');
      btn.disabled = true;
      btn.style.opacity = '0.7';

      const payload = {{
        username: document.getElementById('loginUsername').value,
        password: document.getElementById('loginPassword').value
      }};

      try {{
        const res = await fetch('/api/login', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(payload)
        }});
        const data = await res.json();
        if (res.ok && data.success) {{
          showAlert(currentLang === 'fa' ? 'ورود موفقیت‌آمیز بود! در حال انتقال...' : 'Login successful! Redirecting...', false);
          setTimeout(() => {{ window.location.href = data.redirect || '/dashboard'; }}, 800);
        }} else {{
          showAlert(data.detail || 'Invalid username or password', true);
        }}
      }} catch (err) {{
        showAlert(String(err), true);
      }} finally {{
        btn.disabled = false;
        btn.style.opacity = '1';
      }}
    }}

    // Check URL parameters on load
    window.addEventListener('DOMContentLoaded', () => {{
      const urlParams = new URLSearchParams(window.location.search);
      const qLang = urlParams.get('lang');
      if (qLang && (qLang === 'en' || qLang === 'fa')) {{
        currentLang = qLang;
        localStorage.setItem('vpn_lang', qLang);
      }} else {{
        currentLang = localStorage.getItem('vpn_lang') || 'fa';
      }}
      setLanguage(currentLang);
      const invite = urlParams.get('invite');
      if (invite) {{
        document.getElementById('regInvite').value = invite;
        switchAuthTab('register');
      }}

      const mode = urlParams.get('mode');
      if (mode === 'login') {{
        switchAuthTab('login');
      }}
    }});
  </script>
</body>
</html>"""

# ----------------- 2. END-USER PERSONAL DASHBOARD (BILINGUAL) ----------------- #

DASHBOARD_PAGE_HTML = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>داشبورد کاربری | Home VPN Platform</title>
  {COMMON_HEADER_HTML}
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen selection:bg-indigo-500 selection:text-white flex flex-col justify-between">
  
  <!-- Navigation Header -->
  <header class="border-b border-slate-800/80 bg-slate-900/60 sticky top-0 z-40 backdrop-blur-md">
    <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center space-x-3 space-x-reverse">
        <div class="p-2 rounded-xl bg-gradient-to-tr from-indigo-600 to-cyan-500 text-white shadow-lg shadow-indigo-500/20">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h1 class="font-bold text-sm sm:text-base text-white leading-none">
              <span id="txtUserGreeting">سلام، کاربر گرامی</span>
            </h1>
            <span id="badgeOnlineHeader" class="px-2 py-0.5 text-[10px] rounded-full bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1">
              <span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
              <span id="txtOnlineHeader">در حال بررسی...</span>
            </span>
          </div>
          <p id="txtSubHeader" class="text-xs text-slate-400 mt-0.5">داشبورد اختصاصی مدیریت اشتراک فیلترشکن</p>
        </div>
      </div>

      <div class="flex items-center gap-3">
        <!-- Help & Guide Link -->
        <a href="/help" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>
          <span>راهنما / Help</span>
        </a>

        <!-- Theme Toggle -->
        <button onclick="toggleTheme()" class="px-2.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition" title="Toggle Theme">
          <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
        </button>

        <!-- Language Switcher -->
        <button onclick="toggleLang()" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"/></svg>
          <span id="langSwitchLabel">English</span>
        </button>

        <!-- Admin Control Center Link (if admin) -->
        <a id="linkAdmin" href="/admin" class="hidden px-3 py-1.5 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 text-xs font-semibold transition items-center gap-1">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
          <span id="txtAdminLink">پنل مدیریت</span>
        </a>

        <!-- Logout -->
        <a href="/logout" class="px-3 py-1.5 rounded-xl bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/80 text-xs font-semibold transition flex items-center gap-1">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
          <span id="txtLogout">خروج</span>
        </a>
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <main class="max-w-6xl mx-auto px-4 py-8 flex-1 w-full space-y-8">
    
    <!-- Top KPI Cards Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      
      <!-- Card 1: Connection Status -->
      <div class="glass-card p-6 rounded-3xl border border-slate-800 shadow-xl flex flex-col justify-between">
        <div class="flex items-center justify-between mb-4">
          <span id="lblCardStatusTitle" class="text-xs font-bold text-slate-400 uppercase tracking-wider">وضعیت زنده اتصال</span>
          <div class="p-2 rounded-2xl bg-slate-800 text-indigo-400">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/></svg>
          </div>
        </div>

        <div class="space-y-3">
          <div class="flex items-center gap-3">
            <div id="statusDot" class="w-3.5 h-3.5 rounded-full bg-slate-500"></div>
            <span id="txtLiveStatus" class="text-lg font-bold text-white">در حال بررسی...</span>
          </div>
          <div class="text-xs text-slate-400 space-y-1">
            <div class="flex justify-between">
              <span id="lblLastSeen">آخرین اتصال:</span>
              <span id="valLastSeen" class="font-semibold text-slate-200">تاکنون</span>
            </div>
            <div class="flex justify-between">
              <span id="lblServerGateway">دروازه سرور:</span>
              <span class="font-semibold text-emerald-400">اروپا (Ireland Tunnel)</span>
            </div>
          </div>
        </div>

        <div class="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
          <span id="lblAutoSplit">تفکیک هوشمند ترافیک ایران:</span>
          <span class="text-emerald-400 font-semibold">فعال (Direct)</span>
        </div>
      </div>

      <!-- Card 2: Data Usage & Quota -->
      <div class="glass-card p-6 rounded-3xl border border-slate-800 shadow-xl flex flex-col justify-between">
        <div class="flex items-center justify-between mb-4">
          <span id="lblCardUsageTitle" class="text-xs font-bold text-slate-400 uppercase tracking-wider">حجم مصرفی و سقف مجاز</span>
          <div class="p-2 rounded-2xl bg-slate-800 text-cyan-400">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
          </div>
        </div>

        <div class="space-y-3">
          <div class="flex items-baseline justify-between">
            <span id="valTotalUsed" class="text-2xl font-extrabold text-white">0 B</span>
            <span id="valLimit" class="text-xs text-slate-400">از سقف: نامحدود</span>
          </div>

          <!-- Progress Bar -->
          <div class="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
            <div id="usageBar" class="bg-gradient-to-r from-indigo-500 to-cyan-400 h-2.5 rounded-full transition-all duration-500" style="width: 5%"></div>
          </div>

          <div class="grid grid-cols-2 gap-2 text-xs text-slate-400 pt-1">
            <div>
              <span id="lblUpload">ارسال:</span>
              <span id="valUpload" class="font-mono text-slate-200">0 B</span>
            </div>
            <div>
              <span id="lblDownload">دریافت:</span>
              <span id="valDownload" class="font-mono text-slate-200">0 B</span>
            </div>
          </div>
        </div>

        <div class="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
          <span id="lblExpiry">تاریخ انقضا:</span>
          <span id="valExpiry" class="text-slate-300 font-semibold">دائمی (Never)</span>
        </div>
      </div>

      <!-- Card 3: Anti-DPI & Fallback Lines -->
      <div class="glass-card p-6 rounded-3xl border border-slate-800 shadow-xl flex flex-col justify-between">
        <div class="flex items-center justify-between mb-4">
          <span id="lblCardResilience" class="text-xs font-bold text-slate-400 uppercase tracking-wider">پایداری و مقاومت فیلترینگ</span>
          <div class="p-2 rounded-2xl bg-slate-800 text-emerald-400">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
          </div>
        </div>

        <div class="space-y-2 text-xs">
          <div class="flex items-center justify-between py-1 border-b border-slate-800/60">
            <span class="text-slate-300 flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>TLS Fragmentation</span>
            </span>
            <span class="font-mono text-emerald-400 text-[11px]">Active (10-30 pkts)</span>
          </div>
          <div class="flex items-center justify-between py-1 border-b border-slate-800/60">
            <span class="text-slate-300 flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>uTLS Fingerprint</span>
            </span>
            <span class="font-mono text-indigo-400 text-[11px]">Firefox Browser</span>
          </div>
          <div class="flex items-center justify-between py-1">
            <span class="text-slate-300 flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>Clean Anycast IPs</span>
            </span>
            <span class="font-mono text-cyan-400 text-[11px]">3 Backup Lines</span>
          </div>
        </div>

        <div class="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
          <span id="lblSplitDns">سیستم تفکیک DNS:</span>
          <span class="text-indigo-400 font-semibold">178.22.122.100 (Iran)</span>
        </div>
      </div>

    </div>

    <!-- One-Click Setup & QR Code Section -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
      
      <!-- Subscription Link & One-Click Tools (7 Cols) -->
      <div class="lg:col-span-7 glass-card p-6 sm:p-8 rounded-3xl border border-slate-800 shadow-2xl space-y-6">
        <div>
          <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-950/80 border border-indigo-800 text-[11px] font-semibold text-indigo-300 mb-2">
            <span>یک کلیک تا اتصال</span>
          </div>
          <h3 id="txtSubSectionTitle" class="text-xl font-bold text-white">لینک هوشمند اشتراک اختصاصی شما</h3>
          <p id="txtSubSectionDesc" class="text-xs text-slate-400 mt-1">این لینک را کپی کرده و در برنامه فیلترشکن خود (Hiddify یا v2rayNG یا Streisand) اضافه کنید.</p>
        </div>

        <!-- Copy Subscription URL Box -->
        <div class="space-y-2">
          <div class="flex flex-col sm:flex-row items-stretch gap-2">
            <input type="text" id="inputSubUrl" readonly class="flex-1 px-4 py-3 rounded-2xl bg-slate-950 border border-slate-700 text-xs sm:text-sm font-mono text-indigo-200 select-all focus:outline-none focus:border-indigo-500 ltr-only">
            <button onclick="copySubUrl()" id="btnCopySub" class="px-6 py-3 rounded-2xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs sm:text-sm shadow-lg shadow-indigo-600/30 transition flex items-center justify-center gap-2 shrink-0">
              <svg id="copyIcon" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
              <span id="btnCopySubText">کپی لینک اشتراک</span>
            </button>
          </div>
          <div id="copyToast" class="hidden text-xs text-emerald-400 font-semibold px-2 flex items-center gap-1.5">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
            <span id="txtCopiedToast">لینک در کلیپ‌بورد کپی شد!</span>
          </div>
        </div>

        <!-- Direct Downloads Row -->
        <div class="pt-4 border-t border-slate-800 space-y-3">
          <span id="lblManualDownloads" class="block text-xs font-semibold text-slate-400">دانلود مستقیم فایل و کانفیگ‌ها:</span>
          <div class="flex flex-wrap gap-2.5">
            <a id="btnDownloadJson" href="#" download class="px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 transition flex items-center gap-2">
              <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              <span>دانلود کانفیگ Sing-box (JSON)</span>
            </a>
            <a id="btnDownloadVless" href="#" download class="px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 transition flex items-center gap-2">
              <svg class="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              <span>دانلود لینک‌های VLESS</span>
            </a>
            <button onclick="copyFarsiGuide()" class="px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 transition flex items-center gap-2">
              <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/></svg>
              <span>کپی متن راهنما برای واتساپ/تلگرام</span>
            </button>
          </div>
        </div>

      </div>

      <!-- Scannable QR Code Card (5 Cols) -->
      <div class="lg:col-span-5 glass-card p-6 sm:p-8 rounded-3xl border border-slate-800 shadow-2xl flex flex-col items-center text-center space-y-4">
        <div>
          <h4 id="txtQrTitle" class="text-base font-bold text-white">اسکن کد QR با دوربین گوشی</h4>
          <p id="txtQrDesc" class="text-xs text-slate-400 mt-0.5">در برنامه فیلترشکن، علامت اسکن یا ➕ را بزنید و این تصویر را اسکن کنید.</p>
        </div>

        <div class="p-3 bg-white rounded-3xl shadow-2xl border-4 border-indigo-600/30">
          <img id="imgQrCode" src="" alt="VPN QR Code" class="w-52 h-52 sm:w-56 sm:h-56 object-contain rounded-xl">
        </div>

        <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] text-slate-400">
          <svg class="w-3.5 h-3.5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
          <span id="txtQrTip">حاوی ۴ سرور پشتیبان و قوانین تفکیک ایران</span>
        </div>
      </div>

    </div>

    <!-- Step-by-Step App Guides Section -->
    <div class="glass-card p-6 sm:p-8 rounded-3xl border border-slate-800 shadow-2xl space-y-6">
      
      <div>
        <h3 id="txtGuidesTitle" class="text-xl font-bold text-white">راهنمای راه‌اندازی گام‌به‌گام در گوشی شما</h3>
        <p id="txtGuidesDesc" class="text-xs text-slate-400 mt-1">یکی از برنامه‌های استاندارد زیر را نصب کرده و در ۳ مرحله ساده وصل شوید.</p>
      </div>

      <!-- App Tabs -->
      <div class="flex gap-2 p-1 bg-slate-950/80 rounded-2xl border border-slate-800 max-w-md">
        <button id="tabAppAndroid" onclick="switchAppTab('android')" class="flex-1 py-2.5 text-xs font-bold rounded-xl transition bg-indigo-600 text-white shadow-md flex items-center justify-center gap-2">
          <span>📱 اندروید (Android)</span>
        </button>
        <button id="tabAppIos" onclick="switchAppTab('ios')" class="flex-1 py-2.5 text-xs font-bold rounded-xl transition text-slate-400 hover:text-white flex items-center justify-center gap-2">
          <span>🍏 آیفون و آیپد (iOS)</span>
        </button>
      </div>

      <!-- 1. ANDROID GUIDE CONTENT -->
      <div id="guideAndroid" class="space-y-6">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <!-- Hiddify Box -->
          <div class="p-5 rounded-2xl bg-slate-900/90 border border-indigo-500/30 space-y-3">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <span class="text-xl">🚀</span>
                <div>
                  <h4 class="font-bold text-sm text-white">Hiddify (پیشنهاد اصلی)</h4>
                  <span class="text-[10px] text-emerald-400 font-semibold">پشتیبانی کامل از Sing-box و تفکیک هوشمند</span>
                </div>
              </div>
              <span class="px-2 py-0.5 text-[10px] rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">توصیه شده</span>
            </div>
            <p class="text-xs text-slate-300 leading-relaxed">فوق‌العاده سریع، بدون تبلیغات و خودکار. نیازی به هیچ تنظیم دستی ندارد.</p>
            <div class="flex gap-2 pt-1">
              <a href="https://play.google.com/store/apps/details?id=app.hiddify.com" target="_blank" class="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white border border-slate-700 transition">گوگل پلی (Google Play)</a>
              <a href="https://github.com/hiddify/hiddify-next/releases/latest" target="_blank" class="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white transition">دانلود مستقیم APK</a>
            </div>
          </div>

          <!-- v2rayNG Box -->
          <div class="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div class="flex items-center gap-2">
              <span class="text-xl">⚡</span>
              <div>
                <h4 class="font-bold text-sm text-white">v2rayNG</h4>
                <span class="text-[10px] text-slate-400">کلاسیک و پایدار برای اندروید</span>
              </div>
            </div>
            <p class="text-xs text-slate-300 leading-relaxed">برنامه پرطرفدار و پرسرعت برای اتصال با لینک VLESS و اشتراک معمولی.</p>
            <div class="flex gap-2 pt-1">
              <a href="https://play.google.com/store/apps/details?id=com.v2ray.ang" target="_blank" class="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white border border-slate-700 transition">گوگل پلی (Google Play)</a>
              <a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" class="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white border border-slate-700 transition">دانلود مستقیم APK</a>
            </div>
          </div>
        </div>

        <!-- 3 Steps for Android -->
        <div class="p-5 rounded-2xl bg-slate-900/60 border border-slate-800/80 space-y-3">
          <h4 class="font-bold text-xs text-indigo-300 uppercase tracking-wider">مراحل ۳ گانه اتصال در اندروید:</h4>
          <ol class="text-xs text-slate-300 space-y-2 list-decimal list-inside leading-relaxed">
            <li>برنامه <b>Hiddify</b> یا <b>v2rayNG</b> را از لینک‌های بالا نصب کنید.</li>
            <li>دکمه <b>«کپی لینک اشتراک»</b> در بالای همین صفحه را لمس کنید تا لینک کپی شود.</li>
            <li>برنامه را باز کنید، علامت <b>➕</b> یا <b>«افزودن از کلیپ‌بورد» (Import)</b> را لمس کنید و سپس دکمه دایره‌ای اتصال را بزنید تا متصل شوید!</li>
          </ol>
        </div>
      </div>

      <!-- 2. IOS GUIDE CONTENT -->
      <div id="guideIos" class="space-y-6 hidden">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <!-- Streisand Box -->
          <div class="p-5 rounded-2xl bg-slate-900/90 border border-indigo-500/30 space-y-3">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <span class="text-xl">🍏</span>
                <div>
                  <h4 class="font-bold text-sm text-white">Streisand (پیشنهاد آیفون)</h4>
                  <span class="text-[10px] text-emerald-400 font-semibold">پشتیبانی کامل از Sing-box و VLESS</span>
                </div>
              </div>
              <span class="px-2 py-0.5 text-[10px] rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">توصیه شده</span>
            </div>
            <p class="text-xs text-slate-300 leading-relaxed">برنامه عالی و رایگان در اپ‌استور با پشتیبانی عالی از دور زدن اختلالات.</p>
            <div class="pt-1">
              <a href="https://apps.apple.com/us/app/streisand/id6450534064" target="_blank" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white transition inline-flex items-center gap-1.5">
                <span>دانلود از اپ‌استور (App Store)</span>
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
              </a>
            </div>
          </div>

          <!-- V2Box Box -->
          <div class="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div class="flex items-center gap-2">
              <span class="text-xl">📦</span>
              <div>
                <h4 class="font-bold text-sm text-white">V2Box</h4>
                <span class="text-[10px] text-slate-400">ساده و سریع برای آیفون و آیپد</span>
              </div>
            </div>
            <p class="text-xs text-slate-300 leading-relaxed">محیط کاربری بسیار روان و سازگار با انواع پروتکل‌های V2Ray.</p>
            <div class="pt-1">
              <a href="https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690" target="_blank" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white border border-slate-700 transition inline-flex items-center gap-1.5">
                <span>دانلود از اپ‌استور (App Store)</span>
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
              </a>
            </div>
          </div>
        </div>

        <!-- 3 Steps for iOS -->
        <div class="p-5 rounded-2xl bg-slate-900/60 border border-slate-800/80 space-y-3">
          <h4 class="font-bold text-xs text-indigo-300 uppercase tracking-wider">مراحل ۳ گانه اتصال در آیفون:</h4>
          <ol class="text-xs text-slate-300 space-y-2 list-decimal list-inside leading-relaxed">
            <li>برنامه <b>Streisand</b> یا <b>V2Box</b> را از اپ‌استور دانلود کنید.</li>
            <li>دکمه <b>«کپی لینک اشتراک»</b> در بالای همین صفحه را لمس کنید.</li>
            <li>در برنامه علامت <b>➕</b> را زده، گزینه <b>Add Subscription</b> را انتخاب و لینک را جای‌گذاری (Paste) کنید، سپس متصل شوید!</li>
          </ol>
        </div>
      </div>

      <!-- Iranian Banking Callout Box -->
      <div class="p-4 sm:p-5 rounded-2xl bg-amber-950/40 border border-amber-800/60 flex items-start gap-3">
        <div class="p-2 rounded-xl bg-amber-500/10 text-amber-400 shrink-0">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
        </div>
        <div class="space-y-1">
          <h4 id="txtBankingTipTitle" class="font-bold text-xs sm:text-sm text-amber-200">نکته بسیار مهم برای همراه بانک‌ها، اسنپ و برنامه‌های داخلی:</h4>
          <p id="txtBankingTipDesc" class="text-xs text-amber-300/80 leading-relaxed">
            تمامی سایت‌های ایرانی، بانکی، اسنپ و دیجی‌کالا به صورت خودکار بدون فیلترشکن و با اینترنت عادی باز می‌شوند. با این وجود، اگر همراه بانک خاصی در گوشی شما نسبت به فیلترشکن حساس است، می‌توانید در تنظیمات برنامه Hiddify یا v2rayNG گزینه <b>پروکسی بر اساس برنامه (Per-App Proxy)</b> را فعال کرده و برنامه‌های بانکی را تیک نزنید تا به طور کامل از تونل فیلترشکن مستثنی شوند.
          </p>
        </div>
      </div>

    </div>

  </main>

  <!-- Footer -->
  <footer class="border-t border-slate-800/80 bg-slate-900/40 py-4 text-center text-xs text-slate-400">
    <div class="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
      <span>سرور فیلترشکن خانواده • اختصاصی توحید</span>
      <span class="text-slate-400 font-mono text-[11px]">Clean Cloudflare Anycast Fallback Lines Active</span>
    </div>
  </footer>

  <script>
    let mySubUrl = '';
    let myFarsiGuide = '';
    let currentLang = localStorage.getItem('vpn_lang') || 'fa';

    function setLanguage(lang) {{
      currentLang = lang;
      localStorage.setItem('vpn_lang', lang);
      const isRtl = (lang === 'fa');

      document.documentElement.setAttribute('lang', lang);
      document.documentElement.setAttribute('dir', isRtl ? 'rtl' : 'ltr');
      document.getElementById('langSwitchLabel').textContent = (lang === 'fa' ? 'English' : 'فارسی');

      if (lang === 'en') {{
        document.title = 'Personal Dashboard | Home VPN Platform';
        document.getElementById('txtSubHeader').textContent = 'Personal VPN subscription management dashboard';
        document.getElementById('txtLogout').textContent = 'Logout';
        document.getElementById('lblCardStatusTitle').textContent = 'Live Connection Status';
        document.getElementById('lblLastSeen').textContent = 'Last Connected:';
        document.getElementById('lblServerGateway').textContent = 'Gateway:';
        document.getElementById('lblAutoSplit').textContent = 'Auto Iran Split-Tunneling:';
        document.getElementById('lblCardUsageTitle').textContent = 'Data Quota & Usage';
        document.getElementById('lblUpload').textContent = 'Upload:';
        document.getElementById('lblDownload').textContent = 'Download:';
        document.getElementById('lblExpiry').textContent = 'Expiration:';
        document.getElementById('lblCardResilience').textContent = 'Anti-Censorship & Fallback';
        document.getElementById('lblSplitDns').textContent = 'Split DNS Engine:';
        document.getElementById('txtSubSectionTitle').textContent = 'Your Smart Subscription Link';
        document.getElementById('txtSubSectionDesc').textContent = 'Copy this subscription URL into your VPN client app.';
        document.getElementById('btnCopySubText').textContent = 'Copy Subscription URL';
        document.getElementById('txtCopiedToast').textContent = 'Copied to clipboard!';
        document.getElementById('lblManualDownloads').textContent = 'Direct Config Downloads:';
        document.getElementById('txtQrTitle').textContent = 'Scan QR Code with Phone';
        document.getElementById('txtQrDesc').textContent = 'Scan this QR code in Hiddify, v2rayNG, Streisand, or V2Box.';
        document.getElementById('txtGuidesTitle').textContent = 'Step-by-Step Setup Guides';
        document.getElementById('txtGuidesDesc').textContent = 'Connect in 3 easy steps on your mobile device.';
        document.getElementById('txtBankingTipTitle').textContent = 'Important note for Iranian banking apps:';
        document.getElementById('txtBankingTipDesc').textContent = 'All Iranian banking apps, Snapp and .ir domains automatically route direct without VPN. You can also use Per-App Proxy in Hiddify/v2rayNG to bypass banking apps completely.';
      }} else {{
        document.title = 'داشبورد کاربری | Home VPN Platform';
        document.getElementById('txtSubHeader').textContent = 'داشبورد اختصاصی مدیریت اشتراک فیلترشکن';
        document.getElementById('txtLogout').textContent = 'خروج';
        document.getElementById('lblCardStatusTitle').textContent = 'وضعیت زنده اتصال';
        document.getElementById('lblLastSeen').textContent = 'آخرین اتصال:';
        document.getElementById('lblServerGateway').textContent = 'دروازه سرور:';
        document.getElementById('lblAutoSplit').textContent = 'تفکیک هوشمند ترافیک ایران:';
        document.getElementById('lblCardUsageTitle').textContent = 'حجم مصرفی و سقف مجاز';
        document.getElementById('lblUpload').textContent = 'ارسال:';
        document.getElementById('lblDownload').textContent = 'دریافت:';
        document.getElementById('lblExpiry').textContent = 'تاریخ انقضا:';
        document.getElementById('lblCardResilience').textContent = 'پایداری و مقاومت فیلترینگ';
        document.getElementById('lblSplitDns').textContent = 'سیستم تفکیک DNS:';
        document.getElementById('txtSubSectionTitle').textContent = 'لینک هوشمند اشتراک اختصاصی شما';
        document.getElementById('txtSubSectionDesc').textContent = 'این لینک را کپی کرده و در برنامه فیلترشکن خود اضافه کنید.';
        document.getElementById('btnCopySubText').textContent = 'کپی لینک اشتراک';
        document.getElementById('txtCopiedToast').textContent = 'لینک در کلیپ‌بورد کپی شد!';
        document.getElementById('lblManualDownloads').textContent = 'دانلود مستقیم فایل و کانفیگ‌ها:';
        document.getElementById('txtQrTitle').textContent = 'اسکن کد QR با دوربین گوشی';
        document.getElementById('txtQrDesc').textContent = 'در برنامه فیلترشکن علامت اسکن را بزنید و این کد را اسکن کنید.';
        document.getElementById('txtGuidesTitle').textContent = 'راهنمای راه‌اندازی گام‌به‌گام در گوشی شما';
        document.getElementById('txtGuidesDesc').textContent = 'یکی از برنامه‌های استاندارد زیر را نصب کرده و وصل شوید.';
        document.getElementById('txtBankingTipTitle').textContent = 'نکته بسیار مهم برای همراه بانک‌ها، اسنپ و برنامه‌های داخلی:';
        document.getElementById('txtBankingTipDesc').textContent = 'تمامی سایت‌های ایرانی و بانکی به صورت خودکار بدون فیلترشکن باز می‌شوند. همچنین می‌توانید از گزینه Per-App Proxy برای تفکیک برنامه‌های بانکی استفاده کنید.';
      }}
    }}

    function toggleLang() {{
      const nextLang = (currentLang === 'fa') ? 'en' : 'fa';
      setLanguage(nextLang);
      try {{
        const url = new URL(window.location);
        url.searchParams.set('lang', nextLang);
        window.history.replaceState({{}}, '', url);
      }} catch (e) {{}}
    }}

    function switchAppTab(tab) {{
      const bAnd = document.getElementById('tabAppAndroid');
      const bIos = document.getElementById('tabAppIos');
      const gAnd = document.getElementById('guideAndroid');
      const gIos = document.getElementById('guideIos');

      if (tab === 'android') {{
        bAnd.className = 'flex-1 py-2.5 text-xs font-bold rounded-xl transition bg-indigo-600 text-white shadow-md flex items-center justify-center gap-2';
        bIos.className = 'flex-1 py-2.5 text-xs font-bold rounded-xl transition text-slate-400 hover:text-white flex items-center justify-center gap-2';
        gAnd.classList.remove('hidden');
        gIos.classList.add('hidden');
      }} else {{
        bIos.className = 'flex-1 py-2.5 text-xs font-bold rounded-xl transition bg-indigo-600 text-white shadow-md flex items-center justify-center gap-2';
        bAnd.className = 'flex-1 py-2.5 text-xs font-bold rounded-xl transition text-slate-400 hover:text-white flex items-center justify-center gap-2';
        gIos.classList.remove('hidden');
        gAnd.classList.add('hidden');
      }}
    }}

    async function fetchUserData() {{
      try {{
        const res = await fetch('/api/user/me');
        if (res.status === 401) {{
          window.location.href = '/?mode=login';
          return;
        }}
        const d = await res.json();

        // Greeting
        document.getElementById('txtUserGreeting').textContent = currentLang === 'fa' ? `سلام، ${{d.name || d.email}}` : `Hello, ${{d.name || d.email}}`;
        if (d.role === 'admin') {{
          document.getElementById('linkAdmin').classList.remove('hidden');
        }}

        // Online Badge
        const badge = document.getElementById('badgeOnlineHeader');
        const txtOnline = document.getElementById('txtOnlineHeader');
        const statusDot = document.getElementById('statusDot');
        const txtLive = document.getElementById('txtLiveStatus');

        if (d.is_online) {{
          badge.className = 'px-2 py-0.5 text-[10px] rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1';
          txtOnline.textContent = currentLang === 'fa' ? 'آنلاین / متصل' : 'Online / Connected';
          statusDot.className = 'w-3.5 h-3.5 rounded-full bg-emerald-400 animate-ping';
          txtLive.textContent = currentLang === 'fa' ? '🟢 متصل و آنلاین' : '🟢 Online & Connected';
          txtLive.className = 'text-lg font-bold text-emerald-400';
        }} else {{
          badge.className = 'px-2 py-0.5 text-[10px] rounded-full bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1';
          txtOnline.textContent = currentLang === 'fa' ? 'آفلاین' : 'Offline';
          statusDot.className = 'w-3.5 h-3.5 rounded-full bg-slate-500';
          txtLive.textContent = currentLang === 'fa' ? '⚪ آفلاین' : '⚪ Offline';
          txtLive.className = 'text-lg font-bold text-slate-400';
        }}

        document.getElementById('valLastSeen').textContent = currentLang === 'fa' ? d.last_seen_fa : d.last_seen_en;

        // Quota
        document.getElementById('valTotalUsed').textContent = d.total_used_str;
        document.getElementById('valLimit').textContent = (currentLang === 'fa' ? 'سقف: ' : 'Limit: ') + d.limit_str;
        document.getElementById('valUpload').textContent = d.up_str;
        document.getElementById('valDownload').textContent = d.down_str;
        document.getElementById('valExpiry').textContent = d.expiry_str;

        const pct = Math.min(100, Math.max(3, d.percent_used || 0));
        const bar = document.getElementById('usageBar');
        bar.style.width = pct + '%';
        if (pct >= 85) {{
          bar.className = 'bg-gradient-to-r from-amber-500 to-rose-500 h-2.5 rounded-full transition-all duration-500';
        }} else {{
          bar.className = 'bg-gradient-to-r from-indigo-500 to-cyan-400 h-2.5 rounded-full transition-all duration-500';
        }}

        // Links & QR Code
        mySubUrl = d.smart_sub_link;
        myFarsiGuide = d.farsi_instructions;
        document.getElementById('inputSubUrl').value = d.smart_sub_link;
        document.getElementById('imgQrCode').src = 'data:image/png;base64,' + d.qr_b64;
        document.getElementById('btnDownloadJson').href = d.json_sub_link;
        document.getElementById('btnDownloadVless').href = d.vless_sub_link;

      }} catch (err) {{
        console.error('Fetch user data error:', err);
      }}
    }}

    function copySubUrl() {{
      const el = document.getElementById('inputSubUrl');
      el.select();
      navigator.clipboard.writeText(el.value).then(() => {{
        const toast = document.getElementById('copyToast');
        toast.classList.remove('hidden');
        setTimeout(() => {{ toast.classList.add('hidden'); }}, 3000);
      }});
    }}

    function copyFarsiGuide() {{
      if (myFarsiGuide) {{
        navigator.clipboard.writeText(myFarsiGuide).then(() => {{
          alert(currentLang === 'fa' ? 'متن راهنما کپی شد! می‌توانید آن را در واتساپ یا تلگرام برای دیگران بفرستید.' : 'Guide copied to clipboard!');
        }});
      }}
    }}

    window.addEventListener('DOMContentLoaded', () => {{
      const urlParams = new URLSearchParams(window.location.search);
      const qLang = urlParams.get('lang');
      if (qLang && (qLang === 'en' || qLang === 'fa')) {{
        currentLang = qLang;
        localStorage.setItem('vpn_lang', qLang);
      }} else {{
        currentLang = localStorage.getItem('vpn_lang') || 'fa';
      }}
      setLanguage(currentLang);
      fetchUserData();
      setInterval(fetchUserData, 10000);
    }});
  </script>
</body>
</html>"""

# ----------------- 3. ADMIN DASHBOARD WITH BIRD'S-EYE OVERVIEW & ONE-CLICK BYPASS ----------------- #

ADMIN_PAGE_HTML = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title id="docTitle">مرکز مدیریت فیلترشکن خانواده | Admin Control Center</title>
  {COMMON_HEADER_HTML}
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen selection:bg-indigo-500 selection:text-white flex flex-col justify-between">
  
  <!-- Navigation Header -->
  <header class="border-b border-slate-800/80 bg-slate-900/60 sticky top-0 z-40 backdrop-blur-md">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between gap-4">
      <div class="flex items-center gap-3">
        <div class="p-2.5 rounded-2xl bg-gradient-to-tr from-indigo-600 via-indigo-500 to-cyan-400 text-white shadow-lg shadow-indigo-500/25 shrink-0">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h1 class="font-extrabold text-sm sm:text-base tracking-tight text-white leading-none">
              <span id="txtAdminTitle">مرکز مدیریت فیلترشکن خانواده</span>
            </h1>
            <span id="txtAdminRoleBadge" class="px-2 py-0.5 text-[10px] rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">مدیر سیستم (Tohid)</span>
          </div>
          <p id="txtAdminSub" class="text-xs text-slate-400 mt-0.5">دید پرنده، مدیریت کاربران، و بای‌پس تک‌کلیک دامنه‌ها</p>
        </div>
      </div>

      <div class="flex items-center gap-2 sm:gap-2.5 flex-wrap justify-end">
        <!-- Direct Domains Modal Button -->
        <button onclick="openDomainsModal()" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064"/></svg>
          <span id="txtBtnDomains">دامنه‌های مستقیم</span>
        </button>

        <!-- Telegram Config Modal Button -->
        <button onclick="openTelegramModal()" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/></svg>
          <span id="txtBtnTelegram">هشدار تلگرام</span>
        </button>

        <!-- Backup & Restore Button -->
        <button onclick="openBackupModal()" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>
          <span id="txtBtnBackup">پشتیبان‌گیری</span>
        </button>

        <!-- Help & Guide Link -->
        <a href="/help" target="_blank" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>
          <span id="txtBtnHelp">راهنما</span>
        </a>

        <!-- Diagnostics Modal Button -->
        <button onclick="openDiagModal()" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
          <span id="txtBtnDiag">عیب‌یابی</span>
        </button>

        <!-- Theme Toggle -->
        <button onclick="toggleTheme()" class="px-2.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition" title="Toggle Theme">
          <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
        </button>

        <!-- Language Switcher Button -->
        <button id="btnLangToggle" onclick="toggleLang()" class="px-3.5 py-1.5 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 text-xs font-bold transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"/></svg>
          <span id="langSwitchLabel">English</span>
        </button>

        <!-- Logout -->
        <a href="/logout" id="txtAdminLogout" class="px-3 py-1.5 rounded-xl bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/80 text-xs font-semibold transition">خروج</a>
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <main class="max-w-7xl mx-auto px-4 py-8 flex-1 w-full space-y-8">
    
    <!-- Prominent Connection & Sharing Status Banner -->
    <div class="glass-card p-6 rounded-3xl border border-indigo-900/60 bg-gradient-to-r from-slate-900/90 via-indigo-950/40 to-slate-900/90 shadow-2xl space-y-4">
      <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div class="flex items-center gap-2.5">
          <div class="p-2 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
          </div>
          <div>
            <h3 id="txtConnStatusTitle" class="text-base font-extrabold text-white">وضعیت دسترسی و اشتراک‌گذاری سراسری</h3>
            <p id="txtConnStatusSub" class="text-xs text-slate-400">آدرس‌های پورتال برای دسترسی محلی در خانه و اشتراک‌گذاری امن از راه دور</p>
          </div>
        </div>

        <!-- Action buttons: WhatsApp & Telegram sharing & QR -->
        <div class="flex items-center gap-2 flex-wrap">
          <button onclick="shareViaWhatsApp()" class="px-3.5 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold transition flex items-center gap-1.5 shadow-sm shadow-emerald-600/30">
            <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M.057 24l1.687-6.163c-1.041-1.804-1.588-3.849-1.587-5.946.003-6.556 5.338-11.891 11.893-11.891 3.181.001 6.167 1.24 8.413 3.488 2.245 2.248 3.481 5.236 3.48 8.414-.003 6.557-5.338 11.892-11.893 11.892-1.99-.001-3.951-.5-5.688-1.448l-6.305 1.654zm6.597-3.807c1.676.995 3.276 1.591 5.392 1.592 5.448 0 9.886-4.434 9.889-9.885.002-5.462-4.415-9.89-9.881-9.892-5.452 0-9.887 4.434-9.889 9.884-.001 2.225.651 3.891 1.746 5.634l-.999 3.648 3.742-.981z"/></svg>
            <span id="btnShareWhatsApp">اشتراک با واتس‌اپ</span>
          </button>
          <button onclick="shareViaTelegram()" class="px-3.5 py-1.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold transition flex items-center gap-1.5 shadow-sm shadow-sky-600/30">
            <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.627 0-12 5.373-12 12s5.373 12 12 12 12-5.373 12-12-5.373-12-12-12zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.446 1.394c-.14.18-.357.295-.6.295-.002 0-.003 0-.005 0l.213-3.054 5.56-5.022c.24-.213-.054-.334-.373-.121l-6.869 4.326-2.96-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.536-.195 1.006.128.832.942z"/></svg>
            <span id="btnShareTelegram">اشتراک با تلگرام</span>
          </button>
          <button onclick="openPortalQrModal()" class="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition flex items-center gap-1.5">
            <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"/></svg>
            <span id="btnPortalQr">بارکد QR</span>
          </button>
        </div>
      </div>

      <!-- 3 Connection Cards: Local, LAN, Public -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <!-- Localhost -->
        <div class="p-3.5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1">
          <div class="flex items-center justify-between">
            <span id="lblLocalHostTitle" class="text-[11px] font-bold text-slate-400">آدرس محلی روی این لپ‌تاپ:</span>
            <button onclick="copyToClipboard(currentLocalUrl, 'btnCopyLocal')" id="btnCopyLocal" class="text-[10px] text-indigo-400 hover:text-indigo-300 font-bold">کپی</button>
          </div>
          <div id="valLocalUrl" class="font-mono text-xs text-indigo-300 truncate ltr-only">http://127.0.0.1:8080</div>
          <div id="subLocalHost" class="text-[10px] text-slate-500">مخصوص مرورگر همین دستگاه</div>
        </div>

        <!-- Home Wi-Fi LAN -->
        <div class="p-3.5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1">
          <div class="flex items-center justify-between">
            <span id="lblLanTitle" class="text-[11px] font-bold text-slate-400">آدرس وای‌فای خانگی (LAN):</span>
            <button onclick="copyToClipboard(currentLanUrl, 'btnCopyLan')" id="btnCopyLan" class="text-[10px] text-cyan-400 hover:text-cyan-300 font-bold">کپی</button>
          </div>
          <div id="valLanUrl" class="font-mono text-xs text-cyan-300 truncate ltr-only">http://192.168.1.x:8080</div>
          <div id="subLanTitle" class="text-[10px] text-slate-500">برای گوشی‌های متصل به همین وای‌فای</div>
        </div>

        <!-- Public Cloudflare Tunnel -->
        <div class="p-3.5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1">
          <div class="flex items-center justify-between">
            <span id="lblPublicTunnelTitle" class="text-[11px] font-bold text-slate-400">آدرس عمومی اینترنت (تونل ابری):</span>
            <button onclick="copyToClipboard(currentPublicUrl, 'btnCopyPublic')" id="btnCopyPublic" class="text-[10px] text-emerald-400 hover:text-emerald-300 font-bold">کپی</button>
          </div>
          <div id="valPublicUrl" class="font-mono text-xs text-emerald-300 truncate ltr-only">https://*.trycloudflare.com</div>
          <div id="subPublicTunnel" class="text-[10px] text-emerald-400/80">قابل دسترسی از سراسر دنیا و ایران</div>
        </div>
      </div>
    </div>

    <!-- Top Summary KPI Cards -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
      
      <!-- KPI 1: Total Users -->
      <div class="glass-card p-5 rounded-3xl border border-slate-800 shadow-xl flex items-center justify-between">
        <div>
          <span id="kpiLblTotalUsers" class="text-xs font-bold text-slate-400 uppercase tracking-wider block">کل کاربران خانواده</span>
          <span id="kpiValTotalUsers" class="text-3xl font-extrabold text-white mt-1 block">0</span>
          <span id="kpiSubTotalUsers" class="text-[11px] text-slate-500">حساب‌های فعال در سرور</span>
        </div>
        <div class="p-3 rounded-2xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shrink-0">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
        </div>
      </div>

      <!-- KPI 2: Online Users -->
      <div class="glass-card p-5 rounded-3xl border border-slate-800 shadow-xl flex items-center justify-between">
        <div>
          <span id="kpiLblOnline" class="text-xs font-bold text-slate-400 uppercase tracking-wider block">کاربران آنلاین در این لحظه</span>
          <div class="flex items-center gap-2 mt-1">
            <span id="kpiValOnline" class="text-3xl font-extrabold text-emerald-400">0</span>
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
          </div>
          <span id="kpiSubOnline" class="text-[11px] text-emerald-400/80">ترافیک زنده ۱۵ دقیقه اخیر</span>
        </div>
        <div class="p-3 rounded-2xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"/></svg>
        </div>
      </div>

      <!-- KPI 3: Bandwidth -->
      <div class="glass-card p-5 rounded-3xl border border-slate-800 shadow-xl flex items-center justify-between">
        <div>
          <span id="kpiLblBandwidth" class="text-xs font-bold text-slate-400 uppercase tracking-wider block">مجموع ترافیک خانواده</span>
          <span id="kpiValBandwidth" class="text-3xl font-extrabold text-cyan-400 mt-1 block">0 B</span>
          <div class="text-[11px] text-slate-400 flex gap-2 font-mono mt-0.5">
            <span>↑ <span id="kpiValUp">0 B</span></span>
            <span>↓ <span id="kpiValDown">0 B</span></span>
          </div>
        </div>
        <div class="p-3 rounded-2xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shrink-0">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
        </div>
      </div>

      <!-- KPI 4: Watchdog Health -->
      <div class="glass-card p-5 rounded-3xl border border-slate-800 shadow-xl flex items-center justify-between">
        <div>
          <span id="kpiLblWatchdog" class="text-xs font-bold text-slate-400 uppercase tracking-wider block">سیستم خودترمیمی و تونل</span>
          <span id="kpiValWatchdog" class="text-sm font-bold text-emerald-400 mt-1 block">Healthy & Active</span>
          <span id="kpiSubWatchdog" class="text-[11px] text-slate-500 font-mono">Cloudflare Quick Tunnel</span>
        </div>
        <div class="p-3 rounded-2xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
      </div>

    </div>

    <!-- Shareable Family Invite Code Card -->
    <div class="glass-card p-6 rounded-3xl border border-indigo-900/60 bg-gradient-to-r from-indigo-950/60 via-slate-900/80 to-slate-900/60 shadow-2xl flex flex-col md:flex-row items-center justify-between gap-5">
      <div class="space-y-1.5 text-start w-full">
        <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 text-[11px] font-bold">
          <span id="txtInviteBadge">کد دعوت فعال خانواده</span>
        </div>
        <h3 class="text-lg font-bold text-white flex items-center gap-2">
          <span id="lblInviteTitle">کد دعوت:</span>
          <span id="txtCurrentInviteCode" class="font-mono text-xl text-indigo-300 bg-indigo-950/90 px-3 py-0.5 rounded-xl border border-indigo-700/60">IR-FAMILY</span>
          <button id="btnEditInvite" onclick="editInviteCode()" class="text-xs text-indigo-400 hover:text-indigo-200 underline font-normal">ویرایش</button>
        </h3>
        <p id="txtInviteDesc" class="text-xs text-slate-300 max-w-2xl leading-relaxed">این لینک و کد را برای اعضای خانواده بفرستید تا بتوانند مستقیماً از گوشی ثبت‌نام کرده و اشتراک هوشمند دریافت کنند.</p>
      </div>

      <div class="flex items-center gap-2.5 w-full md:w-auto shrink-0">
        <button onclick="copyShareableInviteLink()" class="w-full md:w-auto px-5 py-3 rounded-2xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg shadow-indigo-600/30 transition flex items-center justify-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
          <span id="btnCopyInviteText">کپی لینک دعوت و متن آماده</span>
        </button>
      </div>
    </div>

    <!-- Automated Cloudflare Clean Edge IP & Speed Optimizer Card -->
    <div class="glass-card p-6 rounded-3xl border border-cyan-900/60 bg-gradient-to-r from-cyan-950/60 via-slate-900/80 to-slate-900/60 shadow-2xl flex flex-col md:flex-row items-center justify-between gap-5">
      <div class="space-y-2 text-start w-full">
        <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-600/20 text-cyan-300 border border-cyan-500/30 text-[11px] font-bold">
          <span id="txtCfIpBadge">بهینه‌سازی خودکار سرعت و Clean Edge IP</span>
        </div>
        <h3 class="text-lg font-bold text-white flex items-center gap-2 flex-wrap">
          <span id="lblCfIpTitle">آی‌پی کلودفلر فعال (پروفایل ۱):</span>
          <span id="txtActiveCfIp" class="font-mono text-base text-cyan-300 bg-cyan-950/90 px-3 py-0.5 rounded-xl border border-cyan-700/60">104.16.132.229</span>
          <span id="txtCfIpType" class="text-[10px] text-emerald-300 bg-emerald-950/80 px-2 py-0.5 rounded-lg border border-emerald-700/60 font-semibold">ارتقای خودکار</span>
          <span id="txtCfLatency" class="text-[10px] text-cyan-300 bg-cyan-950/80 px-2 py-0.5 rounded-lg border border-cyan-700/60 font-mono">-- ms</span>
        </h3>
        <p id="txtCfIpDesc" class="text-xs text-slate-300 max-w-2xl leading-relaxed">اسکنر هوشمند هر ۱۵ دقیقه پینگ و پایداری ۲۴ آی‌پی Anycast کلودفلر را بررسی کرده و سریع‌ترین آی‌پی را به عنوان پروفایل شماره ۱ به اشتراک‌های خانواده ارتقا می‌دهد.</p>
        <div class="flex items-center gap-4 pt-1 text-[11px] text-slate-400 flex-wrap">
          <label class="flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox" id="chkCfAutoOptimize" onchange="toggleCfAutoOptimize(this.checked)" class="w-4 h-4 rounded text-cyan-500 bg-slate-900 border-slate-700 focus:ring-cyan-500" checked>
            <span id="lblAutoOptimizeText" class="text-slate-200 font-semibold">بهینه‌سازی خودکار (هر ۱۵ دقیقه)</span>
          </label>
          <span class="text-slate-600">|</span>
          <div class="flex items-center gap-1">
            <span id="lblLastScanText">آخرین اسکن:</span>
            <span id="txtCfLastScan" class="font-mono text-cyan-400">Never</span>
          </div>
        </div>
      </div>

      <div class="flex flex-col sm:flex-row items-center gap-2.5 w-full md:w-auto shrink-0">
        <button id="btnScanNow" onclick="triggerCfScanNow()" class="w-full sm:w-auto px-4 py-2.5 rounded-2xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-lg shadow-emerald-600/30 transition flex items-center justify-center gap-1.5 whitespace-nowrap">
          <svg id="svgScanSpin" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
          <span id="btnScanNowText">اسکن و ارتقای فوری</span>
        </button>
        <input type="text" id="inpCfIpOverride" placeholder="e.g. 104.16.132.229" class="w-full sm:w-44 px-3 py-2.5 rounded-2xl bg-slate-950/80 border border-slate-700 text-cyan-300 font-mono text-xs focus:outline-none focus:border-cyan-500 transition placeholder:text-slate-600">
        <button onclick="saveCfIpOverride()" class="w-full sm:w-auto px-3.5 py-2.5 rounded-2xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-lg shadow-cyan-600/30 transition flex items-center justify-center gap-1 whitespace-nowrap">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
          <span id="btnSaveCfIpText">ثبت دستی</span>
        </button>
        <button onclick="resetCfIpOverride()" class="w-full sm:w-auto px-3 py-2.5 rounded-2xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-medium text-xs border border-slate-700 transition flex items-center justify-center gap-1 whitespace-nowrap">
          <span id="btnResetCfIpText">بازنشانی</span>
        </button>
      </div>
    </div>

    <!-- ONE-CLICK BYPASS MANAGER: Detected Blocked / Failing / Leaked Domains -->
    <div class="glass-card rounded-3xl border border-slate-800 shadow-2xl overflow-hidden">
      <div class="p-6 border-b border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <div class="flex items-center gap-2">
            <h3 id="txtFailingTitle" class="text-lg font-bold text-white">شناسایی دامنه‌های دچار اختلال یا نشتی به ایرلند</h3>
            <span id="badgeFailingCount" class="px-2 py-0.5 text-[11px] rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 font-mono">0 دامنه</span>
          </div>
          <p id="txtFailingSub" class="text-xs text-slate-400 mt-0.5">دامنه‌های ایرانی که اشتباهاً از فیلترشکن رد شده‌اند یا ارتباط با آن‌ها با خطا روبرو شده است. با یک کلیک آن‌ها را به مسیر مستقیم ایران اضافه کنید.</p>
        </div>
        <button onclick="fetchFailingDomains()" class="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition flex items-center gap-1.5 shrink-0">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
          <span id="txtBtnRefreshFailing">بروزرسانی زنده</span>
        </button>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-start text-xs">
          <thead class="bg-slate-900/80 text-slate-400 uppercase font-semibold text-[11px] border-b border-slate-800">
            <tr>
              <th id="thFailDomain" class="p-4 text-start">دامنه مقصد (Domain)</th>
              <th id="thFailHits" class="p-4 text-center">تعداد مراجعه (Hits)</th>
              <th id="thFailUsers" class="p-4 text-start">کاربران مراجعه‌کننده</th>
              <th id="thFailReason" class="p-4 text-start">علت شناسایی</th>
              <th id="thFailAction" class="p-4 text-center">عملیات</th>
            </tr>
          </thead>
          <tbody id="failingDomainsBody" class="divide-y divide-slate-800/60 font-medium">
            <tr>
              <td colspan="5" class="p-8 text-center text-slate-500">در حال بارگذاری لیست دامنه‌های دچار اختلال...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- User Management Table -->
    <div class="glass-card rounded-3xl border border-slate-800 shadow-2xl overflow-hidden">
      <div class="p-6 border-b border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h3 id="txtUsersTitle" class="text-lg font-bold text-white">مدیریت اعضای خانواده و اشتراک‌ها</h3>
          <p id="txtUsersSub" class="text-xs text-slate-400 mt-0.5">مشاهده حجم، وضعیت آنلاین، کپی لینک اشتراک و مدیریت ترافیک</p>
        </div>
        <button onclick="openAddMemberModal()" class="px-4 py-2.5 rounded-2xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg shadow-indigo-600/30 transition flex items-center gap-2 shrink-0">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/></svg>
          <span id="txtBtnAddMember">+ تعریف عضو جدید</span>
        </button>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-start text-xs">
          <thead class="bg-slate-900/80 text-slate-400 uppercase font-semibold text-[11px] border-b border-slate-800">
            <tr>
              <th id="thUserName" class="p-4 text-start">نام و حساب</th>
              <th id="thUserStatus" class="p-4 text-center">وضعیت زنده</th>
              <th id="thUserUsage" class="p-4 text-start">حجم مصرفی / سقف</th>
              <th id="thUserExpiry" class="p-4 text-start">تاریخ انقضا</th>
              <th id="thUserActions" class="p-4 text-center">عملیات</th>
            </tr>
          </thead>
          <tbody id="clientsTableBody" class="divide-y divide-slate-800/60 font-medium">
            <tr>
              <td colspan="5" class="p-8 text-center text-slate-500">در حال بارگذاری لیست کاربران...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

  </main>

  <!-- Modals Container -->

  <!-- 1. Add Member Modal -->
  <div id="addMemberModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 max-w-md w-full space-y-5">
      <div class="flex items-center justify-between">
        <h4 id="txtAddModalTitle" class="font-bold text-base text-white">افزودن عضو جدید خانواده</h4>
        <button onclick="closeModal('addMemberModal')" class="text-slate-400 hover:text-white">✕</button>
      </div>
      <form onsubmit="handleAddMember(event)" class="space-y-4">
        <div>
          <label id="lblAddName" class="block text-xs font-semibold text-slate-300 mb-1">نام یا ایمیل</label>
          <input type="text" id="addName" required placeholder="مثال: Javad" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label id="lblAddQuota" class="block text-xs font-semibold text-slate-300 mb-1">سقف حجم مجاز (گیگابایت - ۰ برای نامحدود)</label>
          <input type="number" id="addLimitGb" step="1" value="0" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label id="lblAddExpiry" class="block text-xs font-semibold text-slate-300 mb-1">مدت اعتبار (روز - ۰ برای دائمی)</label>
          <input type="number" id="addExpiryDays" step="1" value="0" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500">
        </div>
        <button type="submit" id="btnAddSubmit" class="w-full py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-sm shadow-lg shadow-indigo-600/30 transition">
          ایجاد حساب و صدور لینک
        </button>
      </form>
    </div>
  </div>

  <!-- 2. QR & Setup Modal -->
  <div id="qrModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 max-w-lg w-full space-y-4 text-center">
      <div class="flex items-center justify-between">
        <h4 id="qrModalTitle" class="font-bold text-base text-white">اشتراک کاربر</h4>
        <button onclick="closeModal('qrModal')" class="text-slate-400 hover:text-white">✕</button>
      </div>
      <div class="p-3 bg-white rounded-2xl inline-block border-4 border-indigo-600/30">
        <img id="qrModalImg" src="" alt="QR" class="w-56 h-56 object-contain">
      </div>
      <div class="space-y-2">
        <input type="text" id="qrModalUrl" readonly class="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-xs font-mono text-indigo-300 select-all ltr-only">
        <div class="flex gap-2">
          <button id="btnModalCopySub" onclick="copyModalUrl()" class="flex-1 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition">کپی لینک اشتراک</button>
          <button id="btnModalCopyGuide" onclick="copyModalFarsiGuide()" class="flex-1 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs border border-slate-700 transition">کپی متن راهنما</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 3. Direct Domains Modal -->
  <div id="domainsModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 max-w-lg w-full space-y-4">
      <div class="flex items-center justify-between">
        <h4 id="txtDomainsModalTitle" class="font-bold text-base text-white">ویرایش دامنه‌های مستقیم ایران (Direct Bypass)</h4>
        <button onclick="closeModal('domainsModal')" class="text-slate-400 hover:text-white">✕</button>
      </div>
      <p id="txtDomainsModalDesc" class="text-xs text-slate-400 leading-relaxed">هر دامنه را در یک خط وارد کنید. این دامنه‌ها مستقیماً و بدون مصرف حجم فیلترشکن باز می‌شوند.</p>
      <textarea id="domainsTextarea" rows="10" class="w-full p-3 rounded-2xl bg-slate-950 border border-slate-700 text-xs font-mono text-emerald-400 focus:outline-none focus:border-indigo-500 ltr-only"></textarea>
      <div class="flex justify-end gap-2">
        <button id="btnDomainsCancel" onclick="closeModal('domainsModal')" class="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-semibold">انصراف</button>
        <button id="btnDomainsSave" onclick="saveDirectDomains()" class="px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-lg shadow-emerald-600/30">ذخیره و اعمال فوری</button>
      </div>
    </div>
  </div>

  <!-- 4. Telegram Alerts Modal -->
  <div id="telegramModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 max-w-md w-full space-y-4">
      <div class="flex items-center justify-between">
        <h4 id="txtTgModalTitle" class="font-bold text-base text-white">تنظیمات ربات تلگرام</h4>
        <button onclick="closeModal('telegramModal')" class="text-slate-400 hover:text-white">✕</button>
      </div>
      <form onsubmit="handleSaveTelegram(event)" class="space-y-4">
        <div class="flex items-center gap-2">
          <input type="checkbox" id="tgEnabled" class="w-4 h-4 accent-indigo-600 rounded">
          <label for="tgEnabled" id="lblTgEnabled" class="text-xs font-semibold text-white">فعال‌سازی هشدارهای تلگرام (تغییر تونل و مصرف حجم)</label>
        </div>
        <div>
          <label id="lblTgToken" class="block text-xs font-semibold text-slate-300 mb-1">Telegram Bot Token</label>
          <input type="text" id="tgBotToken" placeholder="123456789:ABCdef..." class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-indigo-500 ltr-only">
        </div>
        <div>
          <label id="lblTgChatId" class="block text-xs font-semibold text-slate-300 mb-1">Your Telegram Chat ID</label>
          <input type="text" id="tgChatId" placeholder="123456789" class="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-indigo-500 ltr-only">
        </div>
        <div class="flex gap-2">
          <button type="button" id="btnTgTest" onclick="testTelegramAlert()" class="flex-1 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 font-semibold text-xs border border-slate-700">تست ارسال پیام</button>
          <button type="submit" id="btnTgSave" class="flex-1 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg shadow-indigo-600/30">ذخیره تنظیمات</button>
        </div>
      </form>
    </div>
  </div>

  <!-- 5. Diagnostics Modal -->
  <div id="diagModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-3xl p-6 sm:p-8 max-w-4xl w-full space-y-4 max-h-[90vh] flex flex-col">
      <div class="flex items-center justify-between">
        <h4 id="txtDiagModalTitle" class="font-bold text-base text-white">عیب‌یابی ترافیک و لاگ‌های زنده Xray</h4>
        <button onclick="closeModal('diagModal')" class="text-slate-400 hover:text-white">✕</button>
      </div>
      <div class="flex justify-between items-center gap-4">
        <button id="btnDiagCopy" onclick="copyRedactedReport()" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold">کپی گزارش عیب‌یابی (Sanitized)</button>
        <button id="btnDiagRefresh" onclick="loadDiagLogs()" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300">بروزرسانی لاگ‌ها</button>
      </div>
      <div id="diagLogBox" class="flex-1 overflow-y-auto bg-slate-950 p-4 rounded-2xl border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1 ltr-only max-h-96">
        در حال بارگذاری...
      </div>
    </div>
  </div>

  <!-- 6. Backup & Restore Modal -->
  <div id="backupModal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
    <div class="glass-card max-w-lg w-full p-6 rounded-3xl border border-slate-700 shadow-2xl space-y-5">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <h3 id="txtBackupModalTitle" class="font-bold text-base text-white flex items-center gap-2">
          <svg class="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>
          <span>پشتیبان‌گیری و بازیابی تنظیمات</span>
        </h3>
        <button onclick="closeModal('backupModal')" class="text-slate-400 hover:text-white text-lg">✕</button>
      </div>

      <div class="space-y-4">
        <!-- Export Section -->
        <div class="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-2">
          <h4 id="lblBackupExportTitle" class="text-xs font-bold text-slate-200">دریافت نسخه پشتیبان (Export)</h4>
          <p id="lblBackupExportDesc" class="text-xs text-slate-400">یک فایل JSON شامل تمام اعضای خانواده، تنظیمات ترافیک، کد دعوت، و دامنه‌های مستقیم دانلود کنید.</p>
          <button onclick="downloadBackupFile()" class="w-full py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs transition flex items-center justify-center gap-2 shadow-lg shadow-purple-600/30">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            <span id="btnDownloadBackupText">دانلود فایل پشتیبان (.json)</span>
          </button>
        </div>

        <!-- Restore Section -->
        <div class="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-2">
          <h4 id="lblBackupRestoreTitle" class="text-xs font-bold text-slate-200">بازیابی تنظیمات (Restore)</h4>
          <p id="lblBackupRestoreDesc" class="text-xs text-slate-400">فایل پشتیبان JSON را انتخاب کرده یا متن آن را در کادر زیر قرار دهید:</p>
          <input type="file" id="backupFileInput" accept=".json" class="hidden" onchange="handleBackupFileSelect(event)">
          <div class="flex gap-2">
            <button type="button" onclick="document.getElementById('backupFileInput').click()" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition">
              <span id="btnSelectFileText">انتخاب فایل...</span>
            </button>
            <span id="selectedFileName" class="text-xs text-slate-400 self-center truncate"></span>
          </div>
          <textarea id="restoreJsonTextarea" rows="3" placeholder="{ ... }" class="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-500 ltr-only"></textarea>
          <button type="button" onclick="executeRestore()" id="btnExecuteRestore" class="w-full py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/30">
            <span id="btnRestoreText">اعمال و بازیابی داده‌ها</span>
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- 7. Portal QR Modal -->
  <div id="portalQrModal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
    <div class="glass-card max-w-sm w-full p-6 rounded-3xl border border-slate-700 shadow-2xl text-center space-y-4">
      <div class="flex items-center justify-between border-b border-slate-800 pb-2">
        <h3 id="txtPortalQrTitle" class="font-bold text-sm text-white">بارکد QR پورتال و ثبت‌نام</h3>
        <button onclick="closeModal('portalQrModal')" class="text-slate-400 hover:text-white text-lg">✕</button>
      </div>

      <!-- Tab for Public vs LAN -->
      <div class="flex rounded-xl bg-slate-900 p-1 text-xs">
        <button onclick="switchPortalQr('public')" id="btnQrTabPublic" class="flex-1 py-1.5 rounded-lg bg-indigo-600 text-white font-bold transition">آدرس عمومی (اینترنت)</button>
        <button onclick="switchPortalQr('lan')" id="btnQrTabLan" class="flex-1 py-1.5 rounded-lg text-slate-400 font-bold transition">وای‌فای خانه (LAN)</button>
      </div>

      <div class="bg-white p-3 rounded-2xl inline-block shadow-lg mx-auto">
        <img id="portalQrImg" src="" alt="Portal QR" class="w-48 h-48 block">
      </div>

      <div class="space-y-1">
        <div id="portalQrUrl" class="font-mono text-[11px] text-indigo-300 truncate bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-800 ltr-only"></div>
        <p id="portalQrDesc" class="text-[11px] text-slate-400">با دوربین موبایل اسکن کنید تا مستقیماً به صفحه ثبت‌نام متصل شوید.</p>
      </div>
    </div>
  </div>

  <script>
    const i18nAdmin = {{
      fa: {{
        docTitle: 'مرکز مدیریت فیلترشکن خانواده | Admin Control Center',
        adminTitle: 'مرکز مدیریت فیلترشکن خانواده',
        adminSub: 'دید پرنده، مدیریت کاربران، و بای‌پس تک‌کلیک دامنه‌ها',
        adminRole: 'مدیر سیستم (Tohid)',
        btnDomains: 'دامنه‌های مستقیم',
        btnTelegram: 'هشدار تلگرام',
        btnDiag: 'عیب‌یابی',
        btnHelp: 'راهنما',
        btnBackup: 'پشتیبان‌گیری',
        langSwitch: 'English',
        logout: 'خروج',

        // Connection Banner
        connStatusTitle: 'وضعیت دسترسی و اشتراک‌گذاری سراسری',
        connStatusSub: 'آدرس‌های پورتال برای دسترسی محلی در خانه و اشتراک‌گذاری امن از راه دور',
        btnShareWhatsApp: 'اشتراک با واتس‌اپ',
        btnShareTelegram: 'اشتراک با تلگرام',
        btnPortalQr: 'بارکد QR',
        lblLocalHostTitle: 'آدرس محلی روی این لپ‌تاپ:',
        subLocalHost: 'مخصوص مرورگر همین دستگاه',
        lblLanTitle: 'آدرس وای‌فای خانگی (LAN):',
        subLanTitle: 'برای دستگاه‌های متصل به همین وای‌فای',
        lblPublicTunnelTitle: 'آدرس عمومی اینترنت (تونل ابری):',
        subPublicTunnel: 'قابل دسترسی از سراسر دنیا و ایران',

        // Backup Modal
        backupModalTitle: 'پشتیبان‌گیری و بازیابی تنظیمات',
        lblBackupExportTitle: 'دریافت نسخه پشتیبان (Export)',
        lblBackupExportDesc: 'یک فایل JSON شامل تمام اعضای خانواده، تنظیمات ترافیک، کد دعوت، و دامنه‌های مستقیم دانلود کنید.',
        btnDownloadBackupText: 'دانلود فایل پشتیبان (.json)',
        lblBackupRestoreTitle: 'بازیابی تنظیمات (Restore)',
        lblBackupRestoreDesc: 'فایل پشتیبان JSON را انتخاب کرده یا متن آن را در کادر زیر قرار دهید:',
        btnSelectFileText: 'انتخاب فایل...',
        btnRestoreText: 'اعمال و بازیابی داده‌ها',

        // Portal QR Modal
        portalQrTitle: 'بارکد QR پورتال و ثبت‌نام',
        portalQrTabPublic: 'آدرس عمومی (اینترنت)',
        portalQrTabLan: 'وای‌فای خانه (LAN)',
        portalQrDesc: 'با دوربین موبایل اسکن کنید تا مستقیماً به صفحه ثبت‌نام متصل شوید.',

        // KPI
        kpiTotalUsers: 'کل کاربران خانواده',
        kpiSubTotalUsers: 'حساب‌های فعال در سرور',
        kpiOnline: 'کاربران آنلاین در این لحظه',
        kpiSubOnline: 'ترافیک زنده ۱۵ دقیقه اخیر',
        kpiBandwidth: 'مجموع ترافیک خانواده',
        kpiWatchdog: 'سیستم خودترمیمی و تونل',
        kpiSubWatchdog: 'Cloudflare Quick Tunnel',

        // Invite Card
        inviteBadge: 'کد دعوت فعال خانواده',
        inviteTitle: 'کد دعوت:',
        btnEditInvite: 'ویرایش',
        inviteDesc: 'این لینک و کد را برای اعضای خانواده بفرستید تا بتوانند مستقیماً از گوشی ثبت‌نام کرده و اشتراک هوشمند دریافت کنند.',
        btnCopyInvite: 'کپی لینک دعوت و متن آماده',

        // Automated Clean Edge IP Optimizer
        cfIpBadge: 'بهینه‌سازی خودکار سرعت و Clean Edge IP',
        cfIpTitle: 'آی‌پی کلودفلر فعال (پروفایل ۱):',
        cfIpDesc: 'اسکنر هوشمند هر ۱۵ دقیقه پینگ و پایداری ۲۴ آی‌پی Anycast کلودفلر را بررسی کرده و سریع‌ترین آی‌پی را به عنوان پروفایل شماره ۱ به اشتراک‌های خانواده ارتقا می‌دهد.',
        lblAutoOptimizeText: 'بهینه‌سازی خودکار (هر ۱۵ دقیقه)',
        lblLastScanText: 'آخرین اسکن:',
        btnScanNowText: 'اسکن و ارتقای فوری',
        btnSaveCfIpText: 'ثبت دستی',
        btnResetCfIpText: 'بازنشانی به خودکار',

        // Failing Domains
        failingTitle: 'شناسایی دامنه‌های دچار اختلال یا نشتی به ایرلند',
        failingSub: 'دامنه‌های ایرانی که اشتباهاً از فیلترشکن رد شده‌اند یا ارتباط با آن‌ها با خطا روبرو شده است. با یک کلیک آن‌ها را به مسیر مستقیم ایران اضافه کنید.',
        btnRefreshFailing: 'بروزرسانی زنده',
        thFailDomain: 'دامنه مقصد (Domain)',
        thFailHits: 'تعداد مراجعه (Hits)',
        thFailUsers: 'کاربران مراجعه‌کننده',
        thFailReason: 'علت شناسایی',
        thFailAction: 'عملیات',
        emptyFailing: 'هیچ دامنه مسدود یا نشت‌کرده‌ای ثبت نشده است. سیستم کاملاً سالم است!',
        btnBypassText: '+ افزودن به لیست مستقیم ایران',
        btnBypassedText: '✓ در لیست مستقیم',

        // User Management
        usersTitle: 'مدیریت اعضای خانواده و اشتراک‌ها',
        usersSub: 'مشاهده حجم، وضعیت آنلاین، کپی لینک اشتراک و مدیریت ترافیک',
        btnAddMember: '+ تعریف عضو جدید',
        thUserName: 'نام و حساب',
        thUserStatus: 'وضعیت زنده',
        thUserUsage: 'حجم مصرفی / سقف',
        thUserExpiry: 'تاریخ انقضا',
        thUserActions: 'عملیات',
        emptyUsers: 'هیچ کاربری یافت نشد. دکمه تعریف عضو جدید را بزنید.',
        badgeOnline: 'آنلاین',
        badgeOffline: 'آفلاین',
        btnQr: 'کد QR',
        btnCopyLink: 'کپی لینک',
        btnResetTraffic: 'ریست مصرف',
        btnDelete: 'حذف',

        // Modals
        addModalTitle: 'افزودن عضو جدید خانواده',
        lblAddName: 'نام یا ایمیل',
        phAddName: 'مثال: Javad',
        lblAddQuota: 'سقف حجم مجاز (گیگابایت - ۰ برای نامحدود)',
        lblAddExpiry: 'مدت اعتبار (روز - ۰ برای دائمی)',
        btnAddSubmit: 'ایجاد حساب و صدور لینک',

        qrModalTitle: 'اشتراک اختصاصی کاربر',
        btnModalCopySub: 'کپی لینک اشتراک',
        btnModalCopyGuide: 'کپی متن راهنما',

        domainsModalTitle: 'ویرایش دامنه‌های مستقیم ایران (Direct Bypass)',
        domainsModalDesc: 'هر دامنه را در یک خط وارد کنید. این دامنه‌ها مستقیماً و بدون مصرف حجم فیلترشکن باز می‌شوند.',
        btnDomainsCancel: 'انصراف',
        btnDomainsSave: 'ذخیره و اعمال فوری',

        tgModalTitle: 'تنظیمات ربات تلگرام',
        lblTgEnabled: 'فعال‌سازی هشدارهای تلگرام (تغییر تونل و مصرف حجم)',
        lblTgToken: 'Telegram Bot Token',
        lblTgChatId: 'Your Telegram Chat ID',
        btnTgTest: 'تست ارسال پیام',
        btnTgSave: 'ذخیره تنظیمات',

        diagModalTitle: 'عیب‌یابی ترافیک و لاگ‌های زنده Xray',
        btnDiagCopy: 'کپی گزارش عیب‌یابی (Sanitized)',
        btnDiagRefresh: 'بروزرسانی لاگ‌ها',
        diagLoading: 'در حال خواندن لاگ‌های زنده Xray...'
      }},
      en: {{
        docTitle: 'Family VPN Admin Center | Home VPN Platform',
        adminTitle: 'Family VPN Admin Center',
        adminSub: "Bird's-eye view, family accounts & one-click domain bypass",
        adminRole: 'System Administrator (Tohid)',
        btnDomains: 'Direct Domains',
        btnTelegram: 'Telegram Alerts',
        btnDiag: 'Diagnostics',
        btnHelp: 'Help & Guide',
        btnBackup: 'Backup & Restore',
        langSwitch: 'فارسی',
        logout: 'Logout',

        // Connection Banner
        connStatusTitle: 'Global Access & Sharing Status',
        connStatusSub: 'Portal URLs for local home network access and secure remote sharing',
        btnShareWhatsApp: 'Share via WhatsApp',
        btnShareTelegram: 'Share via Telegram',
        btnPortalQr: 'QR Code',
        lblLocalHostTitle: 'Localhost URL (This Device):',
        subLocalHost: 'For browser on this laptop',
        lblLanTitle: 'Home Wi-Fi LAN IP:',
        subLanTitle: 'For devices on your home Wi-Fi',
        lblPublicTunnelTitle: 'Public Cloudflare Tunnel:',
        subPublicTunnel: 'Accessible globally and from Iran',

        // Backup Modal
        backupModalTitle: 'Settings Backup & Restore',
        lblBackupExportTitle: 'Export Settings Backup',
        lblBackupExportDesc: 'Download a JSON file containing all family members, settings, invite code, and custom direct domains.',
        btnDownloadBackupText: 'Download Backup (.json)',
        lblBackupRestoreTitle: 'Restore Settings Backup',
        lblBackupRestoreDesc: 'Select a JSON backup file or paste its content below:',
        btnSelectFileText: 'Select File...',
        btnRestoreText: 'Execute Restore',

        // Portal QR Modal
        portalQrTitle: 'Portal Access & Signup QR Code',
        portalQrTabPublic: 'Public Tunnel URL',
        portalQrTabLan: 'Home Wi-Fi (LAN)',
        portalQrDesc: 'Scan with your mobile camera to open the signup page directly.',

        // KPI
        kpiTotalUsers: 'Total Family Members',
        kpiSubTotalUsers: 'Active accounts on server',
        kpiOnline: 'Currently Online Users',
        kpiSubOnline: 'Active traffic in last 15 mins',
        kpiBandwidth: 'Total Family Bandwidth',
        kpiWatchdog: 'Tunnel & Self-Healing Watchdog',
        kpiSubWatchdog: 'Cloudflare Quick Tunnel',

        // Invite Card
        inviteBadge: 'Active Family Invite Code',
        inviteTitle: 'Invite Code:',
        btnEditInvite: 'Edit',
        inviteDesc: 'Share this link and invite code with family members so they can register and get a ready-to-use VPN profile with zero setup.',
        btnCopyInvite: 'Copy Invite Link & Instructions',

        // Automated Clean Edge IP Optimizer
        cfIpBadge: 'Automated Clean Edge IP & Speed Optimizer',
        cfIpTitle: 'Active Cloudflare Edge IP (Profile #1):',
        cfIpDesc: 'Background worker scans 24 Cloudflare Anycast edge IPs every 15 minutes, auto-promoting the lowest-latency edge IP as Profile #1 for family subscriptions.',
        lblAutoOptimizeText: 'Auto-Optimize (Every 15m)',
        lblLastScanText: 'Last Scan:',
        btnScanNowText: 'Scan & Promote Now',
        btnSaveCfIpText: 'Save Manual',
        btnResetCfIpText: 'Reset to Auto',

        // Failing Domains
        failingTitle: 'Detected Blocked, Failing & Leaked Domains',
        failingSub: 'Iranian services leaking through the European proxy or failing connections. Click to add them to the Iran Direct split-tunneling list instantly.',
        btnRefreshFailing: 'Refresh List',
        thFailDomain: 'Destination Domain',
        thFailHits: 'Hits',
        thFailUsers: 'Affected Users',
        thFailReason: 'Detection Reason',
        thFailAction: 'Action',
        emptyFailing: 'No failing or leaking domains detected. Everything is routing smoothly!',
        btnBypassText: '+ Add to Iran Direct List',
        btnBypassedText: '✓ Added to Direct',

        // User Management
        usersTitle: 'Family Members & Subscription Management',
        usersSub: 'Monitor data usage, online status, copy subscription URLs, and manage quotas.',
        btnAddMember: '+ Add Family Member',
        thUserName: 'Name & Account',
        thUserStatus: 'Live Status',
        thUserUsage: 'Data Used / Quota',
        thUserExpiry: 'Expiration',
        thUserActions: 'Actions',
        emptyUsers: 'No users found. Click Add Family Member to create one.',
        badgeOnline: 'Online',
        badgeOffline: 'Offline',
        btnQr: 'QR Code',
        btnCopyLink: 'Copy Link',
        btnResetTraffic: 'Reset Usage',
        btnDelete: 'Delete',

        // Modals
        addModalTitle: 'Add New Family Member',
        lblAddName: 'Name or Username',
        phAddName: 'e.g. Javad',
        lblAddQuota: 'Data Limit (GB - 0 for unlimited)',
        lblAddExpiry: 'Validity Period (Days - 0 for never)',
        btnAddSubmit: 'Create Account & Provision',

        qrModalTitle: 'User Subscription Profile',
        btnModalCopySub: 'Copy Subscription Link',
        btnModalCopyGuide: 'Copy Setup Guide',

        domainsModalTitle: 'Edit Iran Direct Bypass Domains',
        domainsModalDesc: 'Enter one domain per line. These domains will bypass the proxy and route directly via local Iranian internet.',
        btnDomainsCancel: 'Cancel',
        btnDomainsSave: 'Save & Apply Instantly',

        tgModalTitle: 'Telegram Bot Alert Settings',
        lblTgEnabled: 'Enable Telegram Alerts (Tunnel IP updates & 80% Quota warnings)',
        lblTgToken: 'Telegram Bot Token',
        lblTgChatId: 'Your Telegram Chat ID',
        btnTgTest: 'Send Test Alert',
        btnTgSave: 'Save Settings',

        diagModalTitle: 'Traffic Diagnostics & Live Xray Logs',
        btnDiagCopy: 'Copy Redacted Report',
        btnDiagRefresh: 'Refresh Logs',
        diagLoading: 'Loading live Xray logs...'
      }}
    }};

    let currentLang = 'fa';
    let clientsData = [];
    let failingDomainsData = [];
    let currentInviteCode = 'IR-FAMILY';
    let currentShareableLink = '';
    let currentModalGuide = '';

    function setLanguage(lang) {{
      currentLang = (lang === 'en' || lang === 'fa') ? lang : 'fa';
      localStorage.setItem('vpn_lang', currentLang);
      const isRtl = (currentLang === 'fa');

      document.documentElement.setAttribute('lang', currentLang);
      document.documentElement.setAttribute('dir', isRtl ? 'rtl' : 'ltr');

      const dict = i18nAdmin[currentLang];
      const docT = document.getElementById('docTitle');
      if (docT) docT.textContent = dict.docTitle;
      document.title = dict.docTitle;

      const setTxt = (id, val) => {{
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      }};

      setTxt('txtAdminTitle', dict.adminTitle);
      setTxt('txtAdminSub', dict.adminSub);
      setTxt('txtAdminRoleBadge', dict.adminRole);
      setTxt('txtBtnDomains', dict.btnDomains);
      setTxt('txtBtnTelegram', dict.btnTelegram);
      setTxt('txtBtnDiag', dict.btnDiag);
      setTxt('langSwitchLabel', dict.langSwitch);
      setTxt('txtAdminLogout', dict.logout);

      setTxt('kpiLblTotalUsers', dict.kpiTotalUsers);
      setTxt('kpiSubTotalUsers', dict.kpiSubTotalUsers);
      setTxt('kpiLblOnline', dict.kpiOnline);
      setTxt('kpiSubOnline', dict.kpiSubOnline);
      setTxt('kpiLblBandwidth', dict.kpiBandwidth);
      setTxt('kpiLblWatchdog', dict.kpiWatchdog);
      setTxt('kpiSubWatchdog', dict.kpiSubWatchdog);

      setTxt('txtInviteBadge', dict.inviteBadge);
      setTxt('lblInviteTitle', dict.inviteTitle);
      setTxt('btnEditInvite', dict.btnEditInvite);
      setTxt('txtInviteDesc', dict.inviteDesc);
      setTxt('btnCopyInviteText', dict.btnCopyInvite);

      setTxt('txtFailingTitle', dict.failingTitle);
      setTxt('txtFailingSub', dict.failingSub);
      setTxt('txtBtnRefreshFailing', dict.btnRefreshFailing);
      setTxt('thFailDomain', dict.thFailDomain);
      setTxt('thFailHits', dict.thFailHits);
      setTxt('thFailUsers', dict.thFailUsers);
      setTxt('thFailReason', dict.thFailReason);
      setTxt('thFailAction', dict.thFailAction);

      setTxt('txtUsersTitle', dict.usersTitle);
      setTxt('txtUsersSub', dict.usersSub);
      setTxt('txtBtnAddMember', dict.btnAddMember);
      setTxt('thUserName', dict.thUserName);
      setTxt('thUserStatus', dict.thUserStatus);
      setTxt('thUserUsage', dict.thUserUsage);
      setTxt('thUserExpiry', dict.thUserExpiry);
      setTxt('thUserActions', dict.thUserActions);

      setTxt('txtAddModalTitle', dict.addModalTitle);
      setTxt('lblAddName', dict.lblAddName);
      const inAddName = document.getElementById('addName');
      if (inAddName) inAddName.placeholder = dict.phAddName;
      setTxt('lblAddQuota', dict.lblAddQuota);
      setTxt('lblAddExpiry', dict.lblAddExpiry);
      setTxt('btnAddSubmit', dict.btnAddSubmit);

      setTxt('qrModalTitle', dict.qrModalTitle);
      setTxt('btnModalCopySub', dict.btnModalCopySub);
      setTxt('btnModalCopyGuide', dict.btnModalCopyGuide);

      setTxt('txtDomainsModalTitle', dict.domainsModalTitle);
      setTxt('txtDomainsModalDesc', dict.domainsModalDesc);
      setTxt('btnDomainsCancel', dict.btnDomainsCancel);
      setTxt('btnDomainsSave', dict.btnDomainsSave);

      setTxt('txtTgModalTitle', dict.tgModalTitle);
      setTxt('lblTgEnabled', dict.lblTgEnabled);
      setTxt('lblTgToken', dict.lblTgToken);
      setTxt('lblTgChatId', dict.lblTgChatId);
      setTxt('btnTgTest', dict.btnTgTest);
      setTxt('btnTgSave', dict.btnTgSave);

      setTxt('txtDiagModalTitle', dict.diagModalTitle);
      setTxt('btnDiagCopy', dict.btnDiagCopy);
      setTxt('btnDiagRefresh', dict.btnDiagRefresh);

      setTxt('txtCfIpBadge', dict.cfIpBadge);
      setTxt('lblCfIpTitle', dict.cfIpTitle);
      setTxt('txtCfIpDesc', dict.cfIpDesc);
      setTxt('lblAutoOptimizeText', dict.lblAutoOptimizeText);
      setTxt('lblLastScanText', dict.lblLastScanText);
      setTxt('btnScanNowText', dict.btnScanNowText);
      setTxt('btnSaveCfIpText', dict.btnSaveCfIpText);
      setTxt('btnResetCfIpText', dict.btnResetCfIpText);

      setTxt('txtBtnHelp', dict.btnHelp);
      setTxt('txtBtnBackup', dict.btnBackup);
      setTxt('txtConnStatusTitle', dict.connStatusTitle);
      setTxt('txtConnStatusSub', dict.connStatusSub);
      setTxt('btnShareWhatsApp', dict.btnShareWhatsApp);
      setTxt('btnShareTelegram', dict.btnShareTelegram);
      setTxt('btnPortalQr', dict.btnPortalQr);
      setTxt('lblLocalHostTitle', dict.lblLocalHostTitle);
      setTxt('subLocalHost', dict.subLocalHost);
      setTxt('lblLanTitle', dict.lblLanTitle);
      setTxt('subLanTitle', dict.subLanTitle);
      setTxt('lblPublicTunnelTitle', dict.lblPublicTunnelTitle);
      setTxt('subPublicTunnel', dict.subPublicTunnel);

      setTxt('txtBackupModalTitle', dict.backupModalTitle);
      setTxt('lblBackupExportTitle', dict.lblBackupExportTitle);
      setTxt('lblBackupExportDesc', dict.lblBackupExportDesc);
      setTxt('btnDownloadBackupText', dict.btnDownloadBackupText);
      setTxt('lblBackupRestoreTitle', dict.lblBackupRestoreTitle);
      setTxt('lblBackupRestoreDesc', dict.lblBackupRestoreDesc);
      setTxt('btnSelectFileText', dict.btnSelectFileText);
      setTxt('btnRestoreText', dict.btnRestoreText);

      setTxt('txtPortalQrTitle', dict.portalQrTitle);
      setTxt('btnQrTabPublic', dict.portalQrTabPublic);
      setTxt('btnQrTabLan', dict.portalQrTabLan);
      setTxt('portalQrDesc', dict.portalQrDesc);

      // Re-render dynamic lists with new language
      if (clientsData && clientsData.length > 0) {{
        renderClientsTable(clientsData);
      }}
      if (failingDomainsData && failingDomainsData.length > 0) {{
        renderFailingDomainsTable(failingDomainsData);
      }}
    }}

    function toggleLang() {{
      const nextLang = (currentLang === 'fa') ? 'en' : 'fa';
      setLanguage(nextLang);
      try {{
        const url = new URL(window.location);
        url.searchParams.set('lang', nextLang);
        window.history.replaceState({{}}, '', url);
      }} catch (e) {{}}
    }}

    function closeModal(id) {{
      document.getElementById(id).classList.add('hidden');
    }}
    function openModal(id) {{
      document.getElementById(id).classList.remove('hidden');
    }}

    async function fetchAdminOverview() {{
      try {{
        const res = await fetch('/api/admin/overview');
        if (res.status === 401) {{
          window.location.href = '/?mode=login&need=admin';
          return;
        }}
        const d = await res.json();
        document.getElementById('kpiValTotalUsers').textContent = d.total_users;
        document.getElementById('kpiValOnline').textContent = d.online_users;
        document.getElementById('kpiValBandwidth').textContent = d.total_bandwidth_str;
        document.getElementById('kpiValUp').textContent = d.total_up_str;
        document.getElementById('kpiValDown').textContent = d.total_down_str;
        document.getElementById('kpiValWatchdog').textContent = d.watchdog_status;
        
        currentInviteCode = d.invite_code;
        currentShareableLink = d.shareable_invite_url;
        currentLocalUrl = d.local_portal_url || ('http://127.0.0.1:' + (d.portal_port || 8080));
        currentLanUrl = d.lan_portal_url || currentLocalUrl;
        currentPublicUrl = d.portal_url || '';

        document.getElementById('txtCurrentInviteCode').textContent = d.invite_code;
        const autoOpt = (d.cf_auto_optimize !== false);
        const chkAuto = document.getElementById('chkCfAutoOptimize');
        if (chkAuto) chkAuto.checked = autoOpt;

        document.getElementById('txtActiveCfIp').textContent = d.cf_active_edge_ip || '104.16.132.229';

        if (autoOpt) {{
          document.getElementById('txtCfIpType').textContent = (currentLang === 'fa' ? 'ارتقای خودکار' : 'Auto-Promoted');
          document.getElementById('txtCfIpType').className = 'text-[10px] text-emerald-300 bg-emerald-950/80 px-2 py-0.5 rounded-lg border border-emerald-700/60 font-semibold';
          document.getElementById('txtCfLatency').textContent = d.cf_latency_ms ? (d.cf_latency_ms + ' ms') : '-- ms';
          document.getElementById('txtCfLatency').className = 'text-[10px] text-cyan-300 bg-cyan-950/80 px-2 py-0.5 rounded-lg border border-cyan-700/60 font-mono';
        }} else if (d.cf_ip_override) {{
          document.getElementById('txtActiveCfIp').textContent = d.cf_ip_override;
          document.getElementById('txtCfIpType').textContent = (currentLang === 'fa' ? 'شخصی‌سازی دستی' : 'Manual Override');
          document.getElementById('txtCfIpType').className = 'text-[10px] text-amber-300 bg-amber-950/80 px-2 py-0.5 rounded-lg border border-amber-700/60 font-semibold';
          document.getElementById('txtCfLatency').textContent = '-- ms';
        }} else {{
          document.getElementById('txtCfIpType').textContent = (currentLang === 'fa' ? 'پیش‌فرض Anycast' : 'Default Anycast');
          document.getElementById('txtCfIpType').className = 'text-[10px] text-cyan-300 bg-cyan-950/80 px-2 py-0.5 rounded-lg border border-cyan-700/60 font-semibold';
          document.getElementById('txtCfLatency').textContent = '-- ms';
        }}
        document.getElementById('inpCfIpOverride').value = d.cf_ip_override || '';
        document.getElementById('txtCfLastScan').textContent = d.cf_last_scan_time || 'Never';
        document.getElementById('valLocalUrl').textContent = currentLocalUrl;
        document.getElementById('valLanUrl').textContent = currentLanUrl;
        document.getElementById('valPublicUrl').textContent = currentPublicUrl || (currentLang === 'fa' ? 'در حال برقراری ارتباط...' : 'Connecting...');
      }} catch (e) {{
        console.error('Fetch overview error:', e);
      }}
    }}

    async function fetchClients() {{
      try {{
        const res = await fetch('/api/clients');
        const d = await res.json();
        clientsData = d.clients || [];
        renderClientsTable(clientsData);
      }} catch (e) {{
        console.error('Fetch clients error:', e);
      }}
    }}

    function renderClientsTable(list) {{
      const tbody = document.getElementById('clientsTableBody');
      if (!tbody) return;
      if (!list || list.length === 0) {{
        tbody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-slate-500">${{i18nAdmin[currentLang].emptyUsers}}</td></tr>`;
        return;
      }}

      const badgeOnlineTxt = i18nAdmin[currentLang].badgeOnline;
      const badgeOfflineTxt = i18nAdmin[currentLang].badgeOffline;
      const btnQrTxt = i18nAdmin[currentLang].btnQr;
      const btnCopyTxt = i18nAdmin[currentLang].btnCopyLink;
      const btnResetTxt = i18nAdmin[currentLang].btnResetTraffic;
      const btnDelTxt = i18nAdmin[currentLang].btnDelete;

      tbody.innerHTML = list.map(c => {{
        const onlineBadge = c.is_online
          ? `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>${{badgeOnlineTxt}}</span>`
          : `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">${{badgeOfflineTxt}}</span>`;

        const lastSeen = (currentLang === 'fa' ? c.last_seen_fa : c.last_seen_en) || '-';
        const limitLabel = (c.limit_bytes > 0) ? c.limit_str : (currentLang === 'fa' ? 'نامحدود' : 'Unlimited');

        return `
          <tr class="hover:bg-slate-900/40 transition">
            <td class="p-4 text-start">
              <div class="font-bold text-white text-xs">${{c.email}}</div>
              <div class="text-[10px] text-slate-500 font-mono mt-0.5">${{c.id.substring(0, 8)}}...</div>
            </td>
            <td class="p-4 text-center">
              <div>${{onlineBadge}}</div>
              <div class="text-[10px] text-slate-500 mt-1">${{lastSeen}}</div>
            </td>
            <td class="p-4 text-start">
              <div class="font-bold text-slate-200 text-xs">${{c.total_used_str}} / <span class="text-slate-500 font-normal">${{limitLabel}}</span></div>
              <div class="text-[10px] text-slate-500 font-mono">↑ ${{c.up_str}} | ↓ ${{c.down_str}}</div>
            </td>
            <td class="p-4 text-xs text-slate-400 text-start">${{c.expiry_str}}</td>
            <td class="p-4 text-center">
              <div class="inline-flex items-center gap-1.5 flex-wrap justify-center">
                <button onclick="openClientQr('${{c.id}}')" class="px-2.5 py-1.5 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 text-[11px] font-semibold transition">${{btnQrTxt}}</button>
                <button onclick="copyClientSub('${{c.smart_sub_link}}')" class="px-2.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-semibold transition">${{btnCopyTxt}}</button>
                <button onclick="resetClientTraffic('${{c.email}}')" class="px-2.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[11px] font-semibold transition">${{btnResetTxt}}</button>
                <button onclick="deleteClient('${{c.id}}', '${{c.email}}')" class="px-2.5 py-1.5 rounded-xl bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/80 text-[11px] font-semibold transition">${{btnDelTxt}}</button>
              </div>
            </td>
          </tr>
        `;
      }}).join('');
    }}

    async function fetchFailingDomains() {{
      try {{
        const res = await fetch('/api/admin/failing-domains');
        const d = await res.json();
        failingDomainsData = d.domains || [];
        renderFailingDomainsTable(failingDomainsData);
      }} catch (e) {{
        console.error('Fetch failing domains error:', e);
      }}
    }}

    function renderFailingDomainsTable(list) {{
      const badge = document.getElementById('badgeFailingCount');
      if (badge) {{
        badge.textContent = list.length + (currentLang === 'fa' ? ' دامنه' : ' domains');
      }}

      const tbody = document.getElementById('failingDomainsBody');
      if (!tbody) return;
      if (!list || list.length === 0) {{
        tbody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-slate-500">${{i18nAdmin[currentLang].emptyFailing}}</td></tr>`;
        return;
      }}

      const btnBypass = i18nAdmin[currentLang].btnBypassText;
      const btnBypassed = i18nAdmin[currentLang].btnBypassedText;

      tbody.innerHTML = list.map((item, idx) => {{
        const isDirect = item.is_direct;
        const btnAction = isDirect
          ? `<span class="inline-flex items-center gap-1 px-3 py-1.5 rounded-xl bg-emerald-950/80 text-emerald-400 border border-emerald-800 text-[11px] font-bold">${{btnBypassed}}</span>`
          : `<button id="btnBypass_${{idx}}" onclick="addSingleDirectDomain('${{item.domain}}', 'btnBypass_${{idx}}')" class="px-3.5 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-[11px] shadow-sm shadow-indigo-600/30 transition flex items-center gap-1.5">
              <span>${{btnBypass}}</span>
            </button>`;

        const translatedReasons = item.reasons.map(r => {{
          if (r.includes('iran_leak') || r.includes('Iranian') || r.includes('نشتی')) {{
            return currentLang === 'fa' ? 'نشتی ترافیک ایران به خارج' : 'Iranian Traffic Leaked to Ireland';
          }}
          if (r.includes('rejected') || r.includes('رد شده') || r.includes('مسدود')) {{
            return currentLang === 'fa' ? 'اتصال مسدود یا رد شد' : 'Connection Blocked / Rejected';
          }}
          if (r.includes('timeout') || r.includes('تایم‌اوت')) {{
            return currentLang === 'fa' ? 'خطای تایم‌اوت شبکه' : 'Connection Timeout';
          }}
          return r;
        }}).join(' | ');

        return `
          <tr class="hover:bg-slate-900/40 transition">
            <td class="p-4 font-mono font-bold text-white text-xs ltr-only text-start">${{item.domain}}</td>
            <td class="p-4 text-center font-mono font-bold text-indigo-400 text-xs">${{item.hits}}</td>
            <td class="p-4 text-slate-300 text-xs text-start">${{item.users.join(', ') || 'Client'}}</td>
            <td class="p-4 text-rose-300 text-xs font-semibold text-start">${{translatedReasons}}</td>
            <td class="p-4 text-center">${{btnAction}}</td>
          </tr>
        `;
      }}).join('');
    }}

    async function addSingleDirectDomain(domain, btnId) {{
      const btn = document.getElementById(btnId);
      if (btn) {{
        btn.disabled = true;
        btn.textContent = (currentLang === 'fa' ? 'در حال ذخیره...' : 'Saving...');
      }}
      try {{
        const res = await fetch('/api/admin/direct-domains/add', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ domain: domain }})
        }});
        if (res.ok) {{
          if (btn) {{
            btn.className = 'inline-flex items-center gap-1 px-3 py-1.5 rounded-xl bg-emerald-950/80 text-emerald-400 border border-emerald-800 text-[11px] font-bold';
            btn.innerHTML = (currentLang === 'fa' ? '✓ در لیست مستقیم' : '✓ Added to Direct');
          }}
          fetchFailingDomains();
        }} else {{
          alert(currentLang === 'fa' ? 'خطا در افزودن دامنه' : 'Failed to add domain');
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    function copyShareableInviteLink() {{
      const text = currentLang === 'fa'
        ? `🌟 لینک اختصاصی فیلترشکن خانواده:
${{currentShareableLink}}

کد دعوت: ${{currentInviteCode}}

وارد لینک شده و با وارد کردن کد دعوت، فیلترشکن پرسرعت خود را با یک کلیک دریافت کنید!`
        : `🌟 Family VPN Access Link:
${{currentShareableLink}}

Invite Code: ${{currentInviteCode}}

Open the link and enter your invite code to get your personal VPN profile!`;
      navigator.clipboard.writeText(text).then(() => {{
        alert(currentLang === 'fa' ? 'لینک دعوت اختصاصی همراه با متن راهنما کپی شد! می‌توانید آن را برای اعضای خانواده بفرستید.' : 'Invite link and instructions copied to clipboard!');
      }});
    }}

    async function editInviteCode() {{
      const promptMsg = currentLang === 'fa' ? 'کد دعوت جدید خانواده را وارد کنید:' : 'Enter new Family Invite Code:';
      const code = prompt(promptMsg, currentInviteCode);
      if (!code || !code.trim()) return;
      try {{
        const res = await fetch('/api/admin/invite-code', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ invite_code: code.trim() }})
        }});
        if (res.ok) {{
          alert(currentLang === 'fa' ? 'کد دعوت خانواده بروزرسانی شد!' : 'Family invite code updated successfully!');
          fetchAdminOverview();
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    async function toggleCfAutoOptimize(enabled) {{
      try {{
        const res = await fetch('/api/admin/cf-optimizer', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ auto_optimize: enabled }})
        }});
        if (res.ok) {{
          fetchAdminOverview();
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    async function triggerCfScanNow() {{
      const btn = document.getElementById('btnScanNow');
      const svg = document.getElementById('svgScanSpin');
      if (svg) svg.classList.add('animate-spin');
      if (btn) btn.disabled = true;
      try {{
        const res = await fetch('/api/admin/cf-optimizer/scan', {{ method: 'POST' }});
        if (res.ok) {{
          const d = await res.json();
          fetchAdminOverview();
          const msg = (currentLang === 'fa' 
            ? `اسکن با موفقیت انجام شد!\nسریع‌ترین آی‌پی: ${{d.active_ip}} (${{d.latency_ms}} ms)\nاین آی‌پی به عنوان پروفایل ۱ به تمام اشتراک‌ها ارتقا داده شد.`
            : `Scan complete!\nFastest IP: ${{d.active_ip}} (${{d.latency_ms}} ms)\nAuto-promoted as Profile #1 in all subscriptions.`);
          alert(msg);
        }}
      }} catch (e) {{
        alert('Scan error: ' + e);
      }} finally {{
        if (svg) svg.classList.remove('animate-spin');
        if (btn) btn.disabled = false;
      }}
    }}

    async function saveCfIpOverride() {{
      const ip = document.getElementById('inpCfIpOverride').value.trim();
      if (!ip) {{
        alert(currentLang === 'fa' ? 'لطفاً یک آی‌پی معتبر وارد کنید.' : 'Please enter a valid IP address.');
        return;
      }}
      try {{
        const res = await fetch('/api/admin/cf-optimizer', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ auto_optimize: false, override_ip: ip }})
        }});
        if (res.ok) {{
          alert(currentLang === 'fa' ? `آی‌پی دستی (${{ip}}) با موفقیت به عنوان مسیر اصلی ذخیره شد و در تمام لینک‌های اشتراک اعمال گردید!` : `Cloudflare IP (${{ip}}) saved and pushed to all subscription links!`);
          fetchAdminOverview();
        }} else {{
          const err = await res.json();
          alert('Error: ' + (err.detail || 'Failed to save'));
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    async function resetCfIpOverride() {{
      const confirmMsg = currentLang === 'fa' ? 'آیا مایل به بازگشت به بهینه‌سازی خودکار سریع‌ترین آی‌پی هستید؟' : 'Revert to automated lowest-latency IP optimizer?';
      if (!confirm(confirmMsg)) return;
      try {{
        const res = await fetch('/api/admin/cf-optimizer', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ auto_optimize: true, override_ip: '' }})
        }});
        if (res.ok) {{
          document.getElementById('inpCfIpOverride').value = '';
          fetchAdminOverview();
          alert(currentLang === 'fa' ? 'سیستم با موفقیت به حالت بهینه‌سازی خودکار بازگشت.' : 'Reverted to automated edge IP optimizer.');
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    function openAddMemberModal() {{
      openModal('addMemberModal');
    }}

    async function handleAddMember(e) {{
      e.preventDefault();
      const payload = {{
        name: document.getElementById('addName').value,
        limit_gb: parseFloat(document.getElementById('addLimitGb').value || 0),
        expiry_days: parseInt(document.getElementById('addExpiryDays').value || 0)
      }};
      try {{
        const res = await fetch('/api/clients', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(payload)
        }});
        if (res.ok) {{
          closeModal('addMemberModal');
          document.getElementById('addName').value = '';
          fetchClients();
          fetchAdminOverview();
        }} else {{
          const err = await res.json();
          alert('Error: ' + (err.detail || 'Failed to create'));
        }}
      }} catch (err) {{
        alert('Error: ' + err);
      }}
    }}

    function openClientQr(clientId) {{
      const c = clientsData.find(x => x.id === clientId);
      if (!c) return;
      document.getElementById('qrModalTitle').textContent = (currentLang === 'fa' ? 'اشتراک اختصاصی: ' : 'User Subscription: ') + c.email;
      document.getElementById('qrModalImg').src = 'data:image/png;base64,' + c.smart_qr_b64;
      document.getElementById('qrModalUrl').value = c.smart_sub_link;
      currentModalGuide = c.farsi_instructions;
      openModal('qrModal');
    }}

    function copyModalUrl() {{
      const el = document.getElementById('qrModalUrl');
      el.select();
      navigator.clipboard.writeText(el.value).then(() => {{
        alert(currentLang === 'fa' ? 'لینک اشتراک کپی شد!' : 'Subscription link copied to clipboard!');
      }});
    }}

    function copyModalFarsiGuide() {{
      if (currentModalGuide) {{
        navigator.clipboard.writeText(currentModalGuide).then(() => {{
          alert(currentLang === 'fa' ? 'متن راهنمای فارسی کپی شد!' : 'Farsi setup guide copied to clipboard!');
        }});
      }}
    }}

    function copyClientSub(url) {{
      navigator.clipboard.writeText(url).then(() => {{
        alert(currentLang === 'fa' ? 'لینک اشتراک کپی شد!' : 'Subscription link copied to clipboard!');
      }});
    }}

    async function resetClientTraffic(email) {{
      const confirmMsg = currentLang === 'fa' ? `آیا ترافیک مصرفی ${{email}} ریست شود؟` : `Reset bandwidth usage for ${{email}}?`;
      if (!confirm(confirmMsg)) return;
      try {{
        const res = await fetch(`/api/clients/${{email}}/reset`, {{ method: 'POST' }});
        if (res.ok) {{
          fetchClients();
          fetchAdminOverview();
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    async function deleteClient(id, email) {{
      const confirmMsg = currentLang === 'fa' ? `آیا مطمئن هستید که حساب ${{email}} حذف شود؟` : `Are you sure you want to delete ${{email}}?`;
      if (!confirm(confirmMsg)) return;
      try {{
        const res = await fetch(`/api/clients/${{id}}`, {{ method: 'DELETE' }});
        if (res.ok) {{
          fetchClients();
          fetchAdminOverview();
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    // Direct Domains Modal
    async function openDomainsModal() {{
      try {{
        const res = await fetch('/api/direct-domains');
        const data = await res.json();
        document.getElementById('domainsTextarea').value = (data.domains || []).join(String.fromCharCode(10));
        openModal('domainsModal');
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    async function saveDirectDomains() {{
      const text = document.getElementById('domainsTextarea').value;
      const list = text.split(String.fromCharCode(10)).map(d => d.trim()).filter(d => d);
      try {{
        const res = await fetch('/api/direct-domains', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ domains: list }})
        }});
        if (res.ok) {{
          alert(currentLang === 'fa' ? 'دامنه‌های مستقیم ذخیره و به اشتراک‌ها اعمال شدند!' : 'Direct domains saved and applied!');
          closeModal('domainsModal');
          fetchFailingDomains();
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    // Telegram Modal
    async function openTelegramModal() {{
      try {{
        const res = await fetch('/api/telegram');
        const d = await res.json();
        document.getElementById('tgEnabled').checked = d.enabled;
        document.getElementById('tgChatId').value = d.chat_id || '';
        document.getElementById('tgBotToken').placeholder = d.bot_token_masked || 'Enter Bot Token';
        openModal('telegramModal');
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    async function handleSaveTelegram(e) {{
      e.preventDefault();
      const payload = {{
        enabled: document.getElementById('tgEnabled').checked,
        bot_token: document.getElementById('tgBotToken').value,
        chat_id: document.getElementById('tgChatId').value
      }};
      try {{
        const res = await fetch('/api/telegram', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(payload)
        }});
        if (res.ok) {{
          alert(currentLang === 'fa' ? 'تنظیمات تلگرام ذخیره شد!' : 'Telegram settings saved!');
          closeModal('telegramModal');
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    async function testTelegramAlert() {{
      try {{
        const res = await fetch('/api/telegram/test', {{ method: 'POST' }});
        const d = await res.json();
        if (res.ok && d.success) {{
          alert(currentLang === 'fa' ? 'پیام تست به تلگرام شما ارسال شد! تلگرام خود را بررسی کنید.' : 'Test message sent to Telegram successfully!');
        }} else {{
          alert('Error: ' + (d.detail || d.message));
        }}
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

function copyToClipboard(text, btnId) {{
      if (!text) return;
      navigator.clipboard.writeText(text).then(() => {{
        const btn = document.getElementById(btnId);
        if (btn) {{
          const orig = btn.textContent;
          btn.textContent = (currentLang === 'fa' ? 'کپی شد!' : 'Copied!');
          setTimeout(() => {{ btn.textContent = orig; }}, 2000);
        }}
      }});
    }}

    function shareViaWhatsApp() {{
      const portalUrl = currentPublicUrl && currentPublicUrl.startsWith('https://') ? currentPublicUrl : (currentShareableLink || currentLanUrl);
      const text = currentLang === 'fa'
        ? `سلام! فیلترشکن اختصاصی و خانگی ما راه‌اندازی شد.
لینک پورتال و ثبت‌نام هوشمند:
${{portalUrl}}

کد دعوت خانوادگی: ${{currentInviteCode}}

پس از ثبت‌نام، لینک اشتراک اختصاصی خود را در اپلیکیشن‌های زیر وارد کنید:
• اندروید/ویندوز: Hiddify یا v2rayNG
• آیفون (iOS): Streisand یا V2Box
تمامی ترافیک بانکی و سایت‌های ایرانی به صورت مستقیم و بدون مصرف حجم باز می‌شوند.`
        : `Hi! Our private Home Family VPN is up and running.
Portal & Smart Signup:
${{portalUrl}}

Family Invite Code: ${{currentInviteCode}}

After creating your account, import your personal subscription into:
• Android / Windows: Hiddify or v2rayNG
• iPhone (iOS): Streisand or V2Box
Domestic Iranian sites & banking apps bypass the VPN automatically.`;

      window.open('https://wa.me/?text=' + encodeURIComponent(text), '_blank');
    }}

    function shareViaTelegram() {{
      const portalUrl = currentPublicUrl && currentPublicUrl.startsWith('https://') ? currentPublicUrl : (currentShareableLink || currentLanUrl);
      const text = currentLang === 'fa'
        ? `سلام! فیلترشکن اختصاصی و خانگی ما راه‌اندازی شد.
کد دعوت: ${{currentInviteCode}}
پس از ثبت‌نام در پورتال، اشتراک هوشمند خود را در Hiddify یا Streisand فعال کنید.`
        : `Hi! Our private Home Family VPN is up and running.
Invite Code: ${{currentInviteCode}}
After registering, import your smart subscription into Hiddify or Streisand.`;

      window.open('https://t.me/share/url?url=' + encodeURIComponent(portalUrl) + '&text=' + encodeURIComponent(text), '_blank');
    }}

    // Portal QR Modal
    function openPortalQrModal() {{
      currentActiveQrType = 'public';
      updatePortalQrDisplay();
      openModal('portalQrModal');
    }}

    function switchPortalQr(type) {{
      currentActiveQrType = type;
      updatePortalQrDisplay();
    }}

    function updatePortalQrDisplay() {{
      const isPublic = (currentActiveQrType === 'public');
      const url = isPublic
        ? (currentPublicUrl && currentPublicUrl.startsWith('https://') ? currentPublicUrl : (currentShareableLink || currentLocalUrl))
        : currentLanUrl;

      const btnPub = document.getElementById('btnQrTabPublic');
      const btnLan = document.getElementById('btnQrTabLan');
      if (isPublic) {{
        btnPub.className = 'flex-1 py-1.5 rounded-lg bg-indigo-600 text-white font-bold transition';
        btnLan.className = 'flex-1 py-1.5 rounded-lg text-slate-400 font-bold transition';
      }} else {{
        btnPub.className = 'flex-1 py-1.5 rounded-lg text-slate-400 font-bold transition';
        btnLan.className = 'flex-1 py-1.5 rounded-lg bg-cyan-600 text-white font-bold transition';
      }}

      document.getElementById('portalQrUrl').textContent = url;
      document.getElementById('portalQrImg').src = '/api/public/qr?text=' + encodeURIComponent(url);
    }}

    // Backup & Restore
    function openBackupModal() {{
      openModal('backupModal');
    }}

    function downloadBackupFile() {{
      window.location.href = '/api/admin/backup';
    }}

    function handleBackupFileSelect(event) {{
      const file = event.target.files[0];
      if (!file) return;
      document.getElementById('selectedFileName').textContent = file.name;
      const reader = new FileReader();
      reader.onload = function(e) {{
        document.getElementById('restoreJsonTextarea').value = e.target.result;
      }};
      reader.readAsText(file);
    }}

    async function executeRestore() {{
      const text = document.getElementById('restoreJsonTextarea').value.trim();
      if (!text) {{
        alert(currentLang === 'fa' ? 'لطفاً فایل پشتیبان را انتخاب کنید یا محتوای JSON را وارد نمایید.' : 'Please select a backup file or paste JSON content.');
        return;
      }}
      const confirmMsg = currentLang === 'fa' ? 'آیا از بازیابی اطلاعات اطمینان دارید؟ کاربران و تنظیمات بروزرسانی خواهند شد.' : 'Are you sure you want to restore? Users and settings will be updated.';
      if (!confirm(confirmMsg)) return;

      const btn = document.getElementById('btnExecuteRestore');
      btn.disabled = true;
      btn.textContent = (currentLang === 'fa' ? 'در حال بازیابی...' : 'Restoring...');
      try {{
        const res = await fetch('/api/admin/restore', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ backup_json: text }})
        }});
        const d = await res.json();
        if (res.ok && d.success) {{
          alert(d.message);
          closeModal('backupModal');
          fetchAdminOverview();
          fetchClients();
        }} else {{
          alert('Error: ' + (d.detail || d.message));
        }}
      }} catch (e) {{
        alert('Restore error: ' + e);
      }} finally {{
        btn.disabled = false;
        btn.textContent = i18nAdmin[currentLang].btnRestoreText;
      }}
    }}

    // Diagnostics Modal
    async function openDiagModal() {{
      openModal('diagModal');
      loadDiagLogs();
    }}

    async function loadDiagLogs() {{
      const box = document.getElementById('diagLogBox');
      box.textContent = i18nAdmin[currentLang].diagLoading;
      try {{
        const res = await fetch('/api/diagnostics/logs?limit=80');
        const d = await res.json();
        const entries = d.entries || [];
        box.innerHTML = entries.map(e => {{
          const leakBadge = e.is_leak ? '<span class="text-rose-400 font-bold">[!IR_LEAK!]</span> ' : '';
          return `<div>[${{e.timestamp}}] <span class="text-indigo-400">${{e.email}}</span> → <span class="text-white">${{e.destination}}</span> [${{e.route}}] ${{leakBadge}}${{e.status}}</div>`;
        }}).join('');
      }} catch (e) {{
        box.textContent = 'Error loading logs: ' + e;
      }}
    }}

    async function copyRedactedReport() {{
      try {{
        const res = await fetch('/api/diagnostics/report');
        const text = await res.text();
        navigator.clipboard.writeText(text).then(() => {{
          alert(currentLang === 'fa' ? 'گزارش عیب‌یابی بدون اطلاعات حساس کپی شد!' : 'Sanitized diagnostic report copied to clipboard!');
        }});
      }} catch (e) {{
        alert('Error: ' + e);
      }}
    }}

    window.addEventListener('DOMContentLoaded', () => {{
      const urlParams = new URLSearchParams(window.location.search);
      const qLang = urlParams.get('lang');
      if (qLang && (qLang === 'en' || qLang === 'fa')) {{
        currentLang = qLang;
        localStorage.setItem('vpn_lang', qLang);
      }} else {{
        currentLang = localStorage.getItem('vpn_lang') || 'fa';
      }}
      setLanguage(currentLang);

      fetchAdminOverview();
      fetchClients();
      fetchFailingDomains();
      setInterval(fetchAdminOverview, 10000);
      setInterval(fetchClients, 12000);
      setInterval(fetchFailingDomains, 20000);
    }});
  </script>
</body>
</html>"""


# ----------------- 4. DEDICATED BILINGUAL HELP & GUIDE PAGE ----------------- #

HELP_PAGE_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>راهنمای جامع فیلترشکن خانواده | Family VPN Knowledge Base</title>
  __COMMON_HEADER__
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col justify-between selection:bg-indigo-500 selection:text-white">
  <!-- Top Navigation Header -->
  <header class="border-b border-slate-800/80 bg-slate-900/60 sticky top-0 z-40 backdrop-blur-md">
    <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center space-x-3 space-x-reverse">
        <a href="/" class="p-2 rounded-2xl bg-indigo-600 text-white shadow-lg shadow-indigo-600/30 flex items-center justify-center">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>
        </a>
        <div>
          <h1 id="txtHelpBrandTitle" class="font-extrabold text-sm sm:text-base text-white flex items-center gap-2">
            <span>مرکز راهنما و آموزش سامانه</span>
            <span class="px-2 py-0.5 text-[10px] rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Guide v3.0</span>
          </h1>
          <p id="txtHelpBrandSub" class="text-xs text-slate-400">راهنمای تصویری معماری، ماندگاری لینک‌ها و اتصال آسان اعضای خانواده</p>
        </div>
      </div>

      <div class="flex items-center gap-2.5">
        <!-- Dashboard Link -->
        <a href="/dashboard" id="txtNavDashboard" class="hidden sm:inline-flex px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition">داشبورد</a>
        <!-- Admin Link -->
        <a href="/admin" id="txtNavAdmin" class="hidden sm:inline-flex px-3 py-1.5 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 text-xs font-semibold transition">پنل مدیر</a>

        <!-- Theme Toggle -->
        <button onclick="toggleTheme()" class="px-2.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition" title="Toggle Theme">
          <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
        </button>

        <!-- Language Toggle -->
        <button onclick="toggleHelpLang()" class="px-3.5 py-1.5 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 text-xs font-bold transition flex items-center gap-1.5 shadow-sm">
          <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"/></svg>
          <span id="helpLangLabel">English</span>
        </button>
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <main class="max-w-5xl mx-auto px-4 py-8 sm:py-12 flex-1 w-full space-y-12">

    <!-- Hero Header -->
    <div class="text-center space-y-3">
      <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-xs font-bold text-indigo-400">
        <span class="w-2 h-2 rounded-full bg-indigo-400"></span>
        <span id="txtHelpTag">راهنمای گام‌به‌گام و مصور</span>
      </div>
      <h2 id="txtHelpHeroTitle" class="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">آموزش جامع استفاده و نگهداری فیلترشکن خانواده</h2>
      <p id="txtHelpHeroSub" class="text-xs sm:text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">صفر پورت فورواردینگ، رایگان، بدون قطعی، و بدون نیاز به خرید دامنه یا آی‌پی ثابت</p>

      <!-- Quick Jump Pills -->
      <div class="flex items-center justify-center gap-2 flex-wrap pt-2">
        <a href="#section-arch" class="px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:border-indigo-500 transition">🏗️ معماری سیستم</a>
        <a href="#section-lifespan" class="px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:border-indigo-500 transition">🔄 سیستم خودترمیمی</a>
        <a href="#section-onboard" class="px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:border-indigo-500 transition">📱 راهنمای اتصال خانواده</a>
        <a href="#section-trouble" class="px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:border-indigo-500 transition">🛠️ حل مشکلات رایج</a>
      </div>
    </div>

    <!-- SECTION 1: HOW IT WORKS (ARCHITECTURE) -->
    <section id="section-arch" class="glass-card p-6 sm:p-8 rounded-3xl border border-slate-800 shadow-xl space-y-6">
      <div class="flex items-center gap-3 border-b border-slate-800 pb-4">
        <div class="p-3 rounded-2xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
        </div>
        <div>
          <h3 id="txtSec1Title" class="text-lg sm:text-xl font-bold text-white">۱. معماری سامانه و نحوه کارکرد (How It Works)</h3>
          <p id="txtSec1Sub" class="text-xs text-slate-400">چرا این سیستم به باز کردن پورت مودم یا خرید دامنه نیازی ندارد؟</p>
        </div>
      </div>

      <!-- Flowchart / Diagram -->
      <div class="p-5 rounded-2xl bg-slate-950 border border-slate-800/80 space-y-4">
        <h4 id="txtDiagTitle" class="text-xs font-bold text-slate-400 uppercase tracking-wider text-center">مسیر جریان ترافیک اینترنت از ایران به لپ‌تاپ خانگی</h4>
        <div class="grid grid-cols-1 sm:grid-cols-5 gap-3 text-center items-center">
          <div class="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
            <div class="text-2xl">📱</div>
            <div class="text-xs font-bold text-white">گوشی یا لپ‌تاپ کاربر</div>
            <div class="text-[10px] text-slate-400">ایران (همراه اول/ایرانسل)</div>
          </div>
          <div class="text-indigo-400 font-bold text-lg hidden sm:block">➔</div>
          <div class="p-3.5 rounded-xl bg-slate-900 border border-indigo-900/60 space-y-1">
            <div class="text-2xl">⚡</div>
            <div class="text-xs font-bold text-indigo-300">لبه شبکه Cloudflare</div>
            <div class="text-[10px] text-slate-400">Anycast CDN (TLS :443)</div>
          </div>
          <div class="text-indigo-400 font-bold text-lg hidden sm:block">➔</div>
          <div class="p-3.5 rounded-xl bg-slate-900 border border-emerald-900/60 space-y-1">
            <div class="text-2xl">💻</div>
            <div class="text-xs font-bold text-emerald-300">لپ‌تاپ سرور (ایرلند)</div>
            <div class="text-[10px] text-slate-400">تونل ابری Quick Tunnel</div>
          </div>
        </div>
      </div>

      <!-- Key Advantages Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
        <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <div class="font-bold text-emerald-400 flex items-center gap-1.5">
            <span>✓</span>
            <span id="txtAdv1Title">صفر پورت فورواردینگ</span>
          </div>
          <p id="txtAdv1Desc" class="text-slate-400 leading-relaxed">نیازی به دستکاری روتر اینترنت خانه یا باز کردن پورت نیست. تونل از داخل لپ‌تاپ به کلودفلر باز می‌شود (Outbound).</p>
        </div>
        <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <div class="font-bold text-cyan-400 flex items-center gap-1.5">
            <span>✓</span>
            <span id="txtAdv2Title">کاملاً رایگان و بدون دامنه</span>
          </div>
          <p id="txtAdv2Desc" class="text-slate-400 leading-relaxed">بدون نیاز به پرداخت هزینه ماهانه برای خرید دامنه، آی‌پی استاتیک، یا اجاره سرور خارجی.</p>
        </div>
        <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <div class="font-bold text-purple-400 flex items-center gap-1.5">
            <span>✓</span>
            <span id="txtAdv3Title">ضد اختلال عمیق (Anti-DPI)</span>
          </div>
          <p id="txtAdv3Desc" class="text-slate-400 leading-relaxed">مجهز به تکه‌تکه‌سازی پکت‌های TLS (Fragmentation 10-30B) جهت جلوگیری از شناسایی بسته توسط فیلترینگ.</p>
        </div>
      </div>
    </section>

    <!-- SECTION 2: LINK LIFESPAN & AUTO-HEALING WATCHDOG -->
    <section id="section-lifespan" class="glass-card p-6 sm:p-8 rounded-3xl border border-slate-800 shadow-xl space-y-6">
      <div class="flex items-center gap-3 border-b border-slate-800 pb-4">
        <div class="p-3 rounded-2xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
        </div>
        <div>
          <h3 id="txtSec2Title" class="text-lg sm:text-xl font-bold text-white">۲. طول عمر لینک‌ها و سیستم خودترمیمی (Lifespan & Watchdog)</h3>
          <p id="txtSec2Sub" class="text-xs text-slate-400">تونل‌ها پس از ری‌استارت لپ‌تاپ چگونه بدون دخالت شما احیا می‌شوند؟</p>
        </div>
      </div>

      <div class="space-y-4 text-xs sm:text-sm text-slate-300 leading-relaxed">
        <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-2">
          <h4 id="txtLifeQ1" class="font-bold text-white flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
            <span>طول عمر لینک‌های Cloudflare Quick Tunnel چقدر است؟</span>
          </h4>
          <p id="txtLifeA1" class="text-slate-400">کلودفلر برای اتصال‌های رایگان کوئیک تونل، لینک‌های موقت با دامنه trycloudflare.com تولید می‌کند. این لینک‌ها تا زمانی که لپ‌تاپ روشن و به اینترنت متصل باشد پایدار می‌مانند.</p>
        </div>

        <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-2">
          <h4 id="txtLifeQ2" class="font-bold text-white flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>سیستم نگهبان خودکار (۶۰-Second Watchdog) چه می‌کند؟</span>
          </h4>
          <p id="txtLifeA2" class="text-slate-400">پورتال دارای یک نگهبان پس‌زمینه است که هر ۶۰ ثانیه تونل‌ها را بررسی می‌کند. اگر اینترنت خانه قطع و وصل شود یا لپ‌تاپ ری‌استارت شود، نگهبان بلافاصله تونل‌ها را مجدداً بالا آورده، آدرس جدید را دریافت کرده و اینباند سرور 3x-ui را خودکار هماهنگ می‌کند.</p>
        </div>

        <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-2">
          <h4 id="txtLifeQ3" class="font-bold text-white flex items-center gap-2">
            <span class="w-2 h-2 rounded-full bg-purple-400"></span>
            <span>چرا لینک اشتراک اعضای خانواده بعد از ری‌استارت قطع نمی‌شود؟</span>
          </h4>
          <p id="txtLifeA3" class="text-slate-400">لینک اشتراکی که اعضای خانواده در نرم‌افزارهای خود (مانند Hiddify یا Streisand) وارد می‌کنند، یک لینک هوشمند است. این نرم‌افزارها هر چند ساعت یک‌بار لینک را به‌صورت خودکار رفرش کرده و آدرس جدید تونل را بی‌صدا دریافت می‌کنند؛ بنابراین خانواده نیازی به تغییر دستی کانفیگ ندارند.</p>
        </div>
      </div>
    </section>

    <!-- SECTION 3: ONBOARDING FAMILY -->
    <section id="section-onboard" class="glass-card p-6 sm:p-8 rounded-3xl border border-slate-800 shadow-xl space-y-6">
      <div class="flex items-center gap-3 border-b border-slate-800 pb-4">
        <div class="p-3 rounded-2xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
        </div>
        <div>
          <h3 id="txtSec3Title" class="text-lg sm:text-xl font-bold text-white">۳. راهنمای گام‌به‌گام اتصال اعضای خانواده (Family Onboarding)</h3>
          <p id="txtSec3Sub" class="text-xs text-slate-400">نحوه اتصال گوشی‌های اندروید، آیفون، و رایانه‌های ویندوز و مک</p>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
        <!-- Android Card -->
        <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-3">
          <div class="flex items-center gap-2 text-emerald-400 font-bold text-sm">
            <span>🤖</span>
            <span>اندروید (Android)</span>
          </div>
          <ol class="space-y-2 text-xs text-slate-300 list-decimal list-inside leading-relaxed">
            <li>نرم‌افزار <b>Hiddify</b> یا <b>v2rayNG</b> را از گوگل‌پلی نصب کنید.</li>
            <li>در پورتال فیلترشکن، دکمه <b>«کپی لینک اشتراک»</b> را لمس کنید.</li>
            <li>در برنامه هیدیفای علامت <b>«+»</b> و سپس <b>«افزودن از کلیپ‌بورد»</b> را بزنید.</li>
            <li>دکمه دایره‌ای اتصال را لمس کنید.</li>
          </ol>
        </div>

        <!-- iOS Card -->
        <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-3">
          <div class="flex items-center gap-2 text-sky-400 font-bold text-sm">
            <span>🍏</span>
            <span>آیفون و آیپد (iOS)</span>
          </div>
          <ol class="space-y-2 text-xs text-slate-300 list-decimal list-inside leading-relaxed">
            <li>نرم‌افزار <b>Streisand</b> یا <b>V2Box</b> را از App Store دانلود کنید.</li>
            <li>در برنامه دکمه <b>«+»</b> و سپس <b>«Add Subscription»</b> را بزنید.</li>
            <li>لینک اشتراک دریافتی از پورتال را در کادر Paste کنید.</li>
            <li>پروفایل ذخیره شده را انتخاب و متصل شوید.</li>
          </ol>
        </div>

        <!-- Desktop Card -->
        <div class="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-3">
          <div class="flex items-center gap-2 text-purple-400 font-bold text-sm">
            <span>💻</span>
            <span>ویندوز و مک (PC/Mac)</span>
          </div>
          <ol class="space-y-2 text-xs text-slate-300 list-decimal list-inside leading-relaxed">
            <li>نرم‌افزار دسکتاپ <b>Hiddify</b> را از گیت‌هاب دانلود و اجرا کنید.</li>
            <li>لینک اشتراک خود را کپی کرده و در برنامه گزینه <b>Import</b> را بزنید.</li>
            <li>حالت سیستم را روی <b>VPN Service / TUN</b> بگذارید.</li>
            <li>اتصال را برقرار کنید.</li>
          </ol>
        </div>
      </div>
    </section>

    <!-- SECTION 4: TROUBLESHOOTING -->
    <section id="section-trouble" class="glass-card p-6 sm:p-8 rounded-3xl border border-slate-800 shadow-xl space-y-6">
      <div class="flex items-center gap-3 border-b border-slate-800 pb-4">
        <div class="p-3 rounded-2xl bg-rose-500/10 text-rose-400 border border-rose-500/20">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
        </div>
        <div>
          <h3 id="txtSec4Title" class="text-lg sm:text-xl font-bold text-white">۴. عیب‌یابی و حل مشکلات متداول (Troubleshooting)</h3>
          <p id="txtSec4Sub" class="text-xs text-slate-400">راهکارهای کاربردی برای همراه بانک‌ها، افت سرعت و حالت خواب لپ‌تاپ</p>
        </div>
      </div>

      <div class="space-y-4 text-xs sm:text-sm text-slate-300">
        <!-- Trouble 1: Banking Apps -->
        <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <h4 id="txtTr1Title" class="font-bold text-amber-400">💳 همراه بانک‌ها، اسنپ، دیجی‌کالا و سایت‌های دولتی باز نمی‌شوند؟</h4>
          <p id="txtTr1Desc" class="text-slate-400 leading-relaxed">
            تمامی سایت‌های پسوند .ir به صورت خودکار از فیلترشکن دور زده می‌شوند (Direct). اما اگر یک همراه بانک خاص حتی وجود اتصال VPN فعال در گوشی را منع می‌کند، در برنامه Hiddify یا v2rayNG به بخش <b>تنظیمات</b> رفته و گزینه <b>«Per-App Proxy» (پروکسی بر اساس برنامه)</b> را روشن کرده و تیک برنامه بانکی را بردارید تا اصلاً وارد فیلترشکن نشود.
          </p>
        </div>

        <!-- Trouble 2: Speed / Blocking -->
        <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <h4 id="txtTr2Title" class="font-bold text-cyan-400">🚀 افت سرعت اینترنت یا قطعی موقت در ساعات اوج؟</h4>
          <p id="txtTr2Desc" class="text-slate-400 leading-relaxed">
            در اشتراک اختصاصی شما، ۴ مسیر پشتیبان ابری (Clean Anycast Cloudflare IPs) قرار دارد. در نرم‌افزار کاربر می‌تواند بین خط اصلی و خطوط CleanIP 1/2/3 سوئیچ کند یا حالت <b>«URL-Test (تست خودکار پینگ)»</b> را انتخاب نماید تا برنامه خودکار سریع‌ترین خط بدون اختلال را انتخاب کند.
          </p>
        </div>

        <!-- Trouble 3: Power / Sleep -->
        <div class="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <h4 id="txtTr3Title" class="font-bold text-emerald-400">🔌 آیا با بستن درب لپ‌تاپ سرور به خواب می‌رود؟</h4>
          <p id="txtTr3Desc" class="text-slate-400 leading-relaxed">
            خیر! اسکریپت راه‌انداز خودکار سیستم تنظیمات ویندوز را به گونه‌ای پیکربندی کرده است که در زمان اتصال به شارژر، با بستن درب لپ‌تاپ (Lid Close) دستگاه خاموش یا به حالت Sleep نمی‌رود. لطفاً مطمئن شوید لپ‌تاپ به شارژر برق شهری متصل است.
          </p>
        </div>
      </div>
    </section>

  </main>

  <!-- Footer -->
  <footer class="border-t border-slate-800/80 bg-slate-900/40 py-6 text-center text-xs text-slate-500">
    <div class="max-w-6xl mx-auto px-4">
      <p id="txtHelpFooter">سامانه فیلترشکن خانواده | طراحی‌شده با عشق برای دسترسی امن، سریع و بدون فیلتر به اینترنت آزاد</p>
    </div>
  </footer>

  <script>
    const i18nHelp = {
      fa: {
        docTitle: 'راهنمای جامع فیلترشکن خانواده | Family VPN Knowledge Base',
        brandTitle: 'مرکز راهنما و آموزش سامانه',
        brandSub: 'راهنمای تصویری معماری، ماندگاری لینک‌ها و اتصال آسان اعضای خانواده',
        navDashboard: 'داشبورد',
        navAdmin: 'پنل مدیر',
        langLabel: 'English',
        helpTag: 'راهنمای گام‌به‌گام و مصور',
        heroTitle: 'آموزش جامع استفاده و نگهداری فیلترشکن خانواده',
        heroSub: 'صفر پورت فورواردینگ، رایگان، بدون قطعی، و بدون نیاز به خرید دامنه یا آی‌پی ثابت',
        sec1Title: '۱. معماری سامانه و نحوه کارکرد (How It Works)',
        sec1Sub: 'چرا این سیستم به باز کردن پورت مودم یا خرید دامنه نیازی ندارد؟',
        diagTitle: 'مسیر جریان ترافیک اینترنت از ایران به لپ‌تاپ خانگی',
        adv1Title: 'صفر پورت فورواردینگ',
        adv1Desc: 'نیازی به دستکاری روتر اینترنت خانه یا باز کردن پورت نیست. تونل از داخل لپ‌تاپ به کلودفلر باز می‌شود (Outbound).',
        adv2Title: 'کاملاً رایگان و بدون دامنه',
        adv2Desc: 'بدون نیاز به پرداخت هزینه ماهانه برای خرید دامنه، آی‌پی استاتیک، یا اجاره سرور خارجی.',
        adv3Title: 'ضد اختلال عمیق (Anti-DPI)',
        adv3Desc: 'مجهز به تکه‌تکه‌سازی پکت‌های TLS (Fragmentation 10-30B) جهت جلوگیری از شناسایی بسته توسط فیلترینگ.',
        sec2Title: '۲. طول عمر لینک‌ها و سیستم خودترمیمی (Lifespan & Watchdog)',
        sec2Sub: 'تونل‌ها پس از ری‌استارت لپ‌تاپ چگونه بدون دخالت شما احیا می‌شوند؟',
        lifeQ1: 'طول عمر لینک‌های Cloudflare Quick Tunnel چقدر است؟',
        lifeA1: 'کلودفلر برای اتصال‌های رایگان کوئیک تونل، لینک‌های موقت با دامنه trycloudflare.com تولید می‌کند. این لینک‌ها تا زمانی که لپ‌تاپ روشن و به اینترنت متصل باشد پایدار می‌مانند.',
        lifeQ2: 'سیستم نگهبان خودکار (۶۰-Second Watchdog) چه می‌کند؟',
        lifeA2: 'پورتال دارای یک نگهبان پس‌زمینه است که هر ۶۰ ثانیه تونل‌ها را بررسی می‌کند. اگر اینترنت خانه قطع و وصل شود یا لپ‌تاپ ری‌استارت شود، نگهبان بلافاصله تونل‌ها را مجدداً بالا آورده، آدرس جدید را دریافت کرده و اینباند سرور 3x-ui را خودکار هماهنگ می‌کند.',
        lifeQ3: 'چرا لینک اشتراک اعضای خانواده بعد از ری‌استارت قطع نمی‌شود؟',
        lifeA3: 'لینک اشتراکی که اعضای خانواده در نرم‌افزارهای خود وارد می‌کنند، یک لینک هوشمند است. این نرم‌افزارها هر چند ساعت یک‌بار لینک را به‌صورت خودکار رفرش کرده و آدرس جدید تونل را بی‌صدا دریافت می‌کنند؛ بنابراین خانواده نیازی به تغییر دستی کانفیگ ندارند.',
        sec3Title: '۳. راهنمای گام‌به‌گام اتصال اعضای خانواده (Family Onboarding)',
        sec3Sub: 'نحوه اتصال گوشی‌های اندروید، آیفون، و رایانه‌های ویندوز و مک',
        sec4Title: '۴. عیب‌یابی و حل مشکلات متداول (Troubleshooting)',
        sec4Sub: 'راهکارهای کاربردی برای همراه بانک‌ها، افت سرعت و حالت خواب لپ‌تاپ',
        tr1Title: '💳 همراه بانک‌ها، اسنپ، دیجی‌کالا و سایت‌های دولتی باز نمی‌شوند؟',
        tr1Desc: 'تمامی سایت‌های پسوند .ir به صورت خودکار از فیلترشکن دور زده می‌شوند (Direct). اما اگر یک همراه بانک خاص حتی وجود اتصال VPN فعال در گوشی را منع می‌کند، در برنامه Hiddify یا v2rayNG به بخش تنظیمات رفته و گزینه «Per-App Proxy» را روشن کرده و تیک برنامه بانکی را بردارید.',
        tr2Title: '🚀 افت سرعت اینترنت یا قطعی موقت در ساعات اوج؟',
        tr2Desc: 'در اشتراک اختصاصی شما، ۴ مسیر پشتیبان ابری (Clean Anycast Cloudflare IPs) قرار دارد. در نرم‌افزار کاربر می‌تواند بین خط اصلی و خطوط CleanIP سوئیچ کند یا حالت URL-Test را انتخاب نماید.',
        tr3Title: '🔌 آیا با بستن درب لپ‌تاپ سرور به خواب می‌رود؟',
        tr3Desc: 'خیر! اسکریپت راه‌انداز تنظیمات ویندوز را به گونه‌ای پیکربندی کرده است که با بستن درب لپ‌تاپ دستگاه خاموش یا به حالت Sleep نمی‌رود.',
        footer: 'سامانه فیلترشکن خانواده | طراحی‌شده برای دسترسی امن، سریع و بدون فیلتر به اینترنت آزاد'
      },
      en: {
        docTitle: 'Family VPN Knowledge Base | Help & Guide',
        brandTitle: 'Knowledge Base & User Guide',
        brandSub: 'Illustrated architecture, tunnel lifespan, and family onboarding instructions',
        navDashboard: 'Dashboard',
        navAdmin: 'Admin Panel',
        langLabel: 'فارسی',
        helpTag: 'Illustrated Step-by-Step Guide',
        heroTitle: 'Family VPN Setup & Troubleshooting Guide',
        heroSub: 'Zero port forwarding, zero cost, anti-DPI resilient, and zero domain purchase required',
        sec1Title: '1. Architecture & How It Works',
        sec1Sub: 'Why does this setup require zero router configuration or domain costs?',
        diagTitle: 'Traffic Flow from Iran to your Server Laptop',
        adv1Title: 'Zero Port Forwarding',
        adv1Desc: 'No router settings or open ports required. The tunnel establishes an outbound encrypted connection directly to Cloudflare.',
        adv2Title: 'Completely Free & Domainless',
        adv2Desc: 'No monthly subscriptions for custom domains, static public IPs, or remote VPS hosting.',
        adv3Title: 'Anti-DPI Resilient',
        adv3Desc: 'Equipped with TLS packet fragmentation (10-30B) to bypass Deep Packet Inspection firewalls seamlessly.',
        sec2Title: '2. Link Lifespan & Auto-Healing Watchdog',
        sec2Sub: 'How tunnels auto-recover after power cuts or laptop reboots',
        lifeQ1: 'How long do Cloudflare Quick Tunnel links last?',
        lifeA1: 'Cloudflare assigns dynamic trycloudflare.com URLs to Quick Tunnels. They stay active continuously as long as the server laptop is online.',
        lifeQ2: 'What does the 60-Second Auto-Healing Watchdog do?',
        lifeA2: 'The watchdog background process monitors tunnel health every 60 seconds. If internet drops or the laptop restarts, it regenerates tunnels within 10 seconds and syncs 3x-ui inbounds automatically.',
        lifeQ3: 'Why do family subscription links stay permanent?',
        lifeA3: 'Client apps (Hiddify, Streisand, v2rayNG) auto-refresh subscriptions periodically in the background, fetching the updated tunnel without any manual user intervention.',
        sec3Title: '3. Step-by-Step Family Onboarding',
        sec3Sub: 'Connecting Android, iPhone, and desktop devices effortlessly',
        sec4Title: '4. Troubleshooting Common Issues',
        sec4Sub: 'Practical solutions for banking apps, speed degradation, and power management',
        tr1Title: '💳 Domestic Iranian banking apps or Snapp issues?',
        tr1Desc: 'All .ir domains and Iranian bank IPs are automatically routed directly outside the VPN. If a sensitive bank app detects VPN presence, enable "Per-App Proxy" in Hiddify / v2rayNG and uncheck the banking app.',
        tr2Title: '🚀 Experiencing slow speeds or ISP throttle during peak hours?',
        tr2Desc: 'Your subscription includes 4 fallback Anycast Cloudflare routes. Users can manually switch to a CleanIP line or select "URL-Test (Auto-Best)" for lowest latency.',
        tr3Title: '🔌 Does closing the laptop lid put the server to sleep?',
        tr3Desc: 'No! The installer auto-configures Windows power schemes so closing the laptop lid while connected to AC power will NOT put the computer to sleep.',
        footer: 'Home Family VPN | Designed with care for private, high-speed, unrestricted internet access'
      }
    };

    let helpLang = localStorage.getItem('vpn_lang') || 'fa';

    function setHelpLanguage(lang) {
      helpLang = lang;
      localStorage.setItem('vpn_lang', lang);
      document.documentElement.lang = lang;
      document.documentElement.dir = (lang === 'fa') ? 'rtl' : 'ltr';

      const d = i18nHelp[lang];
      document.title = d.docTitle;
      document.getElementById('txtHelpBrandTitle').querySelector('span').textContent = d.brandTitle;
      document.getElementById('txtHelpBrandSub').textContent = d.brandSub;
      document.getElementById('txtNavDashboard').textContent = d.navDashboard;
      document.getElementById('txtNavAdmin').textContent = d.navAdmin;
      document.getElementById('helpLangLabel').textContent = d.langLabel;
      document.getElementById('txtHelpTag').textContent = d.helpTag;
      document.getElementById('txtHelpHeroTitle').textContent = d.heroTitle;
      document.getElementById('txtHelpHeroSub').textContent = d.heroSub;
      document.getElementById('txtSec1Title').textContent = d.sec1Title;
      document.getElementById('txtSec1Sub').textContent = d.sec1Sub;
      document.getElementById('txtDiagTitle').textContent = d.diagTitle;
      document.getElementById('txtAdv1Title').textContent = d.adv1Title;
      document.getElementById('txtAdv1Desc').textContent = d.adv1Desc;
      document.getElementById('txtAdv2Title').textContent = d.adv2Title;
      document.getElementById('txtAdv2Desc').textContent = d.adv2Desc;
      document.getElementById('txtAdv3Title').textContent = d.adv3Title;
      document.getElementById('txtAdv3Desc').textContent = d.adv3Desc;
      document.getElementById('txtSec2Title').textContent = d.sec2Title;
      document.getElementById('txtSec2Sub').textContent = d.sec2Sub;
      document.getElementById('txtLifeQ1').querySelector('span:last-child').textContent = d.lifeQ1;
      document.getElementById('txtLifeA1').textContent = d.lifeA1;
      document.getElementById('txtLifeQ2').querySelector('span:last-child').textContent = d.lifeQ2;
      document.getElementById('txtLifeA2').textContent = d.lifeA2;
      document.getElementById('txtLifeQ3').querySelector('span:last-child').textContent = d.lifeQ3;
      document.getElementById('txtLifeA3').textContent = d.lifeA3;
      document.getElementById('txtSec3Title').textContent = d.sec3Title;
      document.getElementById('txtSec3Sub').textContent = d.sec3Sub;
      document.getElementById('txtSec4Title').textContent = d.sec4Title;
      document.getElementById('txtSec4Sub').textContent = d.sec4Sub;
      document.getElementById('txtTr1Title').textContent = d.tr1Title;
      document.getElementById('txtTr1Desc').textContent = d.tr1Desc;
      document.getElementById('txtTr2Title').textContent = d.tr2Title;
      document.getElementById('txtTr2Desc').textContent = d.tr2Desc;
      document.getElementById('txtTr3Title').textContent = d.tr3Title;
      document.getElementById('txtTr3Desc').textContent = d.tr3Desc;
      document.getElementById('txtHelpFooter').textContent = d.footer;
    }

    function toggleHelpLang() {
      const next = (helpLang === 'fa') ? 'en' : 'fa';
      setHelpLanguage(next);
      try {
        const url = new URL(window.location);
        url.searchParams.set('lang', next);
        window.history.replaceState({}, '', url);
      } catch (e) {}
    }

    window.addEventListener('DOMContentLoaded', () => {
      const urlParams = new URLSearchParams(window.location.search);
      const qLang = urlParams.get('lang');
      if (qLang && (qLang === 'en' || qLang === 'fa')) {
        helpLang = qLang;
      }
      setHelpLanguage(helpLang);
    });
  </script>
</body>
</html>""".replace("__COMMON_HEADER__", COMMON_HEADER_HTML)

# ----------------- HTML Route Handlers ----------------- #

@app.get("/", response_class=HTMLResponse)
def get_landing_page(request: Request):
    return HTMLResponse(LANDING_PAGE_HTML)

@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request):
    return HTMLResponse(LANDING_PAGE_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard_page(request: Request):
    return HTMLResponse(DASHBOARD_PAGE_HTML)

@app.get("/admin", response_class=HTMLResponse)
def get_admin_page(request: Request):
    return HTMLResponse(ADMIN_PAGE_HTML)

@app.get("/help", response_class=HTMLResponse)
def get_help_page(request: Request):
    return HTMLResponse(HELP_PAGE_HTML)

if __name__ == "__main__":
    ensure_services()
    ensure_xray_logging()
    print("\n" + "=" * 72)
    print("  [HOME VPN PLATFORM] Bilingual Family Self-Service Hub Online")
    print(f"  Local Admin URL: http://127.0.0.1:{PORTAL_PORT}/admin")
    print(f"  Local LAN URL:   http://{get_lan_ip()}:{PORTAL_PORT}/admin")
    print("  Active Invite Code: " + get_invite_code())
    print("=" * 72 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=PORTAL_PORT, log_level="info")
