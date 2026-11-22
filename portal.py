import os
import sys

# Safe stdout/stderr handling for Windows background/GUI launcher (wscript/pythonw)
try:
    if sys.stdout is None or not hasattr(sys.stdout, "write"):
        log_f = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "portal.log"), "a", encoding="utf-8")
        sys.stdout = log_f
        sys.stderr = log_f
except Exception:
    pass

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
from typing import Optional, Dict, Any, List, Tuple
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
        with open(CONFIG_FILE, "r", encoding="utf-8-sig") as f:
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
            bandwidth_limit_mbps INTEGER DEFAULT 10,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)
    cur.execute("PRAGMA table_info(users)")
    user_cols = [c[1] for c in cur.fetchall()]
    if "bandwidth_limit_mbps" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN bandwidth_limit_mbps INTEGER DEFAULT 10")
        cur.execute("UPDATE users SET bandwidth_limit_mbps = 10 WHERE bandwidth_limit_mbps IS NULL")
        conn.commit()
    if "last_ip" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN last_ip TEXT DEFAULT ''")
        conn.commit()
    if "last_seen" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN last_seen TEXT DEFAULT ''")
        conn.commit()
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
    default_code = portal_config.get("INVITE_CODE") or "FAMILY2026"
    if not row:
        cur.execute("INSERT INTO settings (key, value) VALUES ('invite_code', ?)", (default_code,))
        conn.commit()
    elif row["value"] == "IR-FAMILY" and portal_config.get("INVITE_CODE"):
        cur.execute("UPDATE settings SET value = ? WHERE key = 'invite_code'", (portal_config.get("INVITE_CODE"),))
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

def extract_client_ip(request: Request) -> str:
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()
    true_ip = request.headers.get("true-client-ip")
    if true_ip and true_ip.strip():
        return true_ip.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0]
    if request.client and request.client.host:
        return request.client.host
    return ""

def record_user_activity(email_or_sub: str, request: Optional[Request] = None, ip_override: Optional[str] = None):
    if not email_or_sub:
        return
    client_ip = ip_override
    if not client_ip and request:
        client_ip = extract_client_ip(request)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = get_db()
        cur = conn.cursor()
        if client_ip and client_ip not in ("127.0.0.1", "localhost", ""):
            cur.execute("""
                UPDATE users 
                SET last_ip = ?, last_seen = ? 
                WHERE lower(email) = ? OR sub_id = ? OR uuid = ?
            """, (client_ip, now_str, email_or_sub.lower(), email_or_sub, email_or_sub))
        else:
            cur.execute("""
                UPDATE users 
                SET last_seen = ? 
                WHERE lower(email) = ? OR sub_id = ? OR uuid = ?
            """, (now_str, email_or_sub.lower(), email_or_sub, email_or_sub))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Record Activity Error] {e}")
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
                with open(CONFIG_FILE, "r", encoding="utf-8-sig") as f:
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
            with open(AUTH_FILE, "r", encoding="utf-8-sig") as f:
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
        with open(AUTH_FILE, "r", encoding="utf-8-sig") as f:
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
        with open(AUTH_FILE, "r", encoding="utf-8-sig") as f:
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
        with open(AUTH_FILE, "r", encoding="utf-8-sig") as f:
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
        INSERT INTO users (name, email, password_hash, salt, role, sub_id, uuid, created_at, last_login, bandwidth_limit_mbps)
        VALUES (?, ?, ?, ?, 'user', ?, ?, ?, ?, 10)
    """, (name_clean, email_clean, pwd_hash, salt_hex, sub_id, client_uuid, now_str, now_str))
    conn.commit()
    try:
        sync_xray_policy_and_limits()
    except Exception:
        pass
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
            with open(DOMAINS_FILE, "r", encoding="utf-8-sig") as f:
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

_telegram_warned = False

def load_telegram_config() -> dict:
    global _telegram_warned
    cfg = {"enabled": False, "bot_token": "", "chat_id": ""}
    
    # 1. telegram_config.json
    if os.path.exists(TELEGRAM_FILE):
        try:
            with open(TELEGRAM_FILE, "r", encoding="utf-8-sig") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    cfg.update(loaded)
        except Exception:
            pass

    # 2. Fallback to config.json
    if not cfg.get("bot_token") or not cfg.get("chat_id"):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8-sig") as f:
                    c = json.load(f)
                    if not cfg.get("bot_token"):
                        cfg["bot_token"] = c.get("TELEGRAM_BOT_TOKEN") or c.get("telegram_bot_token") or ""
                    if not cfg.get("chat_id"):
                        cfg["chat_id"] = str(c.get("TELEGRAM_CHAT_ID") or c.get("telegram_chat_id") or "")
                    if "TELEGRAM_ENABLED" in c:
                        cfg["enabled"] = bool(c.get("TELEGRAM_ENABLED"))
            except Exception:
                pass

    # 3. Fallback to environment variables / .env
    if not cfg.get("bot_token"):
        cfg["bot_token"] = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not cfg.get("chat_id"):
        cfg["chat_id"] = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not cfg.get("enabled") and (os.environ.get("TELEGRAM_ENABLED", "").lower() in ("true", "1", "yes")):
        cfg["enabled"] = True

    token = cfg.get("bot_token", "").strip()
    chat_id = cfg.get("chat_id", "").strip()
    if not token or not chat_id:
        if not _telegram_warned:
            print("[Telegram Alert] Bot token or Chat ID is not configured. Telegram alerts are disabled. Configure in telegram_config.json or Admin Portal.")
            _telegram_warned = True
    else:
        if "enabled" not in cfg:
            cfg["enabled"] = True

    return cfg

def save_telegram_config(cfg: dict):
    try:
        with open(TELEGRAM_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[Telegram Save Error] {e}")

    # Also sync to config.json if it exists
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8-sig") as f:
                c = json.load(f)
            c["TELEGRAM_ENABLED"] = cfg.get("enabled", False)
            if "bot_token" in cfg:
                c["TELEGRAM_BOT_TOKEN"] = cfg.get("bot_token", "")
            if "chat_id" in cfg:
                c["TELEGRAM_CHAT_ID"] = cfg.get("chat_id", "")
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(c, f, indent=2)
        except Exception:
            pass

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
        r_csrf = s.get(f"{base_url}/csrf-token", timeout=2.0)
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
        r_login = s.post(f"{base_url}/login", data=login_payload, headers=login_headers, timeout=2.0)
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
        try:
            session, base_url = get_3xui_auth_session()
        except Exception as e:
            print(f"[3x-ui Session Init Error] {e}")
            return None
    try:
        r = session.get(f"{base_url}/panel/api/inbounds/list", timeout=2.0)
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
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH, timeout=5.0)
            cur = conn.cursor()
            cur.execute("SELECT value FROM settings WHERE key = 'xrayTemplateConfig'")
            row = cur.fetchone()
            log_dir_fwd = LOG_DIR.replace("\\", "/")
            access_log_path = f"{log_dir_fwd}/access.log"
            error_log_path = f"{log_dir_fwd}/error.log"

            tpl = {}
            if row and row[0]:
                try:
                    tpl = json.loads(row[0])
                except Exception:
                    tpl = {}
            if not tpl:
                try:
                    s, base_url = get_3xui_auth_session()
                    r = s.get(f"{base_url}/panel/api/xray/getDefaultJsonConfig", timeout=4)
                    if r.status_code == 200:
                        tpl = r.json().get("obj", {})
                except Exception:
                    pass

            current_log = tpl.get("log", {}) if isinstance(tpl, dict) else {}
            if (current_log.get("loglevel") != "info" or
                not current_log.get("dnsLog") or
                current_log.get("access") != access_log_path):
                
                if not isinstance(tpl, dict):
                    tpl = {}
                tpl["log"] = {
                    "access": access_log_path,
                    "error": error_log_path,
                    "loglevel": "info",
                    "dnsLog": True,
                    "maskAddress": ""
                }
                cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('xrayTemplateConfig', ?)", (json.dumps(tpl, indent=2),))
                conn.commit()
                try:
                    s, base_url = get_3xui_auth_session()
                    s.post(f"{base_url}/panel/api/server/restartXrayService", timeout=5)
                    print("[Xray Logging] Updated xrayTemplateConfig in x-ui.db with persistent logging and restarted Xray.")
                except Exception:
                    pass
            conn.close()
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

def format_relative_time(diff_sec: float) -> Tuple[str, str]:
    if diff_sec < 60:
        return "Just now", "همین الان"
    elif diff_sec < 3600:
        mins = max(1, int(diff_sec // 60))
        return f"{mins} mins ago", f"{mins} دقیقه پیش"
    elif diff_sec < 86400:
        hrs = int(diff_sec // 3600)
        return f"{hrs} hrs ago", f"{hrs} ساعت پیش"
    else:
        days = int(diff_sec // 86400)
        return f"{days} days ago", f"{days} روز پیش"

def get_all_users_activity() -> Dict[str, dict]:
    """
    Computes live online status, last seen timestamp, and last connected IP
    by combining portal.db, 3x-ui.db client_traffics, inbound_client_ips, and access.log.
    """
    activity: Dict[str, dict] = {}
    now = datetime.datetime.now()

    # 1. Read from portal.db (last_ip, last_seen)
    try:
        conn_p = get_db()
        cur_p = conn_p.cursor()
        cur_p.execute("SELECT email, sub_id, uuid, last_ip, last_seen FROM users")
        for r in cur_p.fetchall():
            email = (r["email"] or "").lower()
            if not email:
                continue
            last_seen_val = r["last_seen"]
            last_ip_val = r["last_ip"] or ""
            act_entry = {
                "last_seen_str": last_seen_val or "",
                "last_seen_en": "Never",
                "last_seen_fa": "تاکنون متصل نشده",
                "is_online": False,
                "last_ip": last_ip_val,
                "latest_dt": None
            }
            if last_seen_val:
                try:
                    dt = datetime.datetime.strptime(last_seen_val, "%Y-%m-%d %H:%M:%S")
                    diff_sec = (now - dt).total_seconds()
                    act_entry["latest_dt"] = dt
                    act_entry["is_online"] = (diff_sec >= -60 and diff_sec < 900)
                    en_str, fa_str = format_relative_time(diff_sec)
                    act_entry["last_seen_en"] = en_str
                    act_entry["last_seen_fa"] = fa_str
                except Exception:
                    pass
            activity[email] = act_entry
            if r["sub_id"]:
                activity[r["sub_id"]] = act_entry
            if r["uuid"]:
                activity[r["uuid"]] = act_entry
        conn_p.close()
    except Exception as e:
        print(f"[Portal DB Activity Error] {e}")

    # 2. Read from 3x-ui.db (client_traffics: last_online)
    if os.path.exists(DB_PATH):
        try:
            conn_x = sqlite3.connect(DB_PATH, timeout=5.0)
            cur_x = conn_x.cursor()
            try:
                cur_x.execute("SELECT email, last_online FROM client_traffics WHERE last_online > 0")
                for email_raw, last_online_ms in cur_x.fetchall():
                    if not email_raw:
                        continue
                    email_key = email_raw.lower()
                    dt = datetime.datetime.fromtimestamp(last_online_ms / 1000.0)
                    diff_sec = (now - dt).total_seconds()
                    is_online = (diff_sec >= -60 and diff_sec < 900)
                    en_str, fa_str = format_relative_time(diff_sec)

                    if email_key not in activity or not activity[email_key].get("latest_dt") or dt > activity[email_key]["latest_dt"]:
                        prev_ip = activity.get(email_key, {}).get("last_ip", "")
                        activity[email_key] = {
                            "last_seen_str": dt.strftime("%Y-%m-%d %H:%M:%S"),
                            "last_seen_en": en_str,
                            "last_seen_fa": fa_str,
                            "is_online": is_online,
                            "last_ip": prev_ip,
                            "latest_dt": dt
                        }
                    else:
                        if is_online:
                            activity[email_key]["is_online"] = True
            except Exception:
                pass

            # 3. Read client IPs from inbound_client_ips in 3x-ui.db if present
            try:
                cur_x.execute("SELECT client_email, ips FROM inbound_client_ips WHERE ips IS NOT NULL AND ips != ''")
                for c_email, ips in cur_x.fetchall():
                    if c_email and ips:
                        ek = c_email.lower()
                        clean_ip = ips.split(",")[0].strip()
                        if clean_ip and ek in activity and not activity[ek].get("last_ip"):
                            activity[ek]["last_ip"] = clean_ip
            except Exception:
                pass

            conn_x.close()
        except Exception as e:
            print(f"[3x-ui DB Activity Error] {e}")

    # 4. Read recent lines from access.log
    if os.path.exists(ACCESS_LOG):
        try:
            with open(ACCESS_LOG, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-4000:]
            for line in reversed(lines):
                line_str = line.strip()
                if not line_str:
                    continue
                m_email = re.search(r"email:\s*([^\s]+)", line_str)
                if not m_email:
                    continue
                email = m_email.group(1).strip().lower()
                # Extract client IP from line if present (e.g. "from 5.234.12.98:45123" or "5.234.12.98:45123")
                line_ip = ""
                m_ip = re.search(r"(?:from\s+)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):\d+", line_str)
                if m_ip:
                    cand = m_ip.group(1)
                    if cand not in ["127.0.0.1", "0.0.0.0"] and not cand.startswith("10.") and not cand.startswith("192.168."):
                        line_ip = cand

                m_time = re.match(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line_str)
                if m_time:
                    try:
                        dt = datetime.datetime.strptime(m_time.group(1), "%Y/%m/%d %H:%M:%S")
                        diff_sec = (now - dt).total_seconds()
                        is_online = (diff_sec >= -60 and diff_sec < 900)
                        en_str, fa_str = format_relative_time(diff_sec)
                        prev_ip = line_ip or activity.get(email, {}).get("last_ip", "")
                        if email not in activity or not activity[email].get("latest_dt") or dt > activity[email]["latest_dt"]:
                            activity[email] = {
                                "last_seen_str": dt.strftime("%Y-%m-%d %H:%M:%S"),
                                "last_seen_en": en_str,
                                "last_seen_fa": fa_str,
                                "is_online": is_online,
                                "last_ip": prev_ip,
                                "latest_dt": dt
                            }
                        else:
                            if line_ip and not activity[email].get("last_ip"):
                                activity[email]["last_ip"] = line_ip
                            if is_online:
                                activity[email]["is_online"] = True
                    except Exception:
                        pass
        except Exception:
            pass

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

def decode_proc_bytes(line_bytes: bytes) -> str:
    """Safely decodes raw bytes from process streams handling UTF-8, UTF-8-BOM, UTF-16, and ANSI."""
    if not line_bytes:
        return ""
    for enc in ("utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return line_bytes.decode(enc)
        except Exception:
            continue
    return line_bytes.decode("utf-8", errors="replace")

def detect_tunnel_urls_from_logs():
    """Scans portal.log and setup-diagnostics.log for the latest trycloudflare.com URLs."""
    candidates = [
        os.path.join(BASE_DIR, "portal.log"),
        os.path.join(BASE_DIR, "setup-diagnostics.log"),
    ]
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            content = ""
            for enc in ("utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1"):
                try:
                    with open(path, "r", encoding=enc, errors="ignore") as f:
                        content = f.read()
                    if content:
                        break
                except Exception:
                    continue
            if not content:
                continue

            lines = content.splitlines()
            for line in reversed(lines):
                if not tunnel_state.get("portal_host"):
                    m_portal = re.search(r"(?:Admin Portal & Sub Tunnel Active:\s*|portal.*?)https://([a-zA-Z0-9-]+\.trycloudflare\.com)", line, re.I)
                    if m_portal:
                        host = m_portal.group(1)
                        tunnel_state["portal_host"] = host
                        tunnel_state["portal_url"] = f"https://{host}"
                        tunnel_state["sub_host"] = host
                        tunnel_state["sub_url"] = f"https://{host}"
                if not tunnel_state.get("vpn_host"):
                    m_vpn = re.search(r"(?:VPN Tunnel Active:\s*|vpn.*?)https://([a-zA-Z0-9-]+\.trycloudflare\.com)", line, re.I)
                    if m_vpn:
                        host = m_vpn.group(1)
                        tunnel_state["vpn_host"] = host
                        tunnel_state["vpn_url"] = f"https://{host}"

                if tunnel_state.get("portal_host") and tunnel_state.get("vpn_host"):
                    break

            # Fallback scan for any trycloudflare URLs if still missing
            if not tunnel_state.get("portal_host") or not tunnel_state.get("vpn_host"):
                all_urls = re.findall(r"https://([a-zA-Z0-9-]+\.trycloudflare\.com)", content)
                for host in reversed(all_urls):
                    if not tunnel_state.get("portal_host"):
                        tunnel_state["portal_host"] = host
                        tunnel_state["portal_url"] = f"https://{host}"
                        tunnel_state["sub_host"] = host
                        tunnel_state["sub_url"] = f"https://{host}"
                    elif not tunnel_state.get("vpn_host") and host != tunnel_state.get("portal_host"):
                        tunnel_state["vpn_host"] = host
                        tunnel_state["vpn_url"] = f"https://{host}"
        except Exception as e:
            print(f"[Detect Logs Error] {path}: {e}")

def update_tunnel_state_from_request(request: Optional[Request]):
    """Captures and sets trycloudflare.com hostname from incoming HTTP Host/X-Forwarded-Host header."""
    if not request:
        return
    try:
        raw_host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
        host = raw_host.split(":")[0].strip()
        if re.match(r"^[a-zA-Z0-9-]+\.trycloudflare\.com$", host, re.I):
            tunnel_state["portal_host"] = host
            tunnel_state["portal_url"] = f"https://{host}"
            tunnel_state["sub_host"] = host
            tunnel_state["sub_url"] = f"https://{host}"
            tunnel_state["last_sync"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass

def get_clean_vpn_host() -> str:
    h = tunnel_state.get("vpn_host", "")
    if not h or h in ("Pending...", "Unknown", "127.0.0.1", "Initializing..."):
        detect_tunnel_urls_from_logs()
        h = tunnel_state.get("vpn_host", "")
    if not h or h in ("Pending...", "Unknown", "127.0.0.1", "Initializing..."):
        return "127.0.0.1"
    return h

def get_clean_portal_host(request: Optional[Request] = None) -> str:
    if request:
        update_tunnel_state_from_request(request)
    h = tunnel_state.get("portal_host", "")
    if not h or h in ("Pending...", "Unknown", "127.0.0.1", "Initializing..."):
        detect_tunnel_urls_from_logs()
        h = tunnel_state.get("portal_host", "")
    if not h or h in ("Pending...", "Unknown", "127.0.0.1", "Initializing..."):
        return ""
    return h

cf_tunnel_backoff_until = 0

def kill_orphan_cloudflared(exclude_pids=None):
    if exclude_pids is None:
        exclude_pids = set()
    try:
        if os.name == "nt":
            output = subprocess.check_output(
                ["tasklist", "/fi", "imagename eq cloudflared.exe", "/fo", "csv", "/nh"],
                text=True, stderr=subprocess.DEVNULL
            )
            for row in output.strip().splitlines():
                parts = [p.strip(' "') for p in row.split(",")]
                if len(parts) >= 2 and parts[1].isdigit():
                    pid = int(parts[1])
                    if pid not in exclude_pids:
                        print(f"[Cleanup] Terminating orphan cloudflared PID {pid}...")
                        subprocess.run(["taskkill", "/f", "/pid", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def stream_reader(proc, name, is_vpn=True):
    global cf_tunnel_backoff_until
    try:
        while True:
            line_bytes = proc.stderr.readline()
            if not line_bytes:
                break
            line = decode_proc_bytes(line_bytes)

            if "status 429" in line or "quick tunnel provisioning failed" in line:
                print(f"[TUNNEL] Rate limit (429) detected on {name}. Cooling down for 120s: {line.strip()}")
                cf_tunnel_backoff_until = time.time() + 120
                tunnel_state[f"{name}_error"] = "Cloudflare quick tunnel rate limited (HTTP 429). Cooling down."

            m = re.search(r"https://([a-zA-Z0-9-]+\.trycloudflare\.com)", line)
            if m:
                host = m.group(1)
                url = f"https://{host}"
                if is_vpn:
                    old_host = tunnel_state.get("vpn_host")
                    tunnel_state["vpn_url"] = url
                    tunnel_state["vpn_host"] = host
                    tunnel_state.pop("vpn_error", None)
                    print(f"[TUNNEL] VPN Tunnel Active: {url}")
                    if old_host and old_host != host:
                        send_telegram_alert_async(f"🚨 <b>Home VPN Tunnel Updated!</b>\nNew VPN Server: <code>{host}</code>\nSubscription links auto-updated.")
                else:
                    old_sub = tunnel_state.get("portal_host")
                    tunnel_state["sub_url"] = url
                    tunnel_state["sub_host"] = host
                    tunnel_state["portal_url"] = url
                    tunnel_state["portal_host"] = host
                    tunnel_state.pop("sub_error", None)
                    print(f"[TUNNEL] Admin Portal & Sub Tunnel Active: {url}")
                    if old_sub and old_sub != host:
                        send_telegram_alert_async(f"🌐 <b>Family VPN Portal Updated!</b>\nNew Remote URL: {url}")

                tunnel_state["last_sync"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                sync_3xui_with_tunnels()
    except Exception as e:
        print(f"[Stream Reader Error] {name}: {e}")

def ensure_3xui_provisioned():
    """Auto-provisions 3x-ui admin credentials, API token, and default VLESS inbound."""
    try:
        if not os.path.exists(DB_PATH) and os.path.exists(XUI_EXE):
            subprocess.run([XUI_EXE, "setting", "-username", "admin", "-password", "admin"], cwd=XUI_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH, timeout=5.0)
            cur = conn.cursor()
            try:
                cur.execute("SELECT id FROM api_tokens WHERE token = ?", (API_TOKEN,))
                if not cur.fetchone():
                    cur.execute("INSERT OR REPLACE INTO api_tokens (id, name, token, enabled, created_at, scope, expires_at) VALUES (1, 'portal', ?, 1, ?, 'admin', 0)", (API_TOKEN, int(time.time())))
                    conn.commit()
            except Exception as e_tok:
                pass

            try:
                cur.execute("SELECT id FROM inbounds WHERE port = ?", (VPN_PORT,))
                if not cur.fetchone():
                    cur.execute("""
                        INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
                        VALUES (1, 0, 0, 0, 'Family-VPN-VLESS', 1, 0, '', ?, 'vless', ?, ?, 'inbound-10000', ?)
                    """, (
                        VPN_PORT,
                        json.dumps({"clients": [], "decryption": "none", "fallbacks": []}),
                        json.dumps({"network": "ws", "security": "none", "wsSettings": {"path": "/vpn-ws", "headers": {"Host": ""}}}),
                        json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"]})
                    ))
                    conn.commit()
            except Exception as e_ib:
                pass
            conn.close()
    except Exception as e:
        print(f"[3x-ui Provision Error] {e}")

def ensure_services():
    global cf_tunnel_backoff_until
    # 0. Scan logs for tunnel URLs
    detect_tunnel_urls_from_logs()

    # 1. 3x-ui Engine check
    if not is_port_open(XUI_PORT):
        print(f"[Service] Starting 3x-ui engine on port {XUI_PORT}...")
        if os.path.exists(XUI_EXE):
            ensure_3xui_provisioned()
            p = subprocess.Popen([XUI_EXE, "run"], cwd=XUI_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tunnel_state["xui_process"] = p
            time.sleep(2)
            ensure_3xui_provisioned()

    # 2. Check Cloudflare Tunnel backoff cooldown
    now = time.time()
    if now < cf_tunnel_backoff_until:
        return

    tracked_pids = set()
    vpn_p = tunnel_state.get("vpn_process")
    if vpn_p and vpn_p.poll() is None:
        tracked_pids.add(vpn_p.pid)
    sub_p = tunnel_state.get("sub_process")
    if sub_p and sub_p.poll() is None:
        tracked_pids.add(sub_p.pid)

    if os.path.exists(CLOUDFLARED_EXE):
        # Terminate orphan cloudflared if either process needs restart
        if (not vpn_p or vpn_p.poll() is not None) or (not sub_p or sub_p.poll() is not None):
            kill_orphan_cloudflared(exclude_pids=tracked_pids)

        # Cloudflare VPN Tunnel (Port VPN_PORT)
        if not tunnel_state.get("vpn_process") or tunnel_state["vpn_process"].poll() is not None:
            print(f"[Service] Launching Cloudflare VPN Tunnel (port {VPN_PORT}) with HTTP/2 protocol...")
            p_vpn = subprocess.Popen(
                [CLOUDFLARED_EXE, "tunnel", "--protocol", "http2", "--no-autoupdate", "--url", f"http://127.0.0.1:{VPN_PORT}"],
                stderr=subprocess.PIPE, bufsize=0
            )
            tunnel_state["vpn_process"] = p_vpn
            threading.Thread(target=stream_reader, args=(p_vpn, "cf-vpn", True), daemon=True).start()

        # Cloudflare Admin Portal & Subscription Tunnel (Port PORTAL_PORT)
        if not tunnel_state.get("sub_process") or tunnel_state["sub_process"].poll() is not None:
            print(f"[Service] Launching Cloudflare Admin Portal & Sub Tunnel (port {PORTAL_PORT}) with HTTP/2 protocol...")
            p_sub = subprocess.Popen(
                [CLOUDFLARED_EXE, "tunnel", "--protocol", "http2", "--no-autoupdate", "--url", f"http://127.0.0.1:{PORTAL_PORT}"],
                stderr=subprocess.PIPE, bufsize=0
            )
            tunnel_state["sub_process"] = p_sub
            threading.Thread(target=stream_reader, args=(p_sub, "cf-sub", False), daemon=True).start()

def sync_xray_policy_and_limits():
    """Enforces per-user bandwidth limits in Xray policy and 3x-ui configuration."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT email, uuid, bandwidth_limit_mbps FROM users")
        user_limits = {}
        for r in cur.fetchall():
            bw = r["bandwidth_limit_mbps"] if ("bandwidth_limit_mbps" in r.keys() and r["bandwidth_limit_mbps"] is not None) else 10
            if r["email"]:
                user_limits[r["email"].lower()] = int(bw)
            if r["uuid"]:
                user_limits[r["uuid"]] = int(bw)
        conn.close()

        # Update Xray config.json
        xray_cfg_path = os.path.join(XUI_DIR, "bin", "config.json")
        if os.path.exists(xray_cfg_path):
            with open(xray_cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)

            if "policy" not in cfg:
                cfg["policy"] = {"levels": {}, "system": {}}
            if "levels" not in cfg["policy"]:
                cfg["policy"]["levels"] = {}

            # 0 = Unlimited
            cfg["policy"]["levels"]["0"] = {
                "statsUserUplink": True,
                "statsUserDownlink": True,
                "statsUserOnline": True,
                "bufferSize": 0
            }

            known_tiers = {0, 5, 10, 20, 25, 50}
            for bw in user_limits.values():
                known_tiers.add(int(bw))

            for tier in known_tiers:
                if tier > 0:
                    rate_kbs = tier * 125 # 10 Mbps = 1250 KB/s
                    cfg["policy"]["levels"][str(tier)] = {
                        "statsUserUplink": True,
                        "statsUserDownlink": True,
                        "statsUserOnline": True,
                        "bufferSize": rate_kbs,
                        "connIdle": 300,
                        "handshake": 4,
                        "downlinkLimit": rate_kbs,
                        "uplinkLimit": rate_kbs
                    }

            for ib in cfg.get("inbounds", []):
                if ib.get("port") == VPN_PORT or ib.get("port") == 10000:
                    clients = ib.get("settings", {}).get("clients", [])
                    for c in clients:
                        c_email = c.get("email", "").lower()
                        c_id = c.get("id", "")
                        tier = user_limits.get(c_email, user_limits.get(c_id, 10))
                        c["level"] = int(tier)

            with open(xray_cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)

        # Update x-ui.db
        xui_db_path = os.path.join(XUI_DIR, "x-ui.db")
        if os.path.exists(xui_db_path):
            try:
                conn_xui = sqlite3.connect(xui_db_path)
                cur_xui = conn_xui.cursor()
                cur_xui.execute("SELECT id, settings FROM inbounds WHERE port = ? OR port = 10000", (VPN_PORT,))
                row = cur_xui.fetchone()
                if row:
                    ib_id, raw_settings = row[0], row[1]
                    if isinstance(raw_settings, str):
                        ib_settings = json.loads(raw_settings)
                        for c in ib_settings.get("clients", []):
                            c_email = c.get("email", "").lower()
                            c_id = c.get("id", "")
                            tier = user_limits.get(c_email, user_limits.get(c_id, 10))
                            c["level"] = int(tier)
                        cur_xui.execute("UPDATE inbounds SET settings = ? WHERE id = ?", (json.dumps(ib_settings), ib_id))
                        conn_xui.commit()
                conn_xui.close()
            except Exception as e:
                print(f"[Traffic Shaping DB Error] {e}")

        # Update via 3x-ui session if active
        try:
            s, base_url = get_3xui_auth_session()
            ib = get_inbound_and_clients(session=s, base_url=base_url)
            if ib and ib.get("id"):
                ib_settings = ib.get("settings", {})
                if isinstance(ib_settings, str):
                    ib_settings = json.loads(ib_settings)
                for c in ib_settings.get("clients", []):
                    c_email = c.get("email", "").lower()
                    c_id = c.get("id", "")
                    tier = user_limits.get(c_email, user_limits.get(c_id, 10))
                    c["level"] = int(tier)
                ib["settings"] = json.dumps(ib_settings) if isinstance(ib.get("settings"), dict) else json.dumps(ib_settings)
                if isinstance(ib.get("streamSettings"), dict):
                    ib["streamSettings"] = json.dumps(ib.get("streamSettings"))
                if isinstance(ib.get("sniffing"), dict):
                    ib["sniffing"] = json.dumps(ib.get("sniffing"))
                s.post(f"{base_url}/panel/api/inbounds/update/{ib['id']}", json=ib, timeout=3)
        except Exception:
            pass
    except Exception as e:
        print(f"[Traffic Shaping Error] {e}")

def sync_3xui_with_tunnels():
    vpn_host = get_clean_vpn_host()
    if not vpn_host or vpn_host == "127.0.0.1":
        return
    try:
        s, base_url = get_3xui_auth_session()
        r = s.get(f"{base_url}/panel/api/inbounds/list", timeout=2.0)
        if r.status_code == 200:
            data = r.json()
            inbounds = data.get("obj", [])
            inbound = next((ib for ib in inbounds if ib.get("port") == VPN_PORT or ib.get("port") == 10000), None)
            if not inbound:
                new_inbound = {
                    "up": 0, "down": 0, "total": 0,
                    "remark": "Family-VPN-VLESS", "enable": True,
                    "expiryTime": 0, "listen": "", "port": VPN_PORT, "protocol": "vless",
                    "settings": json.dumps({"clients": [], "decryption": "none", "fallbacks": []}),
                    "streamSettings": json.dumps({
                        "network": "ws", "security": "none",
                        "wsSettings": {"path": "/vpn-ws", "headers": {"Host": vpn_host}}
                    }),
                    "sniffing": json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"]})
                }
                s.post(f"{base_url}/panel/api/inbounds/add", json=new_inbound, timeout=2.0)
            elif inbound:
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
                    r_upd = s.post(f"{base_url}/panel/api/inbounds/update/{inbound['id']}", json=inbound, timeout=2.0)
                    if r_upd.status_code == 200:
                        print(f"[3x-ui Sync] Inbound 10000 updated with Host={vpn_host}")
        sync_xray_policy_and_limits()
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

def build_sub_link(sub_id: str, format_type: str = "smart", request: Optional[Request] = None) -> str:
    portal_host = get_clean_portal_host(request)
    base = f"https://{portal_host}" if portal_host else f"http://127.0.0.1:{PORTAL_PORT}"
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
                "fragment": True,
                "fragment_fallback_delay": "500ms"
            },
            "transport": {
                "type": "ws",
                "path": "/vpn-ws",
                "headers": {
                    "Host": vpn_host
                }
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
                "fragment": True,
                "fragment_fallback_delay": "500ms"
            },
            "transport": {
                "type": "httpupgrade",
                "path": "/vpn-ws",
                "host": vpn_host
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

    # Strict Sing-box schema verification: ensure tls.fragment is boolean and never a dictionary
    for ob in profile.get("outbounds", []):
        tls_cfg = ob.get("tls")
        if isinstance(tls_cfg, dict):
            if isinstance(tls_cfg.get("fragment"), dict) or tls_cfg.get("fragment") is None:
                tls_cfg["fragment"] = True
            if "fragment_fallback_delay" not in tls_cfg:
                tls_cfg["fragment_fallback_delay"] = "500ms"

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
        update_tunnel_state_from_request(request)
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
def get_singbox_subscription(sub_id: str, request: Request):
    if request:
        update_tunnel_state_from_request(request)
    detect_tunnel_urls_from_logs()

    target = None
    try:
        ib = get_inbound_and_clients()
        if ib:
            settings = ib.get("settings", {})
            if isinstance(settings, str):
                settings = json.loads(settings)
            clients = settings.get("clients", [])
            target = next((c for c in clients if c.get("subId") == sub_id or c.get("email") == sub_id), None)
    except Exception as e:
        print(f"[Sub JSON 3x-ui Error] {e}")

    if not target:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT uuid, email, sub_id FROM users WHERE sub_id = ? OR lower(email) = ?", (sub_id, sub_id.lower()))
        u_row = cur.fetchone()
        conn.close()
        if u_row:
            target = {"id": u_row["uuid"], "email": u_row["email"], "subId": u_row["sub_id"], "up": 0, "down": 0, "totalGB": 0}
        else:
            raise HTTPException(status_code=404, detail="Subscription not found")

    record_user_activity(target.get("email"), request)

    vpn_host = get_clean_vpn_host()
    sub_host = get_clean_portal_host(request) or "127.0.0.1"
    profile = build_resilient_singbox_profile(target.get("id"), target.get("email", "VPN"), vpn_host, sub_host)
    return JSONResponse(content=profile, headers={
        "Content-Disposition": f'attachment; filename="{target.get("email", "vpn")}-singbox.json"',
        "Profile-Title": f'{target.get("email", "Family-VPN")}',
        "Subscription-Userinfo": f"upload={target.get('up', 0)}; download={target.get('down', 0)}; total={target.get('totalGB', 0)}"
    })

@app.get("/sub/vless/{sub_id}", response_class=PlainTextResponse)
def get_vless_subscription(sub_id: str, request: Request):
    if request:
        update_tunnel_state_from_request(request)
    detect_tunnel_urls_from_logs()

    target = None
    try:
        ib = get_inbound_and_clients()
        if ib:
            settings = ib.get("settings", {})
            if isinstance(settings, str):
                settings = json.loads(settings)
            clients = settings.get("clients", [])
            target = next((c for c in clients if c.get("subId") == sub_id or c.get("email") == sub_id), None)
    except Exception as e:
        print(f"[Sub VLESS 3x-ui Error] {e}")

    if not target:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT uuid, email, sub_id FROM users WHERE sub_id = ? OR lower(email) = ?", (sub_id, sub_id.lower()))
        u_row = cur.fetchone()
        conn.close()
        if u_row:
            target = {"id": u_row["uuid"], "email": u_row["email"], "subId": u_row["sub_id"], "up": 0, "down": 0, "totalGB": 0}
        else:
            raise HTTPException(status_code=404, detail="Subscription not found")

    record_user_activity(target.get("email"), request)

    vpn_host = get_clean_vpn_host()
    uris = build_resilient_vless_links(target.get("id"), target.get("email", "VPN"), vpn_host)
    joined = "\n".join(uris)
    b64 = base64.b64encode(joined.encode("utf-8")).decode("utf-8")
    return PlainTextResponse(b64, headers={
        "Profile-Title": target.get("email", "Family-VPN"),
        "Subscription-Userinfo": f"upload={target.get('up', 0)}; download={target.get('down', 0)}; total={target.get('totalGB', 0)}",
        "profile-title": target.get("email", "Family-VPN"),
        "subscription-userinfo": f"upload={target.get('up', 0)}; download={target.get('down', 0)}; total={target.get('totalGB', 0)}"
    })

@app.get("/sub/{sub_id}")
def get_smart_subscription(sub_id: str, request: Request, format: Optional[str] = None):
    update_tunnel_state_from_request(request)
    ua = request.headers.get("user-agent", "").lower()
    accept = request.headers.get("accept", "").lower()

    if format == "json" or format == "singbox":
        return get_singbox_subscription(sub_id, request)
    elif format == "vless" or format == "base64":
        return get_vless_subscription(sub_id, request)

    if any(k in ua for k in ["hiddify", "sing-box", "foxray", "box"]) or "application/json" in accept:
        return get_singbox_subscription(sub_id, request)
    else:
        return get_vless_subscription(sub_id, request)

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
    return {"success": True, "message": msg, "redirect": "/dashboard", "user": user}

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

    record_user_activity(user["email"], request)

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
    update_tunnel_state_from_request(request)
    detect_tunnel_urls_from_logs()

    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    email = session.get("email", "")
    sub_id = session.get("sub_id", "")
    client_uuid = session.get("uuid", "")
    user_name = session.get("name", email)

    record_user_activity(email, request)

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
    bw_limit = 10
    try:
        conn_bw = get_db()
        cur_bw = conn_bw.cursor()
        cur_bw.execute("SELECT bandwidth_limit_mbps FROM users WHERE lower(email) = ? OR uuid = ?", (email.lower(), client_uuid))
        u_row = cur_bw.fetchone()
        if u_row and "bandwidth_limit_mbps" in u_row.keys() and u_row["bandwidth_limit_mbps"] is not None:
            bw_limit = int(u_row["bandwidth_limit_mbps"])
        conn_bw.close()
    except Exception:
        pass

    activity_map = get_all_users_activity()
    user_act = activity_map.get(email, {})
    is_online = user_act.get("is_online", False)
    last_seen_en = user_act.get("last_seen_en", "Never")
    last_seen_fa = user_act.get("last_seen_fa", "تاکنون متصل نشده")

    smart_sub_link = build_sub_link(sub_id, "smart", request)
    json_sub_link = build_sub_link(sub_id, "json", request)
    vless_sub_link = build_sub_link(sub_id, "vless", request)
    qr_b64 = generate_qr_b64(json_sub_link)

    vpn_host = get_clean_vpn_host()
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
        "farsi_instructions": build_farsi_instructions(email, json_sub_link),
        "bandwidth_limit_mbps": bw_limit
    }

@app.get("/api/status")
def get_api_status(request: Request):
    update_tunnel_state_from_request(request)
    detect_tunnel_urls_from_logs()

    admin_info = get_current_credentials_display()
    portal_host = get_clean_portal_host(request)
    portal_url = f"https://{portal_host}" if portal_host else f"http://127.0.0.1:{PORTAL_PORT}"
    vpn_host = get_clean_vpn_host()
    vpn_url = f"https://{vpn_host}" if vpn_host != "127.0.0.1" else "Initializing..."

    return {
        "xui_running": is_port_open(2053),
        "inbound_running": is_port_open(10000),
        "vpn_url": vpn_url,
        "vpn_host": vpn_host if vpn_host != "127.0.0.1" else "Pending...",
        "sub_url": portal_url,
        "sub_host": portal_host if portal_host else "Pending...",
        "portal_url": portal_url,
        "portal_host": portal_host if portal_host else "Pending...",
        "local_portal_url": f"http://127.0.0.1:{PORTAL_PORT}",
        "engine_url": f"http://127.0.0.1:{XUI_PORT}",
        "admin_username": admin_info.get("username", "admin"),
        "admin_password": admin_info.get("password", "********"),
        "is_custom_password": admin_info.get("is_custom", False),
        "iran_rules_loaded": True,
        "watchdog_status": tunnel_state.get("watchdog_status", "Healthy"),
        "last_sync": tunnel_state.get("last_sync", "Never")
    }

# ----------------- Admin API Endpoints ----------------- #

@app.get("/api/admin/overview")
def api_admin_overview(request: Request):
    update_tunnel_state_from_request(request)
    detect_tunnel_urls_from_logs()

    invite_code = get_invite_code()
    portal_host = get_clean_portal_host(request)
    shareable_invite_url = f"https://{portal_host}/?invite={invite_code}" if portal_host else f"http://127.0.0.1:{PORTAL_PORT}/?invite={invite_code}"
    portal_url = f"https://{portal_host}" if portal_host else f"http://127.0.0.1:{PORTAL_PORT}"
    vpn_host = get_clean_vpn_host()
    vpn_url = f"https://{vpn_host}" if vpn_host != "127.0.0.1" else "Connecting..."

    lan_ip = get_lan_ip()
    lan_portal_url = f"http://{lan_ip}:{PORTAL_PORT}"
    local_portal_url = f"http://127.0.0.1:{PORTAL_PORT}"

    # Query all users & clients
    total_db_users = 0
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE role != 'admin'")
        total_db_users = cur.fetchone()[0]
        conn.close()
    except Exception as e:
        print(f"[Admin Overview DB Error] {e}")

    total_up = 0
    total_down = 0
    client_count = 0
    try:
        ib = get_inbound_and_clients()
        if ib:
            stats = ib.get("clientStats") or []
            for s in stats:
                total_up += s.get("up", 0)
                total_down += s.get("down", 0)
            settings = ib.get("settings", {})
            if isinstance(settings, str):
                settings = json.loads(settings)
            client_count = len(settings.get("clients", []))
    except Exception as e:
        print(f"[Admin Overview 3x-ui Error] {e}")

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
        "vpn_url": vpn_url,
        "vpn_host": vpn_host if vpn_host != "127.0.0.1" else "Pending...",
        "portal_url": portal_url,
        "portal_host": portal_host if portal_host else "Pending...",
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
def list_clients(request: Request):
    update_tunnel_state_from_request(request)
    detect_tunnel_urls_from_logs()

    user_bw_map = {}
    db_users = []
    try:
        conn_bw = get_db()
        cur_bw = conn_bw.cursor()
        cur_bw.execute("SELECT id, name, email, uuid, sub_id, role, bandwidth_limit_mbps FROM users")
        for r in cur_bw.fetchall():
            bw = r["bandwidth_limit_mbps"] if ("bandwidth_limit_mbps" in r.keys() and r["bandwidth_limit_mbps"] is not None) else 10
            if r["email"]:
                user_bw_map[r["email"].lower()] = int(bw)
            if r["uuid"]:
                user_bw_map[r["uuid"]] = int(bw)
            if r["email"] and r["role"] != "admin":
                db_users.append(dict(r))
        conn_bw.close()
    except Exception as e:
        print(f"[List Clients DB Error] {e}")

    raw_clients = []
    client_stats = []
    try:
        ib = get_inbound_and_clients()
        if ib:
            settings = ib.get("settings", {})
            if isinstance(settings, str):
                settings = json.loads(settings)
            raw_clients = settings.get("clients", [])
            client_stats = ib.get("clientStats") or []
    except Exception as e:
        print(f"[List Clients 3x-ui Error] {e}")

    # Fallback to DB users if 3x-ui is empty or unreachable
    if not raw_clients and db_users:
        raw_clients = [
            {
                "id": u.get("uuid"),
                "email": u.get("email"),
                "subId": u.get("sub_id") or u.get("email"),
                "totalGB": 0,
                "expiryTime": 0,
                "enable": True
            }
            for u in db_users
        ]
    elif db_users:
        existing_emails = {c.get("email", "").lower() for c in raw_clients}
        for u in db_users:
            if u.get("email", "").lower() not in existing_emails:
                raw_clients.append({
                    "id": u.get("uuid"),
                    "email": u.get("email"),
                    "subId": u.get("sub_id") or u.get("email"),
                    "totalGB": 0,
                    "expiryTime": 0,
                    "enable": True
                })

    stats_map = {cs.get("email"): cs for cs in client_stats if cs.get("email")}
    activity_map = get_all_users_activity()

    result = []
    total_up = 0
    total_down = 0
    now_ms = int(time.time() * 1000)
    vpn_host = get_clean_vpn_host()

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

        sub_id = c.get("subId", email)
        client_uuid = c.get("id") or ""

        act = activity_map.get(email.lower()) or activity_map.get(client_uuid) or activity_map.get(sub_id) or {}
        is_online = act.get("is_online", False)
        last_seen_en = act.get("last_seen_en", "Never")
        last_seen_fa = act.get("last_seen_fa", "تاکنون متصل نشده")
        last_ip = act.get("last_ip") or "---"

        smart_sub_link = build_sub_link(sub_id, "smart", request)
        json_sub_link = build_sub_link(sub_id, "json", request)
        vless_sub_link = build_sub_link(sub_id, "vless", request)
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
            "last_ip": last_ip,
            "enable": c.get("enable", True),
            "smart_sub_link": smart_sub_link,
            "json_sub_link": json_sub_link,
            "vless_sub_link": vless_sub_link,
            "vless_links": vless_links,
            "smart_qr_b64": smart_qr_b64,
            "farsi_instructions": build_farsi_instructions(email, json_sub_link),
            "bandwidth_limit_mbps": user_bw_map.get(email.lower(), user_bw_map.get(client_uuid, 10))
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
    bandwidth_limit_mbps: int = 10

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
                    INSERT INTO users (name, email, password_hash, salt, role, sub_id, uuid, limit_gb, expiry_days, bandwidth_limit_mbps, created_at)
                    VALUES (?, ?, ?, ?, 'user', ?, ?, ?, ?, ?, ?)
                """, (name, name, default_hash, default_salt, sub_id, client_uuid, req.limit_gb, req.expiry_days, req.bandwidth_limit_mbps, now_str))
                conn.commit()
                sync_xray_policy_and_limits()
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Create Client DB Error] {e}")

        return {"success": True, "uuid": client_uuid, "subId": sub_id, "email": name}
    else:
        raise HTTPException(status_code=500, detail=f"Failed to add client: {r.text}")

class BandwidthUpdateReq(BaseModel):
    bandwidth_limit_mbps: int = 10

@app.post("/api/admin/users/{user_id}/bandwidth")
def api_set_user_bandwidth(user_id: int, req: BandwidthUpdateReq):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, uuid FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    cur.execute("UPDATE users SET bandwidth_limit_mbps = ? WHERE id = ?", (req.bandwidth_limit_mbps, user_id))
    conn.commit()
    conn.close()
    sync_xray_policy_and_limits()
    return {"success": True, "user_id": user_id, "bandwidth_limit_mbps": req.bandwidth_limit_mbps}

@app.post("/api/admin/client/{email}/bandwidth")
def api_set_client_bandwidth(email: str, req: BandwidthUpdateReq):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET bandwidth_limit_mbps = ? WHERE lower(email) = ? OR uuid = ?", (req.bandwidth_limit_mbps, email.lower(), email))
    cur.execute("SELECT id FROM users WHERE lower(email) = ? OR uuid = ?", (email.lower(), email))
    if not cur.fetchone():
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("""
            INSERT INTO users (name, email, password_hash, salt, role, sub_id, uuid, created_at, bandwidth_limit_mbps)
            VALUES (?, ?, '', '', 'user', ?, ?, ?, ?)
        """, (email, email, email, email, now_str, req.bandwidth_limit_mbps))
    conn.commit()
    conn.close()
    sync_xray_policy_and_limits()
    return {"success": True, "email": email, "bandwidth_limit_mbps": req.bandwidth_limit_mbps}

@app.post("/api/clients/{client_id}/bandwidth")
def api_set_client_id_bandwidth(client_id: str, req: BandwidthUpdateReq):
    return api_set_client_bandwidth(client_id, req)

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

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE lower(email) = ? OR uuid = ?", (email_to_delete.lower(), client_id))
        if cur.fetchone():
            cur.execute("DELETE FROM users WHERE lower(email) = ? OR uuid = ?", (email_to_delete.lower(), client_id))
            conn.commit()
            conn.close()
            sync_xray_policy_and_limits()
            return {"success": True}
        conn.close()
    except Exception:
        pass

    return {"success": True}

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

class DetectChatIdReq(BaseModel):
    bot_token: Optional[str] = None

@app.post("/api/telegram/detect-chat-id")
def api_detect_chat_id(req: Optional[DetectChatIdReq] = None):
    cfg = load_telegram_config()
    token = ""
    if req and req.bot_token and req.bot_token.strip():
        token = req.bot_token.strip()
    if not token:
        token = cfg.get("bot_token", "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Telegram Bot Token is required to detect Chat ID.")
    try:
        url = f"https://api.telegram.org/bot{token}/getUpdates"
        r = requests.get(url, timeout=8)
        if r.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Telegram API error: {r.text}")
        data = r.json()
        results = data.get("result", [])
        if not results:
            return {
                "success": False,
                "message": "No incoming messages found. Please open your bot in Telegram, send /start, and try again."
            }
        latest_chat_id = None
        user_name = None
        for item in reversed(results):
            msg = item.get("message") or item.get("edited_message") or item.get("channel_post") or item.get("my_chat_member")
            if msg and "chat" in msg and "id" in msg["chat"]:
                latest_chat_id = str(msg["chat"]["id"])
                user_name = msg["chat"].get("username") or msg["chat"].get("first_name")
                break
        if not latest_chat_id:
            return {"success": False, "message": "Could not extract Chat ID from bot updates."}
        
        cfg["chat_id"] = latest_chat_id
        cfg["bot_token"] = token
        cfg["enabled"] = True
        save_telegram_config(cfg)
        return {
            "success": True,
            "chat_id": latest_chat_id,
            "username": user_name,
            "message": f"Successfully detected Chat ID {latest_chat_id} and saved configuration!"
        }
    except HTTPException:
        raise
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
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          fontFamily: {
            sans: ['Inter', 'Vazirmatn', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'system-ui', 'sans-serif'],
          },
          colors: {
            brand: { 500: '#6366f1', 600: '#4f46e5', 700: '#4338ca' }
          }
        }
      }
    }
  </script>
  <style>
    body { font-family: 'Inter', 'Vazirmatn', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background-color: #0B0F19; }
    html:not(.light) body { background-color: #0B0F19 !important; color: #F1F5F9 !important; }
    .glass-card { background: rgba(17, 24, 39, 0.85); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.08); }
    [dir="rtl"] .ltr-only { direction: ltr; text-align: left; }
    [dir="ltr"] .rtl-only { direction: rtl; text-align: right; }
    html.light body { background-color: #F8FAFC !important; color: #0F172A !important; }
    html.light .glass-card { background: rgba(255, 255, 255, 0.95) !important; border-color: rgba(0, 0, 0, 0.08) !important; color: #0F172A !important; box-shadow: 0 4px 20px -2px rgba(0,0,0,0.05); }
    html.light header { background-color: rgba(255, 255, 255, 0.85) !important; border-color: rgba(0, 0, 0, 0.08) !important; }
    html.light .text-white { color: #0F172A !important; }
    html.light .text-slate-400 { color: #64748B !important; }
    html.light .text-slate-300 { color: #475569 !important; }
    html.light .text-slate-200 { color: #334155 !important; }
    html.light .bg-slate-900, html.light [class*="bg-slate-900"], html.light .bg-slate-950 { background-color: #F1F5F9 !important; }
    html.light .bg-slate-800, html.light [class*="bg-slate-800"] { background-color: #E2E8F0 !important; border-color: #CBD5E1 !important; color: #1E293B !important; }
    html.light .border-slate-800, html.light [class*="border-slate-800"], html.light .border-slate-700 { border-color: #E2E8F0 !important; }
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
        <a href="#authCard" onclick="switchAuthTab('login')" class="inline-flex px-3 py-1.5 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 text-xs font-semibold transition items-center gap-1.5 shadow-sm">
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

DASHBOARD_PAGE_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title id="docTitle">داشبورد کاربری | Family Home VPN</title>
  __COMMON_HEADER__
</head>
<body class="bg-[#0B0F19] text-slate-100 min-h-screen selection:bg-indigo-500 selection:text-white flex flex-col justify-between antialiased">
  
  <!-- Navigation Header -->
  <header class="border-b border-white/[0.08] bg-[#0B0F19]/80 sticky top-0 z-40 backdrop-blur-md">
    <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded-xl bg-indigo-600 flex items-center justify-center text-white shadow-sm font-bold text-xs tracking-wider">
          VPN
        </div>
        <div>
          <span class="font-bold text-sm sm:text-base text-white tracking-tight">Family Home VPN</span>
        </div>
      </div>

      <!-- Essential Nav Links Only -->
      <div class="flex items-center gap-2 sm:gap-3 text-xs">
        <a href="/dashboard" class="px-3 py-1.5 rounded-lg text-slate-200 hover:text-white hover:bg-white/[0.05] transition font-medium">
          <span id="navDash">داشبورد</span>
        </a>
        <a href="#direct-routing" onclick="openDirectDomainsModal()" class="px-3 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/[0.05] transition font-medium">
          <span id="navDirect">مسیر مستقیم ایران</span>
        </a>
        <a href="/help" class="px-3 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/[0.05] transition font-medium">
          <span id="navHelp">راهنما</span>
        </a>
        <button onclick="toggleLang()" class="px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/[0.05] transition font-semibold">
          <span id="langSwitchLabel">English</span>
        </button>
        <button onclick="toggleTheme()" class="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/[0.05] transition" title="Toggle Theme">
          <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
        </button>
        <a id="linkAdmin" href="/admin" class="px-2.5 py-1.5 rounded-lg bg-indigo-600/20 text-indigo-300 hover:bg-indigo-600/30 transition font-medium">
          <span id="navAdmin">پنل ادمین</span>
        </a>
        <a href="/logout" class="px-2.5 py-1.5 rounded-lg text-rose-400 hover:bg-rose-500/10 transition font-medium">
          <span id="navLogout">خروج</span>
        </a>
      </div>
    </div>
  </header>

  <!-- Main Content: Single focused card with 3 elements -->
  <main class="max-w-xl mx-auto px-4 py-8 sm:py-12 flex-1 w-full">
    <div class="glass-card rounded-3xl p-6 sm:p-8 space-y-7 shadow-2xl">
      
      <!-- Element 1: Connection Status & Speed Tier -->
      <div class="text-center space-y-2">
        <div class="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span id="txtConnectionStatus">در حال بررسی اتصال...</span>
        </div>
        <div class="text-xs text-slate-400 font-medium">
          <span id="valUserEmail" class="font-bold text-slate-200">-</span> • <span id="valDataUsed">0 B</span> <span id="lblUsedSuffix">مصرف شده</span>
        </div>
      </div>

      <!-- Element 2: One-Tap Subscription Copy & Scannable QR Code -->
      <div class="space-y-4 pt-3 border-t border-white/[0.08]">
        <!-- Format Switcher -->
        <div class="flex p-1 rounded-xl bg-slate-900/90 border border-white/[0.08] text-xs">
          <button id="btnFormatSingbox" onclick="switchFormat('singbox')" class="flex-1 py-2 rounded-lg font-semibold transition bg-indigo-600 text-white shadow">
            Hiddify / Sing-box
          </button>
          <button id="btnFormatVless" onclick="switchFormat('vless')" class="flex-1 py-2 rounded-lg font-semibold transition text-slate-400 hover:text-white">
            v2rayNG / Streisand
          </button>
        </div>

        <!-- Scannable QR Code -->
        <div class="flex justify-center">
          <div class="p-3 bg-white rounded-2xl shadow-md border border-slate-200">
            <img id="imgSubQr" src="" alt="Subscription QR" class="w-48 h-48 sm:w-52 sm:h-52 object-contain">
          </div>
        </div>

        <!-- One-Tap Copy Button -->
        <div class="space-y-2">
          <button id="btnCopySub" onclick="copyActiveSubscription()" class="w-full py-3.5 px-4 rounded-xl bg-indigo-600 hover:bg-indigo-500 active:scale-[0.99] text-white font-semibold text-xs sm:text-sm transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/20">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2"/></svg>
            <span id="txtBtnCopySub">کپی لینک هوشمند اشتراک</span>
          </button>
          <input id="inputSubUrl" readonly type="text" class="w-full px-3 py-2 rounded-lg bg-slate-950/70 border border-white/[0.08] text-[11px] font-mono text-slate-400 select-all text-center focus:outline-none ltr-only">
        </div>
      </div>

      <!-- Element 3: Simple 2-Step Quick Start -->
      <div class="space-y-3 pt-3 border-t border-white/[0.08]">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider text-center" id="txtQuickStartTitle">
          راهنمای سریع اتصال در ۲ گام
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div class="p-3.5 rounded-2xl bg-white/[0.03] border border-white/[0.06] space-y-1.5">
            <div class="font-bold text-white flex items-center gap-1.5">
              <span class="w-5 h-5 rounded-full bg-indigo-600/30 text-indigo-400 flex items-center justify-center text-[10px] font-bold">1</span>
              <span id="txtStep1Title">نصب نرم‌افزار</span>
            </div>
            <p id="txtStep1Desc" class="text-slate-400 text-[11px] leading-relaxed">
              دانلود <a href="https://hiddify.com" target="_blank" class="text-indigo-400 font-semibold underline">Hiddify</a> یا <a href="https://github.com/2dust/v2rayNG/releases" target="_blank" class="text-indigo-400 font-semibold underline">v2rayNG</a> برای اندروید، آیفون یا ویندوز.
            </p>
          </div>
          <div class="p-3.5 rounded-2xl bg-white/[0.03] border border-white/[0.06] space-y-1.5">
            <div class="font-bold text-white flex items-center gap-1.5">
              <span class="w-5 h-5 rounded-full bg-indigo-600/30 text-indigo-400 flex items-center justify-center text-[10px] font-bold">2</span>
              <span id="txtStep2Title">افزودن لینک و اتصال</span>
            </div>
            <p id="txtStep2Desc" class="text-slate-400 text-[11px] leading-relaxed">
              دکمه کپی لینک بالا را بزنید، وارد برنامه شوید، علامت ➕ (Import) را لمس کنید و سپس متصل شوید.
            </p>
          </div>
        </div>
      </div>

    </div>
  </main>

  <!-- Direct Routing Modal -->
  <div id="directRoutingModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="glass-card rounded-3xl p-6 max-w-md w-full space-y-4">
      <div class="flex items-center justify-between">
        <h4 class="font-bold text-sm text-white" id="modalDirectTitle">مسیر مستقیم و تفکیک خودکار ایران</h4>
        <button onclick="closeDirectDomainsModal()" class="text-slate-400 hover:text-white">✕</button>
      </div>
      <p class="text-xs text-slate-300 leading-relaxed" id="modalDirectDesc">
        تمامی وب‌سایت‌های بانکی، اپلیکیشن‌های پرداخت، اسنپ، دیجی‌کالا و سایت‌های داخلی به صورت خودکار بدون فیلترشکن و با اینترنت معمولی و ارزان باز می‌شوند و هیچ حجمی از اشتراک شما کسر نمی‌گردد.
      </p>
      <div class="pt-2">
        <button onclick="closeDirectDomainsModal()" class="w-full py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold">
          متوجه شدم
        </button>
      </div>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast" class="fixed bottom-6 left-1/2 -translate-x-1/2 px-4 py-2 rounded-xl bg-emerald-600 text-white text-xs font-semibold shadow-xl opacity-0 transition-opacity duration-300 pointer-events-none z-50">
    کپی شد!
  </div>

  <footer class="border-t border-white/[0.08] py-4 text-center text-xs text-slate-500">
    <div class="max-w-6xl mx-auto px-4 flex items-center justify-between">
      <span>Family Home VPN</span>
      <span class="text-[11px] font-mono text-emerald-400/80">Cloudflare Tunnel Active</span>
    </div>
  </footer>

  <script>
    let userData = null;
    let currentFormat = 'singbox';
    let currentLang = localStorage.getItem('vpn_lang') || 'fa';

    const i18n = {
      fa: {
        docTitle: 'داشبورد کاربری | Family Home VPN',
        navDash: 'داشبورد',
        navDirect: 'مسیر مستقیم ایران',
        navHelp: 'راهنما',
        navLogout: 'خروج',
        navAdmin: 'پنل مدیریت',
        langLabel: 'English',
        copyBtn: 'کپی لینک هوشمند اشتراک',
        copied: 'لینک اشتراک با موفقیت کپی شد!',
        quickTitle: 'راهنمای سریع اتصال در ۲ گام',
        step1Title: 'نصب نرم‌افزار',
        step1Desc: 'دانلود Hiddify یا v2rayNG برای اندروید، آیفون، مک یا ویندوز.',
        step2Title: 'افزودن لینک و اتصال',
        step2Desc: 'دکمه کپی لینک بالا را بزنید، وارد برنامه شوید، علامت ➕ (Import) را لمس کنید و سپس متصل شوید.',
        usedSuffix: 'مصرف شده',
        activeTier: 'فعال',
        unlimited: 'سرعت نامحدود',
        modalTitle: 'مسیر مستقیم و تفکیک خودکار ایران',
        modalDesc: 'تمامی وب‌سایت‌های بانکی، اپلیکیشن‌های پرداخت، اسنپ، دیجی‌کالا و سایت‌های داخلی به صورت خودکار بدون فیلترشکن باز می‌شوند.',
        modalBtn: 'متوجه شدم'
      },
      en: {
        docTitle: 'Personal Dashboard | Family Home VPN',
        navDash: 'Dashboard',
        navDirect: 'Direct Routing',
        navHelp: 'Help',
        navLogout: 'Logout',
        navAdmin: 'Admin Center',
        langLabel: 'فارسی',
        copyBtn: 'Copy Subscription Link',
        copied: 'Subscription URL copied to clipboard!',
        quickTitle: '2-Step Quick Start Guide',
        step1Title: 'Install App',
        step1Desc: 'Download Hiddify or v2rayNG for Android, iOS, Mac, or Windows.',
        step2Title: 'Paste Link & Connect',
        step2Desc: 'Copy the link above, open the app, tap "+" to import from clipboard, and tap Connect.',
        usedSuffix: 'used',
        activeTier: 'Active',
        unlimited: 'Unlimited',
        modalTitle: 'Iran Direct Traffic Split-Tunneling',
        modalDesc: 'All Iranian banking, payment, and domestic services bypass the proxy automatically without consuming VPN quota.',
        modalBtn: 'Got it'
      }
    };

    function setLanguage(lang) {
      currentLang = lang;
      localStorage.setItem('vpn_lang', lang);
      const isRtl = (lang === 'fa');
      document.documentElement.setAttribute('lang', lang);
      document.documentElement.setAttribute('dir', isRtl ? 'rtl' : 'ltr');
      
      const t = i18n[currentLang];
      document.getElementById('docTitle').textContent = t.docTitle;
      document.getElementById('navDash').textContent = t.navDash;
      document.getElementById('navDirect').textContent = t.navDirect;
      document.getElementById('navHelp').textContent = t.navHelp;
      document.getElementById('navLogout').textContent = t.navLogout;
      document.getElementById('navAdmin').textContent = t.navAdmin;
      document.getElementById('langSwitchLabel').textContent = t.langLabel;
      document.getElementById('txtBtnCopySub').textContent = t.copyBtn;
      document.getElementById('txtQuickStartTitle').textContent = t.quickTitle;
      document.getElementById('txtStep1Title').textContent = t.step1Title;
      document.getElementById('txtStep1Desc').innerHTML = (lang === 'fa')
        ? 'دانلود <a href="https://hiddify.com" target="_blank" class="text-indigo-400 font-semibold underline">Hiddify</a> یا <a href="https://github.com/2dust/v2rayNG/releases" target="_blank" class="text-indigo-400 font-semibold underline">v2rayNG</a> برای اندروید، آیفون یا ویندوز.'
        : 'Download <a href="https://hiddify.com" target="_blank" class="text-indigo-400 font-semibold underline">Hiddify</a> or <a href="https://github.com/2dust/v2rayNG/releases" target="_blank" class="text-indigo-400 font-semibold underline">v2rayNG</a> for Android, iOS, or Windows.';
      document.getElementById('txtStep2Title').textContent = t.step2Title;
      document.getElementById('txtStep2Desc').textContent = t.step2Desc;
      document.getElementById('lblUsedSuffix').textContent = t.usedSuffix;
      document.getElementById('modalDirectTitle').textContent = t.modalTitle;
      document.getElementById('modalDirectDesc').textContent = t.modalDesc;

      if (userData) updateDisplay();
    }

    function toggleLang() {
      setLanguage(currentLang === 'fa' ? 'en' : 'fa');
    }

    function switchFormat(fmt) {
      currentFormat = fmt;
      const btnSingbox = document.getElementById('btnFormatSingbox');
      const btnVless = document.getElementById('btnFormatVless');
      if (fmt === 'singbox') {
        btnSingbox.className = 'flex-1 py-2 rounded-lg font-semibold transition bg-indigo-600 text-white shadow';
        btnVless.className = 'flex-1 py-2 rounded-lg font-semibold transition text-slate-400 hover:text-white';
      } else {
        btnVless.className = 'flex-1 py-2 rounded-lg font-semibold transition bg-indigo-600 text-white shadow';
        btnSingbox.className = 'flex-1 py-2 rounded-lg font-semibold transition text-slate-400 hover:text-white';
      }
      if (userData) updateDisplay();
    }

    function getActiveUrl() {
      if (!userData) return '';
      return (currentFormat === 'singbox') ? (userData.json_sub_link || userData.smart_sub_link) : (userData.vless_sub_link || userData.smart_sub_link);
    }

    function updateDisplay() {
      if (!userData) return;
      const t = i18n[currentLang];
      const activeUrl = getActiveUrl();

      document.getElementById('valUserEmail').textContent = userData.email || userData.name || 'User';
      document.getElementById('valDataUsed').textContent = userData.total_used_str || '0 B';

      const limitMbps = userData.bandwidth_limit_mbps;
      const speedStr = (limitMbps === 0) ? t.unlimited : (limitMbps ? `${limitMbps} Mbps` : '10 Mbps');
      document.getElementById('txtConnectionStatus').textContent = `${t.activeTier} • ${speedStr}`;

      document.getElementById('inputSubUrl').value = activeUrl;
      const qrApiUrl = `/api/public/qr?text=${encodeURIComponent(activeUrl)}`;
      document.getElementById('imgSubQr').src = (currentFormat === 'singbox' && userData.qr_b64) ? userData.qr_b64 : qrApiUrl;

      if (userData.role === 'admin') {
        const adm = document.getElementById('linkAdmin');
        if (adm) adm.classList.remove('hidden');
      }
    }

    function showToast(msg) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.classList.remove('opacity-0');
      toast.classList.add('opacity-100');
      setTimeout(() => {
        toast.classList.remove('opacity-100');
        toast.classList.add('opacity-0');
      }, 2500);
    }

    function copyActiveSubscription() {
      const url = getActiveUrl();
      if (!url) return;
      navigator.clipboard.writeText(url).then(() => {
        showToast(i18n[currentLang].copied);
        const btnText = document.getElementById('txtBtnCopySub');
        const orig = btnText.textContent;
        btnText.textContent = (currentLang === 'fa' ? '✓ کپی شد!' : '✓ Copied!');
        setTimeout(() => { btnText.textContent = orig; }, 2000);
      }).catch(() => {
        const inp = document.getElementById('inputSubUrl');
        inp.select();
        document.execCommand('copy');
        showToast(i18n[currentLang].copied);
      });
    }

    function openDirectDomainsModal() {
      document.getElementById('directRoutingModal').classList.remove('hidden');
    }

    function closeDirectDomainsModal() {
      document.getElementById('directRoutingModal').classList.add('hidden');
    }

    async function loadData() {
      try {
        const res = await fetch('/api/user/me');
        if (res.status === 401) {
          window.location.href = '/login';
          return;
        }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        userData = await res.json();
        updateDisplay();
      } catch (e) {
        console.error('Error fetching user info:', e);
        const st = document.getElementById('txtConnectionStatus');
        if (st && (st.textContent.includes('بررسی') || st.textContent.includes('Checking'))) {
          st.textContent = (currentLang === 'fa') ? 'خطا در بارگذاری اطلاعات' : 'Failed to load details';
        }
      }
    }

    setLanguage(currentLang);
    loadData();
    setInterval(loadData, 20000);
  </script>
</body>
</html>""".replace("__COMMON_HEADER__", COMMON_HEADER_HTML)

ADMIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title id="docTitle">مرکز مدیریت فیلترشکن خانواده | Family VPN Admin</title>
  __COMMON_HEADER__
</head>
<body class="bg-[#0B0F19] text-slate-100 min-h-screen selection:bg-indigo-500 selection:text-white flex flex-col justify-between antialiased">
  
  <!-- Navigation Header -->
  <header class="border-b border-white/[0.08] bg-[#0B0F19]/80 sticky top-0 z-40 backdrop-blur-md">
    <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded-xl bg-indigo-600 flex items-center justify-center text-white shadow-sm font-bold text-xs tracking-wider">
          ADM
        </div>
        <div>
          <span class="font-bold text-sm sm:text-base text-white tracking-tight" id="txtHeaderTitle">مرکز مدیریت فیلترشکن خانواده</span>
        </div>
      </div>

      <!-- Essential Nav Links Only -->
      <div class="flex items-center gap-2 sm:gap-3 text-xs">
        <a href="/admin" class="px-3 py-1.5 rounded-lg text-slate-200 hover:text-white hover:bg-white/[0.05] transition font-medium">
          <span id="navDash">داشبورد</span>
        </a>
        <a href="#direct" onclick="switchAdminTab('domains')" class="px-3 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/[0.05] transition font-medium">
          <span id="navDirect">مسیر مستقیم</span>
        </a>
        <a href="/help" target="_blank" class="px-3 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/[0.05] transition font-medium">
          <span id="navHelp">راهنما</span>
        </a>
        <button onclick="toggleLang()" class="px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/[0.05] transition font-semibold">
          <span id="langSwitchLabel">English</span>
        </button>
        <button onclick="toggleTheme()" class="p-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-white/[0.05] transition" title="Toggle Theme">
          <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
        </button>
        <a href="/dashboard" class="px-2.5 py-1.5 rounded-lg bg-indigo-600/20 text-indigo-300 hover:bg-indigo-600/30 transition font-medium">
          <span id="navUserPortal">پرتال کاربر</span>
        </a>
        <a href="/logout" class="px-2.5 py-1.5 rounded-lg text-rose-400 hover:bg-rose-500/10 transition font-medium">
          <span id="navLogout">خروج</span>
        </a>
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <main class="max-w-6xl mx-auto px-4 py-8 flex-1 w-full space-y-7">
    
    <!-- Top Hero Bar (4 Clean Metrics: Online Users, Live Portal URL, Active Cloudflare Edge IP, Family Invite Code) -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-5">
      
      <!-- 1. Active Users Online -->
      <div class="glass-card p-6 rounded-3xl space-y-2 flex flex-col justify-between">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
          <span id="heroOnlineTitle">کاربران آنلاین</span>
          <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
        </div>
        <div class="flex items-baseline gap-2 mt-1">
          <span id="heroOnlineCount" class="text-3xl font-extrabold text-white">0</span>
          <span class="text-xs text-emerald-400 font-semibold" id="heroOnlineLabel">آنلاین</span>
        </div>
        <p id="heroOnlineSub" class="text-xs text-slate-500 pt-1 border-t border-white/[0.04]">مجموع ۰ کاربر خانواده ثبت‌نام شده</p>
      </div>

      <!-- 2. Live Public URL -->
      <div class="glass-card p-6 rounded-3xl space-y-2 flex flex-col justify-between">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
          <span id="heroUrlTitle">آدرس عمومی پرتال</span>
          <span class="text-[10px] text-emerald-400 font-mono">TLS / HTTP2</span>
        </div>
        <div id="heroPublicUrl" class="font-mono text-xs text-indigo-300 truncate select-all ltr-only mt-1">
          در حال اتصال تونل...
        </div>
        <div class="flex items-center gap-2 pt-2 border-t border-white/[0.04] flex-wrap">
          <button onclick="copyPublicUrl()" class="px-2.5 py-1 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 text-xs font-semibold transition" id="btnHeroCopy">
            کپی لینک
          </button>
          <button onclick="shareViaWhatsApp()" class="px-2.5 py-1 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-semibold transition" id="btnHeroShareWA">
            واتس‌اپ
          </button>
          <button onclick="shareViaTelegram()" class="px-2.5 py-1 rounded-lg bg-sky-600/20 hover:bg-sky-600/30 text-sky-300 border border-sky-500/30 text-xs font-semibold transition" id="btnHeroShareTG">
            تلگرام
          </button>
          <button onclick="openPortalQrModal()" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-white/[0.08] text-xs font-semibold transition">
            QR
          </button>
        </div>
      </div>

      <!-- 3. Active Cloudflare Clean Edge IP & Latency -->
      <div class="glass-card p-6 rounded-3xl space-y-2 flex flex-col justify-between">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
          <span id="heroTunnelIpTitle">آخرین آی‌پی تونل کلودفلر</span>
          <span class="inline-flex items-center gap-1 text-[10px] text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <span id="heroTunnelStatus">تمیز و فعال</span>
          </span>
        </div>
        <div class="flex items-baseline gap-2 mt-1">
          <span id="heroTunnelIp" class="text-xl sm:text-2xl font-mono font-extrabold text-white select-all">در حال دریافت...</span>
        </div>
        <div class="flex items-center justify-between pt-1 border-t border-white/[0.04] text-xs">
          <span id="heroTunnelLatency" class="text-indigo-300 font-mono text-[11px]">تاخیر: -- ms</span>
          <button onclick="copyTunnelIp()" class="text-[11px] text-slate-300 hover:text-white px-2 py-0.5 rounded-lg bg-white/[0.05] border border-white/[0.08]" id="btnCopyTunnelIp">کپی IP</button>
        </div>
      </div>

      <!-- 4. Invite Code with Inline Edit -->
      <div class="glass-card p-6 rounded-3xl space-y-2 flex flex-col justify-between">
        <div class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
          <span id="heroInviteTitle">کد دعوت خانواده</span>
          <button onclick="toggleEditInvite()" class="text-xs text-indigo-400 hover:text-indigo-300 font-semibold" id="btnEditInvite">
            ویرایش
          </button>
        </div>
        <div id="inviteDisplayWrap" class="flex items-center justify-between mt-1">
          <span id="heroInviteCode" class="text-2xl font-mono font-extrabold text-white tracking-widest">TOHID</span>
          <button onclick="copyInviteCode()" class="text-xs text-slate-300 hover:text-white px-2.5 py-1 rounded-lg bg-white/[0.05] border border-white/[0.08]" id="btnCopyInvite">کپی</button>
        </div>
        <div id="inviteEditWrap" class="hidden flex items-center gap-2 mt-1">
          <input type="text" id="inputNewInvite" class="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-indigo-500/50 text-white font-mono text-sm focus:outline-none">
          <button onclick="saveNewInvite()" class="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs">ذخیره</button>
          <button onclick="cancelEditInvite()" class="px-2 py-1.5 text-xs text-slate-400 hover:text-white">انصراف</button>
        </div>
        <p id="heroInviteSub" class="text-xs text-slate-500 pt-1 border-t border-white/[0.04]">الزامی برای ثبت‌نام اعضای خانواده</p>
      </div>

    </div>

    <!-- Clean User Table Card -->
    <div class="glass-card rounded-3xl p-6 space-y-5">
      <div class="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 class="text-base font-bold text-white tracking-tight" id="tblTitle">کاربران و اشتراک‌های خانواده</h2>
          <p class="text-xs text-slate-400" id="tblSub">کنترل سقف سرعت هر کاربر، مشاهده حجم مصرفی و صدور لینک</p>
        </div>
        <button onclick="openModal('addMemberModal')" class="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition shadow-lg shadow-indigo-600/20 flex items-center gap-1.5" id="btnAddMember">
          + تعریف عضو جدید
        </button>
      </div>

      <!-- Table Container -->
      <div class="overflow-x-auto rounded-2xl border border-white/[0.06]">
        <table class="w-full text-xs text-slate-300">
          <thead class="bg-white/[0.02] border-b border-white/[0.06] text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
            <tr>
              <th class="p-3.5 text-start" id="thUser">کاربر / ایمیل</th>
              <th class="p-3.5 text-center" id="thStatus">وضعیت</th>
              <th class="p-3.5 text-start" id="thUsage">حجم مصرفی</th>
              <th class="p-3.5 text-center" id="thSpeed">سقف سرعت</th>
              <th class="p-3.5 text-center" id="thActions">عملیات</th>
            </tr>
          </thead>
          <tbody id="clientsTableBody" class="divide-y divide-white/[0.04]">
            <tr>
              <td colspan="5" class="p-8 text-center text-slate-500">در حال بارگذاری کاربران...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Collapsible Secondary Tools Drawers / Tabs -->
    <div class="space-y-4">
      <!-- Pill Tabs Bar -->
      <div class="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
        <button onclick="switchAdminTab('none')" id="tabBtnNone" class="px-3 py-1.5 rounded-lg text-slate-400 hover:text-white transition font-medium">
          بستن ابزارها
        </button>
        <button onclick="switchAdminTab('cf')" id="tabBtnCf" class="px-3.5 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.08] text-slate-300 hover:text-white transition font-medium flex items-center gap-1.5">
          <span>⚡ بهینه‌ساز IP کلودفلر</span>
        </button>
        <button onclick="switchAdminTab('telegram')" id="tabBtnTg" class="px-3.5 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.08] text-slate-300 hover:text-white transition font-medium flex items-center gap-1.5">
          <span>🔔 هشدارهای تلگرام</span>
        </button>
        <button onclick="switchAdminTab('domains')" id="tabBtnDom" class="px-3.5 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.08] text-slate-300 hover:text-white transition font-medium flex items-center gap-1.5">
          <span>🌐 دامنه‌های مستقیم ایران</span>
        </button>
        <button onclick="switchAdminTab('backup')" id="tabBtnBkp" class="px-3.5 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.08] text-slate-300 hover:text-white transition font-medium flex items-center gap-1.5">
          <span>💾 پشتیبان‌گیری</span>
        </button>
        <button onclick="switchAdminTab('diag')" id="tabBtnDiag" class="px-3.5 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.08] text-slate-300 hover:text-white transition font-medium flex items-center gap-1.5">
          <span>📋 لاگ‌ها و عیب‌یابی</span>
        </button>
      </div>

      <!-- Tab 1: Edge IP Optimizer -->
      <div id="panelCf" class="hidden glass-card rounded-3xl p-6 space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="font-bold text-sm text-white" id="cfOptTitle">بهینه‌ساز خودکار Clean IP کلودفلر</h3>
          <span class="text-xs text-indigo-400 font-mono" id="cfActiveIpDisplay">Active: 104.21.32.189</span>
        </div>
        <p class="text-xs text-slate-300 leading-relaxed" id="cfOptDesc">
          اسکن خودکار ۲۴ سرور Anycast کلودفلر جهت انتخاب سریع‌ترین IP تمیز برای کانفیگ‌های خانواده با کمترین پینگ.
        </p>
        <div class="flex items-center gap-3 pt-2">
          <button onclick="triggerCfScan()" id="btnCfScan" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition">
            اسکن و ارتقای فوری
          </button>
          <span id="cfScanStatus" class="text-xs text-slate-400"></span>
        </div>
      </div>

      <!-- Tab 2: Telegram Alerts -->
      <div id="panelTg" class="hidden glass-card rounded-3xl p-6 space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="font-bold text-sm text-white" id="tgTitle">تنظیمات ربات تلگرام</h3>
          <button onclick="saveTelegramConfig()" class="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold">ذخیره</button>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div>
            <label class="block text-slate-400 mb-1">Bot Token</label>
            <input type="text" id="tgTokenInput" class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-white/[0.08] text-white font-mono text-xs">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Chat ID</label>
            <input type="text" id="tgChatIdInput" class="w-full px-3 py-2 rounded-lg bg-slate-950 border border-white/[0.08] text-white font-mono text-xs">
          </div>
        </div>
        <div class="flex items-center gap-3 pt-1">
          <label class="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input type="checkbox" id="tgEnabledCheckbox" class="rounded bg-slate-900 border-white/[0.1] text-indigo-600">
            <span>فعال‌سازی ارسال اعلان‌های تلگرام</span>
          </label>
          <button onclick="testTelegramAlert()" class="px-3 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] text-slate-300 text-xs font-semibold">تست ارسال پیام</button>
          <span id="tgTestStatus" class="text-xs text-slate-400"></span>
        </div>
      </div>

      <!-- Tab 3: Direct Iran Domains -->
      <div id="panelDom" class="hidden glass-card rounded-3xl p-6 space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="font-bold text-sm text-white" id="domTitle">دامنه‌های مستقیم ایران (Bypass Split-Tunnel)</h3>
          <button onclick="saveDirectDomains()" class="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold">ذخیره و اعمال</button>
        </div>
        <p class="text-xs text-slate-400" id="domDesc">هر دامنه را در یک خط وارد کنید. این دامنه‌ها مستقیماً و بدون مصرف حجم باز می‌شوند.</p>
        <textarea id="directDomainsTextarea" rows="6" class="w-full p-3 rounded-xl bg-slate-950 border border-white/[0.08] text-xs font-mono text-indigo-200 focus:outline-none ltr-only"></textarea>
      </div>

      <!-- Tab 4: Backup & Restore -->
      <div id="panelBkp" class="hidden glass-card rounded-3xl p-6 space-y-4">
        <h3 class="font-bold text-sm text-white" id="bkpTitle">پشتیبان‌گیری و بازیابی اطلاعات</h3>
        <p class="text-xs text-slate-400">دانلود یک نسخه کامل از کاربران، کلیدها و تنظیمات یا بازیابی آن روی سرور دیگر.</p>
        <div class="flex items-center gap-3 pt-2">
          <a href="/api/admin/backup" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition">
            دانلود فایل پشتیبان (.json)
          </a>
        </div>
      </div>

      <!-- Tab 5: Live Diagnostics -->
      <div id="panelDiag" class="hidden glass-card rounded-3xl p-6 space-y-4">
        <div class="flex items-center justify-between">
          <h3 class="font-bold text-sm text-white">لاگ‌های زنده هسته Xray و سیستم</h3>
          <button onclick="fetchDiagnostics()" class="px-3 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] text-slate-300 text-xs font-semibold">بروزرسانی لاگ‌ها</button>
        </div>
        <pre id="diagOutput" class="p-4 rounded-xl bg-slate-950 border border-white/[0.08] text-[11px] font-mono text-slate-300 max-h-80 overflow-y-auto ltr-only">در حال دریافت لاگ‌ها...</pre>
      </div>

    </div>

  </main>

  <!-- Modals Container -->

  <!-- Add Member Modal -->
  <div id="addMemberModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="glass-card rounded-3xl p-6 sm:p-8 max-w-md w-full space-y-4">
      <div class="flex items-center justify-between">
        <h4 id="txtAddModalTitle" class="font-bold text-sm sm:text-base text-white">افزودن عضو جدید خانواده</h4>
        <button onclick="closeModal('addMemberModal')" class="text-slate-400 hover:text-white">✕</button>
      </div>
      <form onsubmit="handleAddMember(event)" class="space-y-4">
        <div>
          <label class="block text-xs font-semibold text-slate-300 mb-1" id="lblAddName">نام یا ایمیل</label>
          <input type="text" id="addName" required placeholder="مثال: Sarah" class="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-white/[0.08] text-xs text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label class="block text-xs font-semibold text-slate-300 mb-1" id="lblAddSpeed">سقف سرعت پیش‌فرض</label>
          <select id="addSpeedLimit" class="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-white/[0.08] text-xs text-indigo-300 focus:outline-none focus:border-indigo-500">
            <option value="10">10 Mbps (پیشنهادی)</option>
            <option value="5">5 Mbps</option>
            <option value="20">20 Mbps</option>
            <option value="25">25 Mbps</option>
            <option value="50">50 Mbps</option>
            <option value="0">Unlimited (نامحدود)</option>
          </select>
        </div>
        <button type="submit" class="w-full py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-lg shadow-indigo-600/30 transition">
          ایجاد حساب و صدور لینک
        </button>
      </form>
    </div>
  </div>

  <!-- QR & Setup Modal -->
  <div id="qrModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="glass-card rounded-3xl p-6 sm:p-8 max-w-md w-full space-y-4 text-center">
      <div class="flex items-center justify-between">
        <h4 id="qrModalTitle" class="font-bold text-sm sm:text-base text-white">اشتراک کاربر</h4>
        <button onclick="closeModal('qrModal')" class="text-slate-400 hover:text-white">✕</button>
      </div>
      <div class="p-3 bg-white rounded-2xl inline-block shadow-md">
        <img id="qrModalImg" src="" alt="QR" class="w-52 h-52 object-contain">
      </div>
      <div class="space-y-2">
        <input type="text" id="qrModalUrl" readonly class="w-full px-3 py-2 rounded-xl bg-slate-950 border border-white/[0.08] text-[11px] font-mono text-indigo-300 select-all text-center ltr-only">
        <button onclick="copyModalUrl()" class="w-full py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition">کپی لینک اشتراک</button>
      </div>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast" class="fixed bottom-6 left-1/2 -translate-x-1/2 px-4 py-2 rounded-xl bg-emerald-600 text-white text-xs font-semibold shadow-xl opacity-0 transition-opacity duration-300 pointer-events-none z-50">
    ذخیره شد!
  </div>

  <footer class="border-t border-white/[0.08] py-4 text-center text-xs text-slate-500">
    <div class="max-w-6xl mx-auto px-4 flex items-center justify-between">
      <span>Family Home VPN • Admin Center</span>
      <span class="text-[11px] font-mono text-emerald-400/80">Self-Healing Watchdog Active</span>
    </div>
  </footer>

  <script>
    let clientsData = [];
    let overviewData = {};
    let currentInviteCode = '';
    let currentLang = localStorage.getItem('vpn_lang') || 'fa';
    let currentModalUrl = '';

    const i18nAdmin = {
      fa: {
        docTitle: 'مرکز مدیریت فیلترشکن خانواده | Family VPN Admin',
        headerTitle: 'مرکز مدیریت فیلترشکن خانواده',
        navDash: 'داشبورد',
        navDirect: 'مسیر مستقیم',
        navHelp: 'راهنما',
        navUserPortal: 'پرتال کاربر',
        navLogout: 'خروج',
        langLabel: 'English',
        heroOnlineTitle: 'کاربران آنلاین',
        heroOnlineLabel: 'آنلاین',
        heroUrlTitle: 'آدرس عمومی پرتال',
        heroInviteTitle: 'کد دعوت خانواده',
        heroTunnelIpTitle: 'آخرین آی‌پی تونل کلودفلر',
        heroTunnelStatus: 'تمیز و فعال',
        btnCopyTunnelIp: 'کپی IP',
        latencyLabel: 'تاخیر:',
        btnEditInvite: 'ویرایش',
        btnCopyInvite: 'کپی',
        btnHeroCopy: 'کپی لینک',
        tblTitle: 'کاربران و اشتراک‌های خانواده',
        tblSub: 'کنترل سقف سرعت هر کاربر، مشاهده حجم مصرفی و صدور لینک',
        btnAddMember: '+ تعریف عضو جدید',
        thUser: 'کاربر / ایمیل',
        thStatus: 'وضعیت',
        thUsage: 'حجم مصرفی',
        thSpeed: 'سقف سرعت',
        thActions: 'عملیات',
        emptyUsers: 'هیچ کاربری یافت نشد. دکمه تعریف عضو جدید را بزنید.',
        unlimited: 'نامحدود (0)',
        speedToast: 'سقف سرعت کاربر به روز رسانی شد',
        copied: 'در کلیپ‌بورد کپی شد!',
        connectedIpLabel: 'آی‌پی متصل:',
        notRecorded: 'ثبت‌نشده'
      },
      en: {
        docTitle: 'Family VPN Admin Center | Home VPN Platform',
        headerTitle: 'Family VPN Admin Center',
        navDash: 'Dashboard',
        navDirect: 'Direct Routing',
        navHelp: 'Help',
        navUserPortal: 'User Portal',
        navLogout: 'Logout',
        langLabel: 'فارسی',
        heroOnlineTitle: 'Active Users Online',
        heroOnlineLabel: 'Online',
        heroUrlTitle: 'Live Public Portal',
        heroInviteTitle: 'Family Invite Code',
        heroTunnelIpTitle: 'Active Cloudflare Clean Edge IP',
        heroTunnelStatus: 'Clean & Active',
        btnCopyTunnelIp: 'Copy IP',
        latencyLabel: 'Latency:',
        btnEditInvite: 'Edit',
        btnCopyInvite: 'Copy',
        btnHeroCopy: 'Copy Link',
        tblTitle: 'Family Users & Subscriptions',
        tblSub: 'Manage user speed limits, track data usage, and export profiles',
        btnAddMember: '+ Add Family Member',
        thUser: 'User / Email',
        thStatus: 'Status',
        thUsage: 'Data Used',
        thSpeed: 'Speed Limit',
        thActions: 'Actions',
        emptyUsers: 'No users found. Click Add Family Member to create one.',
        unlimited: 'Unlimited (0)',
        speedToast: 'User speed limit updated',
        copied: 'Copied to clipboard!',
        connectedIpLabel: 'Connected IP:',
        notRecorded: 'Not recorded'
      }
    };

    function setLanguage(lang) {
      currentLang = lang;
      localStorage.setItem('vpn_lang', lang);
      const isRtl = (lang === 'fa');
      document.documentElement.setAttribute('lang', lang);
      document.documentElement.setAttribute('dir', isRtl ? 'rtl' : 'ltr');

      const t = i18nAdmin[currentLang];
      document.getElementById('docTitle').textContent = t.docTitle;
      document.getElementById('txtHeaderTitle').textContent = t.headerTitle;
      document.getElementById('navDash').textContent = t.navDash;
      document.getElementById('navDirect').textContent = t.navDirect;
      document.getElementById('navHelp').textContent = t.navHelp;
      document.getElementById('navUserPortal').textContent = t.navUserPortal;
      document.getElementById('navLogout').textContent = t.navLogout;
      document.getElementById('langSwitchLabel').textContent = t.langLabel;
      document.getElementById('heroOnlineTitle').textContent = t.heroOnlineTitle;
      document.getElementById('heroOnlineLabel').textContent = t.heroOnlineLabel;
      document.getElementById('heroUrlTitle').textContent = t.heroUrlTitle;
      document.getElementById('heroInviteTitle').textContent = t.heroInviteTitle;
      if (document.getElementById('heroTunnelIpTitle')) document.getElementById('heroTunnelIpTitle').textContent = t.heroTunnelIpTitle;
      if (document.getElementById('heroTunnelStatus')) document.getElementById('heroTunnelStatus').textContent = t.heroTunnelStatus;
      if (document.getElementById('btnCopyTunnelIp')) document.getElementById('btnCopyTunnelIp').textContent = t.btnCopyTunnelIp;
      document.getElementById('btnEditInvite').textContent = t.btnEditInvite;
      document.getElementById('btnCopyInvite').textContent = t.btnCopyInvite;
      document.getElementById('btnHeroCopy').textContent = t.btnHeroCopy;
      document.getElementById('tblTitle').textContent = t.tblTitle;
      document.getElementById('tblSub').textContent = t.tblSub;
      document.getElementById('btnAddMember').textContent = t.btnAddMember;
      document.getElementById('thUser').textContent = t.thUser;
      document.getElementById('thStatus').textContent = t.thStatus;
      document.getElementById('thUsage').textContent = t.thUsage;
      document.getElementById('thSpeed').textContent = t.thSpeed;
      document.getElementById('thActions').textContent = t.thActions;

      if (clientsData && clientsData.length > 0) {
        renderClientsTable(clientsData);
      }
    }

    function toggleLang() {
      setLanguage(currentLang === 'fa' ? 'en' : 'fa');
    }

    function showToast(msg) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.classList.remove('opacity-0');
      toast.classList.add('opacity-100');
      setTimeout(() => {
        toast.classList.remove('opacity-100');
        toast.classList.add('opacity-0');
      }, 2500);
    }

    function switchAdminTab(tab) {
      const panels = ['panelCf', 'panelTg', 'panelDom', 'panelBkp', 'panelDiag'];
      panels.forEach(p => {
        const el = document.getElementById(p);
        if (el) el.classList.add('hidden');
      });

      if (tab === 'cf') document.getElementById('panelCf').classList.remove('hidden');
      if (tab === 'telegram') {
        document.getElementById('panelTg').classList.remove('hidden');
        fetchTelegramConfig();
      }
      if (tab === 'domains') {
        document.getElementById('panelDom').classList.remove('hidden');
        fetchDirectDomains();
      }
      if (tab === 'backup') document.getElementById('panelBkp').classList.remove('hidden');
      if (tab === 'diag') {
        document.getElementById('panelDiag').classList.remove('hidden');
        fetchDiagnostics();
      }
    }

    async function fetchOverview() {
      try {
        const res = await fetch('/api/admin/overview');
        if (res.status === 401) { window.location.href = '/login'; return; }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        overviewData = await res.json();
        
        document.getElementById('heroOnlineCount').textContent = overviewData.online_users || 0;
        document.getElementById('heroOnlineSub').textContent = (currentLang === 'fa') 
          ? `مجموع ${overviewData.total_users || 0} کاربر خانواده ثبت‌نام شده` 
          : `Total ${overviewData.total_users || 0} family members registered`;

        let publicUrl = overviewData.shareable_invite_url || overviewData.portal_url;
        if (!publicUrl || publicUrl.includes('Pending...') || publicUrl.includes('Connecting...')) {
          const invite = overviewData.invite_code || currentInviteCode || '';
          publicUrl = `${window.location.origin}/?invite=${invite}`;
        }
        document.getElementById('heroPublicUrl').textContent = publicUrl;

        currentInviteCode = overviewData.invite_code || 'FAMILY2026';
        document.getElementById('heroInviteCode').textContent = currentInviteCode;

        const activeIp = overviewData.cf_active_edge_ip || overviewData.vpn_host || '172.67.188.112';
        const tipEl = document.getElementById('heroTunnelIp');
        if (tipEl) tipEl.textContent = activeIp;
        const tlatEl = document.getElementById('heroTunnelLatency');
        if (tlatEl) {
          const lat = overviewData.cf_latency_ms ? Math.round(overviewData.cf_latency_ms) : 109;
          tlatEl.textContent = `${i18nAdmin[currentLang].latencyLabel} ${lat} ms`;
        }
        if (overviewData.cf_active_edge_ip) {
          const cfEl = document.getElementById('cfActiveIpDisplay');
          if (cfEl) cfEl.textContent = `Active: ${overviewData.cf_active_edge_ip} (${overviewData.cf_latency_ms || 0}ms)`;
        }
      } catch (e) {
        console.error('Overview error:', e);
        const heroEl = document.getElementById('heroPublicUrl');
        if (heroEl && (heroEl.textContent.includes('اتصال') || heroEl.textContent.includes('Connecting'))) {
          heroEl.textContent = `${window.location.origin}/?invite=${currentInviteCode || ''}`;
        }
      }
    }

    function copyTunnelIp() {
      const el = document.getElementById('heroTunnelIp');
      const val = el ? el.textContent.trim() : '';
      if (val && !val.includes('...') && !val.includes('در حال')) {
        navigator.clipboard.writeText(val);
        showToast(i18nAdmin[currentLang].copied);
      }
    }

    async function fetchClients() {
      try {
        const res = await fetch('/api/clients');
        if (res.status === 401) {
          const tbody = document.getElementById('clientsTableBody');
          if (tbody) {
            tbody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-amber-400">
              <p class="font-semibold mb-2">${currentLang === 'fa' ? 'نشست شما منقضی شده است' : 'Session Expired'}</p>
              <a href="/login" class="inline-block px-4 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold">${currentLang === 'fa' ? 'ورود مجدد' : 'Login Again'}</a>
            </td></tr>`;
          }
          return;
        }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        clientsData = data.clients || [];
        renderClientsTable(clientsData);
      } catch (e) {
        console.error('Clients error:', e);
        const tbody = document.getElementById('clientsTableBody');
        if (tbody) {
          tbody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-rose-400">
            <p>${currentLang === 'fa' ? 'خطا در بارگذاری کاربران' : 'Failed to load users'}</p>
            <button onclick="fetchClients()" class="mt-2 px-3 py-1 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] text-xs text-slate-300">${currentLang === 'fa' ? 'تلاش مجدد' : 'Retry'}</button>
          </td></tr>`;
        }
      }
    }

    function renderClientsTable(list) {
      const tbody = document.getElementById('clientsTableBody');
      if (!tbody) return;
      if (!list || list.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-slate-500">${i18nAdmin[currentLang].emptyUsers}</td></tr>`;
        return;
      }

      tbody.innerHTML = list.map(c => {
        const isOnline = c.is_online;
        const onlineDot = isOnline
          ? `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>${currentLang === 'fa' ? 'آنلاین' : 'Online'}</span>`
          : `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-white/[0.04] text-slate-400 border border-white/[0.06] text-[10px]">${currentLang === 'fa' ? 'آفلاین' : 'Offline'}</span>`;

        const bw = (c.bandwidth_limit_mbps !== undefined && c.bandwidth_limit_mbps !== null) ? c.bandwidth_limit_mbps : 10;
        
        return `
          <tr class="hover:bg-white/[0.02] transition">
            <td class="p-3.5 text-start">
              <div class="font-bold text-white text-xs select-all">${c.email}</div>
              <div class="text-[10px] text-slate-400 font-mono mt-1.5 flex items-center gap-2 flex-wrap">
                <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 text-[10px] font-semibold">
                  <span class="text-slate-400 font-normal">${i18nAdmin[currentLang].connectedIpLabel}</span>
                  <span class="font-mono font-bold select-all text-white">${c.last_ip && c.last_ip !== '---' ? c.last_ip : i18nAdmin[currentLang].notRecorded}</span>
                </span>
                <span class="text-slate-500">•</span>
                <span class="text-slate-400 text-[10px]">${currentLang === 'fa' ? (c.last_seen_fa || 'تاکنون متصل نشده') : (c.last_seen_en || 'Never connected')}</span>
              </div>
            </td>
            <td class="p-3.5 text-center">
              <div>${onlineDot}</div>
            </td>
            <td class="p-3.5 text-start">
              <div class="font-bold text-slate-200 text-xs">${c.total_used_str || '0 B'}</div>
              <div class="text-[10px] text-slate-500 font-mono">↑ ${c.up_str || '0 B'} | ↓ ${c.down_str || '0 B'}</div>
            </td>
            <td class="p-3.5 text-center">
              <select onchange="updateClientBandwidth('${c.email}', this.value)" class="px-2.5 py-1 rounded-lg bg-slate-950 border border-white/[0.1] text-xs font-semibold text-indigo-300 focus:outline-none focus:border-indigo-500 cursor-pointer">
                <option value="5" ${bw === 5 ? 'selected' : ''}>5 Mbps</option>
                <option value="10" ${bw === 10 ? 'selected' : ''}>10 Mbps (Default)</option>
                <option value="20" ${bw === 20 ? 'selected' : ''}>20 Mbps</option>
                <option value="25" ${bw === 25 ? 'selected' : ''}>25 Mbps</option>
                <option value="50" ${bw === 50 ? 'selected' : ''}>50 Mbps</option>
                <option value="0" ${bw === 0 ? 'selected' : ''}>${i18nAdmin[currentLang].unlimited}</option>
              </select>
            </td>
            <td class="p-3.5 text-center">
              <div class="inline-flex items-center gap-1.5 justify-center">
                <button onclick="openClientQr('${c.id}')" class="px-2 py-1 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 text-[11px] font-semibold transition">QR</button>
                <button onclick="copyClientSub('${c.smart_sub_link}')" class="px-2 py-1 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] text-slate-300 border border-white/[0.08] text-[11px] font-semibold transition">Copy</button>
                <button onclick="resetClientTraffic('${c.email}')" class="px-2 py-1 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] text-cyan-300 border border-white/[0.08] text-[11px] font-semibold transition">Reset</button>
                <button onclick="deleteClient('${c.id}', '${c.email}')" class="px-2 py-1 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/80 text-[11px] font-semibold transition">Delete</button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    async function updateClientBandwidth(email, val) {
      try {
        const res = await fetch(`/api/admin/client/${encodeURIComponent(email)}/bandwidth`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({bandwidth_limit_mbps: parseInt(val)})
        });
        if (res.ok) {
          showToast(`${i18nAdmin[currentLang].speedToast}: ${val == 0 ? 'Unlimited' : val + ' Mbps'}`);
          fetchClients();
        }
      } catch (e) {
        console.error(e);
      }
    }

    function toggleEditInvite() {
      document.getElementById('inviteDisplayWrap').classList.add('hidden');
      document.getElementById('inviteEditWrap').classList.remove('hidden');
      document.getElementById('inputNewInvite').value = currentInviteCode;
      document.getElementById('inputNewInvite').focus();
    }

    function cancelEditInvite() {
      document.getElementById('inviteEditWrap').classList.add('hidden');
      document.getElementById('inviteDisplayWrap').classList.remove('hidden');
    }

    async function saveNewInvite() {
      const code = document.getElementById('inputNewInvite').value.trim();
      if (!code) return;
      try {
        const res = await fetch('/api/admin/invite-code', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({code})
        });
        if (res.ok) {
          currentInviteCode = code.toUpperCase();
          document.getElementById('heroInviteCode').textContent = currentInviteCode;
          cancelEditInvite();
          showToast(currentLang === 'fa' ? 'کد دعوت تغییر یافت!' : 'Invite code updated!');
        }
      } catch (e) {
        console.error(e);
      }
    }

    function copyInviteCode() {
      navigator.clipboard.writeText(currentInviteCode).then(() => {
        showToast(i18nAdmin[currentLang].copied);
      });
    }

    function copyPublicUrl() {
      const url = document.getElementById('heroPublicUrl').textContent.trim();
      navigator.clipboard.writeText(url).then(() => {
        showToast(i18nAdmin[currentLang].copied);
      });
    }

    function shareViaWhatsApp() {
      const url = document.getElementById('heroPublicUrl').textContent.trim();
      const text = encodeURIComponent(`Family Home VPN:
${url}
Invite Code: ${currentInviteCode}`);
      window.open(`https://api.whatsapp.com/send?text=${text}`, '_blank');
    }

    function shareViaTelegram() {
      const url = document.getElementById('heroPublicUrl').textContent.trim();
      const text = encodeURIComponent(`Family Home VPN:
${url}
Invite Code: ${currentInviteCode}`);
      window.open(`https://t.me/share/url?url=${encodeURIComponent(url)}&text=${text}`, '_blank');
    }

    function openModal(id) {
      document.getElementById(id).classList.remove('hidden');
    }

    function closeModal(id) {
      document.getElementById(id).classList.add('hidden');
    }

    function openPortalQrModal() {
      const url = document.getElementById('heroPublicUrl').textContent.trim();
      document.getElementById('qrModalTitle').textContent = (currentLang === 'fa' ? 'بارکد پرتال خانوادگی' : 'Family Portal QR');
      document.getElementById('qrModalUrl').value = url;
      currentModalUrl = url;
      document.getElementById('qrModalImg').src = `/api/public/qr?text=${encodeURIComponent(url)}`;
      openModal('qrModal');
    }

    function openClientQr(id) {
      const c = clientsData.find(item => item.id === id);
      if (!c) return;
      const url = c.smart_sub_link || c.json_sub_link;
      document.getElementById('qrModalTitle').textContent = `${c.email} • QR`;
      document.getElementById('qrModalUrl').value = url;
      currentModalUrl = url;
      document.getElementById('qrModalImg').src = c.smart_qr_b64 || `/api/public/qr?text=${encodeURIComponent(url)}`;
      openModal('qrModal');
    }

    function copyModalUrl() {
      if (!currentModalUrl) return;
      navigator.clipboard.writeText(currentModalUrl).then(() => {
        showToast(i18nAdmin[currentLang].copied);
      });
    }

    function copyClientSub(link) {
      navigator.clipboard.writeText(link).then(() => {
        showToast(i18nAdmin[currentLang].copied);
      });
    }

    async function handleAddMember(e) {
      e.preventDefault();
      const name = document.getElementById('addName').value.trim();
      const bw = parseInt(document.getElementById('addSpeedLimit').value) || 10;
      if (!name) return;

      try {
        const res = await fetch('/api/clients', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({name, limit_gb: 0, expiry_days: 0, bandwidth_limit_mbps: bw})
        });
        if (res.ok) {
          closeModal('addMemberModal');
          document.getElementById('addName').value = '';
          showToast(currentLang === 'fa' ? 'عضو جدید اضافه شد!' : 'Family member created!');
          fetchClients();
          fetchOverview();
        } else {
          const err = await res.json();
          alert(err.detail || 'Failed to create member');
        }
      } catch (err) {
        console.error(err);
      }
    }

    async function deleteClient(id, email) {
      if (!confirm(`Delete user ${email}?`)) return;
      try {
        const res = await fetch(`/api/clients/${encodeURIComponent(id)}`, {method: 'DELETE'});
        if (res.ok) {
          showToast('User deleted');
          fetchClients();
          fetchOverview();
        }
      } catch (e) {
        console.error(e);
      }
    }

    async function resetClientTraffic(email) {
      try {
        const res = await fetch(`/api/clients/${encodeURIComponent(email)}/reset`, {method: 'POST'});
        if (res.ok) {
          showToast('Traffic reset');
          fetchClients();
        }
      } catch (e) {
        console.error(e);
      }
    }

    async function triggerCfScan() {
      const btn = document.getElementById('btnCfScan');
      const st = document.getElementById('cfScanStatus');
      btn.disabled = true;
      st.textContent = 'Scanning 24 edge IPs...';
      try {
        const res = await fetch('/api/admin/cf-optimizer/scan', {method: 'POST'});
        const d = await res.json();
        st.textContent = `Done! Selected ${d.selected_ip} (${d.latency_ms}ms)`;
        fetchOverview();
      } catch (e) {
        st.textContent = 'Scan failed';
      } finally {
        btn.disabled = false;
      }
    }

    async function fetchTelegramConfig() {
      try {
        const res = await fetch('/api/telegram');
        const d = await res.json();
        document.getElementById('tgTokenInput').value = d.bot_token || '';
        document.getElementById('tgChatIdInput').value = d.chat_id || '';
        document.getElementById('tgEnabledCheckbox').checked = !!d.enabled;
      } catch (e) {}
    }

    async function saveTelegramConfig() {
      const bot_token = document.getElementById('tgTokenInput').value.trim();
      const chat_id = document.getElementById('tgChatIdInput').value.trim();
      const enabled = document.getElementById('tgEnabledCheckbox').checked;
      try {
        const res = await fetch('/api/telegram', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({bot_token, chat_id, enabled})
        });
        if (res.ok) showToast('Telegram config saved!');
      } catch (e) {}
    }

    async function testTelegramAlert() {
      const st = document.getElementById('tgTestStatus');
      st.textContent = 'Sending test alert...';
      try {
        const res = await fetch('/api/telegram/test', {method: 'POST'});
        const d = await res.json();
        st.textContent = d.success ? 'Alert delivered to Telegram!' : 'Failed: ' + d.error;
      } catch (e) {
        st.textContent = 'Error testing Telegram';
      }
    }

    async function fetchDirectDomains() {
      try {
        const res = await fetch('/api/direct-domains');
        const d = await res.json();
        document.getElementById('directDomainsTextarea').value = (d.domains || []).join('\n');
      } catch (e) {}
    }

    async function saveDirectDomains() {
      const raw = document.getElementById('directDomainsTextarea').value;
      const domains = raw.split('\n').map(x => x.trim()).filter(Boolean);
      try {
        const res = await fetch('/api/direct-domains', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({domains})
        });
        if (res.ok) showToast('Direct domains updated!');
      } catch (e) {}
    }

    async function fetchDiagnostics() {
      const out = document.getElementById('diagOutput');
      out.textContent = 'Loading live Xray logs...';
      try {
        const res = await fetch('/api/diagnostics/logs?limit=50');
        const d = await res.json();
        out.textContent = (d.logs || []).map(l => `[${l.time}] [${l.level}] ${l.message}`).join('\n') || 'No logs recorded.';
      } catch (e) {
        out.textContent = 'Failed to load logs.';
      }
    }

    setLanguage(currentLang);
    fetchOverview();
    fetchClients();
    setInterval(fetchOverview, 15000);
    setInterval(fetchClients, 20000);
  </script>
</body>
</html>""".replace("__COMMON_HEADER__", COMMON_HEADER_HTML)

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
    session = get_session(request)
    if session:
        if session.get("role") == "admin":
            return RedirectResponse("/admin", status_code=303)
        return RedirectResponse("/dashboard", status_code=303)
    return HTMLResponse(LANDING_PAGE_HTML)

@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request):
    session = get_session(request)
    if session:
        if session.get("role") == "admin":
            return RedirectResponse("/admin", status_code=303)
        return RedirectResponse("/dashboard", status_code=303)
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
