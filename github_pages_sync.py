"""
Automated GitHub Pages Redirector & Permanent Subscription Publisher
Publishes static redirect files and permanent user subscription files (.json, raw base64, and user landing pages)
to the gh-pages branch of https://github.com/tohid-sargol/family-home-vpn.git.

Guarantees 100% automated synchronization:
Whenever tunnels rotate or clean IPs change, all user subscriptions are regenerated and pushed to gh-pages,
allowing VPN apps (Hiddify, v2rayNG, Sing-Box) to auto-update permanently via their GitHub Pages link.
"""

import os
import sys
import json
import time
import base64
import sqlite3
import tempfile
import subprocess
import urllib.request
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import quote

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "gh_pages_sync_state.json")
PORTAL_DB = os.path.join(BASE_DIR, "portal.db")
DEFAULT_REPO_DIR = r"C:\Users\Dell\home-vpn-shareable"
GH_PAGES_BASE = "https://tohid-sargol.github.io/family-home-vpn"

REDIRECT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8">
  <title>Family VPN | سامانه هوشمند فیلترشکن خانواده</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <meta http-equiv="refresh" content="2;url=__ACTIVE_PORTAL_URL__">
  <script>
    (function() {
      var ACTIVE_URL = "__ACTIVE_PORTAL_URL__".replace(/\\/+$/, "");
      try {
        var params = new URLSearchParams(window.location.search);
        if (params.has("sub")) {
          var token = params.get("sub");
          var isJson = params.get("json") === "1" || params.has("json");
          // If sub token is provided, redirect to static user page
          window.location.replace("user/" + encodeURIComponent(token) + "/");
          return;
        }
        var path = window.location.pathname.replace(/^\\/family-home-vpn\\/?/, "/");
        if (!path.startsWith("/")) path = "/" + path;
        if (path === "/" || path === "") {
          window.location.replace(ACTIVE_URL + window.location.search + window.location.hash);
        } else {
          window.location.replace(ACTIVE_URL + path + window.location.search + window.location.hash);
        }
      } catch (err) {
        window.location.href = ACTIVE_URL;
      }
    })();
  </script>
  <style>
    body {
      background: radial-gradient(circle at 50% 20%, #1e1b4b 0%, #0f172a 60%, #020617 100%);
      color: #f8fafc;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      min-height: 100vh;
      margin: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      direction: rtl;
    }
    .card {
      background: rgba(15, 23, 42, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(16px);
      border-radius: 20px;
      padding: 2.5rem 2rem;
      max-width: 440px;
      width: 90%;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    }
    .spinner {
      width: 48px;
      height: 48px;
      border: 4px solid rgba(99, 102, 241, 0.2);
      border-top-color: #6366f1;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 1.5rem auto;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    h1 { font-size: 1.25rem; font-weight: 700; margin-bottom: 0.5rem; color: #ffffff; }
    p { font-size: 0.9rem; color: #94a3b8; line-height: 1.6; margin-bottom: 1.5rem; }
    .btn {
      display: inline-block;
      background: #4f46e5;
      color: #ffffff;
      padding: 0.75rem 1.5rem;
      border-radius: 12px;
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 600;
      transition: background 0.2s;
    }
    .btn:hover { background: #4338ca; }
    .en-sub { font-size: 0.75rem; color: #64748b; margin-top: 1rem; direction: ltr; }
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <h1>در حال انتقال امن به سامانه...</h1>
    <p>اتصال مستقیم به پورتال ابری و سرور فیلترشکن خانواده برقرار شد. تا لحظاتی دیگر منتقل می‌شوید.</p>
    <a id="btnFallback" class="btn" href="__ACTIVE_PORTAL_URL__">ورود مستقیم به سامانه (Enter)</a>
    <div class="en-sub">Securely redirecting to Family Home VPN Portal...</div>
  </div>
</body>
</html>
"""

USER_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="utf-8">
  <title>اشتراک اختصاصی فیلترشکن خانواده | __USER_NAME__</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --bg: #090d16;
      --card-bg: rgba(17, 24, 39, 0.85);
      --border: rgba(255, 255, 255, 0.1);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
    }
    * { box-sizing: border-box; }
    body {
      background: radial-gradient(circle at 50% 10%, #1e1b4b 0%, #090d16 100%);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      min-height: 100vh;
      margin: 0;
      padding: 2rem 1rem;
      display: flex;
      align-items: center;
      justify-content: center;
      direction: rtl;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      backdrop-filter: blur(20px);
      border-radius: 24px;
      padding: 2.25rem;
      max-width: 520px;
      width: 100%;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
    }
    .avatar {
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: linear-gradient(135deg, #6366f1, #a855f7);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 28px;
      margin: 0 auto 1.25rem auto;
      box-shadow: 0 0 25px rgba(99, 102, 241, 0.5);
    }
    h1 { font-size: 1.4rem; font-weight: 800; margin: 0 0 0.5rem 0; color: #fff; }
    .badge {
      display: inline-block;
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      margin-bottom: 1.5rem;
    }
    .btn-group { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1.5rem; }
    .btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      padding: 0.875rem 1.25rem;
      border-radius: 14px;
      font-size: 0.95rem;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.2s;
      border: none;
    }
    .btn-hiddify {
      background: linear-gradient(135deg, #6366f1, #4f46e5);
      color: #ffffff;
      box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
    }
    .btn-hiddify:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(99, 102, 241, 0.6); }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.06);
      color: #e2e8f0;
      border: 1px solid var(--border);
    }
    .btn-secondary:hover { background: rgba(255, 255, 255, 0.12); }
    .link-box {
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.75rem 1rem;
      font-family: monospace;
      font-size: 0.8rem;
      color: #cbd5e1;
      word-break: break-all;
      direction: ltr;
      text-align: left;
      margin-bottom: 1.5rem;
      user-select: all;
    }
    .features {
      text-align: right;
      font-size: 0.825rem;
      color: var(--text-muted);
      line-height: 1.8;
      border-top: 1px solid var(--border);
      padding-top: 1.25rem;
    }
    .features li { list-style: none; margin-bottom: 0.4rem; display: flex; align-items: center; gap: 0.5rem; }
    .toast {
      visibility: hidden;
      min-width: 200px;
      background-color: #10b981;
      color: #fff;
      text-align: center;
      border-radius: 8px;
      padding: 10px;
      position: fixed;
      z-index: 100;
      bottom: 30px;
      left: 50%;
      transform: translateX(-50%);
      font-size: 0.875rem;
    }
    .toast.show { visibility: visible; animation: fadeInOut 2.5s; }
    @keyframes fadeInOut {
      0% { opacity: 0; bottom: 20px; }
      15% { opacity: 1; bottom: 30px; }
      85% { opacity: 1; bottom: 30px; }
      100% { opacity: 0; bottom: 20px; }
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="avatar">⚡</div>
    <h1>اشتراک اختصاصی __USER_NAME__</h1>
    <div class="badge">🟢 متصل به سرور خانگی ایرلند (Always-Active)</div>

    <div class="btn-group">
      <a class="btn btn-hiddify" href="__HIDDIFY_DEEP_LINK__">
        🚀 افزودن مستقیم به هیدیفای (یک کلیک)
      </a>
      <button class="btn btn-secondary" onclick="copyText('__PERM_SUB_JSON__', 'لینک سابسکریپشن کپی شد!')">
        📋 کپی لینک سابسکریپشن دائمی (JSON)
      </button>
      <button class="btn btn-secondary" onclick="copyText('__PERM_SUB_RAW__', 'لینک سابسکریپشن VLESS کپی شد!')">
        📋 کپی لینک سابسکریپشن VLESS (برای v2rayNG)
      </button>
    </div>

    <div class="link-box" id="subUrl">__PERM_SUB_JSON__</div>

    <div class="features">
      <li>✨ <b>لینک دائمی و بدون قطعی:</b> با تغییر خودکار آدرس سرورها، اتصال شما قطع نمی‌شود.</li>
      <li>🛡️ <b>سایت‌های ایرانی (Split-Tunneling):</b> بانک‌ها، اسنپ، دیجی‌کالا و اپ‌های داخلی مستقیم و بدون مصرف حجم باز می‌شوند.</li>
      <li>⚡ <b>ضد فیلترینگ (Anti-DPI):</b> مجهز به ۵ مسیر پاک Anycast کلودفلر و تکه‌تکه‌سازی پکت‌ها (Fragmentation).</li>
    </div>
  </div>

  <div id="toast" class="toast">کپی شد!</div>

  <script>
    function copyText(text, msg) {
      navigator.clipboard.writeText(text).then(function() {
        var x = document.getElementById("toast");
        x.innerText = msg || "کپی شد!";
        x.className = "toast show";
        setTimeout(function(){ x.className = x.className.replace("show", ""); }, 2500);
      });
    }
  </script>
</body>
</html>
"""

def get_last_synced_url() -> str:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("last_synced_url", "")
        except Exception:
            pass
    return ""

def set_last_synced_url(url: str, commit_id: str = ""):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "last_synced_url": url,
                "commit_id": commit_id,
                "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }, f, indent=2)
    except Exception:
        pass

def detect_active_portal_url() -> str:
    try:
        req = urllib.request.Request("http://127.0.0.1:8080/api/status", headers={"User-Agent": "gh-pages-sync"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                url = data.get("portal_url") or data.get("sub_url")
                if url and "trycloudflare.com" in url:
                    return url.strip().rstrip("/")
    except Exception:
        pass
    return ""

def detect_active_vpn_host() -> str:
    try:
        req = urllib.request.Request("http://127.0.0.1:8080/api/status", headers={"User-Agent": "gh-pages-sync"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                host = data.get("vpn_host")
                if host and "trycloudflare.com" in host:
                    return host.strip()
    except Exception:
        pass
    return ""

def find_repo_dir(custom_path: Optional[str] = None) -> Optional[str]:
    candidates = []
    if custom_path and os.path.exists(custom_path):
        candidates.append(custom_path)
    if os.path.exists(DEFAULT_REPO_DIR) and os.path.exists(os.path.join(DEFAULT_REPO_DIR, ".git")):
        candidates.append(DEFAULT_REPO_DIR)
    parent_git = os.path.join(BASE_DIR, ".git")
    if os.path.exists(parent_git):
        candidates.append(BASE_DIR)

    for c in candidates:
        try:
            remotes = subprocess.check_output(["git", "-C", c, "remote", "-v"], text=True, stderr=subprocess.DEVNULL)
            if "family-home-vpn" in remotes:
                return c
        except Exception:
            pass
    return candidates[0] if candidates else None

def get_active_users() -> List[Dict[str, Any]]:
    if not os.path.exists(PORTAL_DB):
        return []
    try:
        conn = sqlite3.connect(PORTAL_DB)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, sub_id, uuid FROM users WHERE sub_id IS NOT NULL AND uuid IS NOT NULL")
        users = [dict(r) for r in cur.fetchall()]
        conn.close()
        return users
    except Exception as e:
        print(f"[GH-Pages Sync DB Error] {e}")
        return []

def sync_github_pages(active_portal_url: Optional[str] = None, active_vpn_host: Optional[str] = None, repo_dir: Optional[str] = None, force: bool = False) -> Dict[str, Any]:
    """
    Publishes index.html, 404.html, .nojekyll, AND all user permanent subscription files to the gh-pages branch.
    Guarantees permanent connectivity for Hiddify / v2rayNG / Sing-Box.
    """
    p_url = (active_portal_url or "").strip().rstrip("/")
    if not p_url:
        p_url = detect_active_portal_url()

    v_host = (active_vpn_host or "").strip()
    if not v_host:
        v_host = detect_active_vpn_host()

    if not p_url or "trycloudflare.com" not in p_url:
        return {"success": False, "error": f"Invalid or missing portal URL: '{p_url}'"}

    target_repo = find_repo_dir(repo_dir)
    if not target_repo:
        return {"success": False, "error": "Could not locate family-home-vpn git repository"}

    # Import profile generators from portal
    try:
        import portal
        build_singbox = portal.build_resilient_singbox_profile
        build_vless = portal.build_resilient_vless_links
    except Exception as e:
        return {"success": False, "error": f"Failed to import profile builders from portal: {e}"}

    users = get_active_users()

    temp_dir = tempfile.mkdtemp(prefix="gh_pages_")
    index_file = os.path.join(temp_dir, "git_index")
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = index_file

    files_to_index: List[Tuple[str, str]] = [] # (temp_file_path, git_relative_path)

    try:
        # 1. Root index.html
        html_content = REDIRECT_HTML_TEMPLATE.replace("__ACTIVE_PORTAL_URL__", p_url)
        p_index = os.path.join(temp_dir, "index.html")
        with open(p_index, "w", encoding="utf-8") as f:
            f.write(html_content)
        files_to_index.append((p_index, "index.html"))

        # 2. 404.html
        p_404 = os.path.join(temp_dir, "404.html")
        with open(p_404, "w", encoding="utf-8") as f:
            f.write(html_content)
        files_to_index.append((p_404, "404.html"))

        # 3. .nojekyll
        p_nojekyll = os.path.join(temp_dir, ".nojekyll")
        with open(p_nojekyll, "w", encoding="utf-8") as f:
            f.write("")
        files_to_index.append((p_nojekyll, ".nojekyll"))

        # 4. Generate user subscription files
        sub_dir = os.path.join(temp_dir, "sub")
        os.makedirs(sub_dir, exist_ok=True)
        sub_json_dir = os.path.join(sub_dir, "json")
        os.makedirs(sub_json_dir, exist_ok=True)

        for u in users:
            sub_id = u.get("sub_id")
            uuid = u.get("uuid")
            name = u.get("name") or u.get("email") or "User"
            if not sub_id or not uuid:
                continue

            # A. Sing-Box JSON Config
            sb_profile = build_singbox(uuid, name, v_host, p_url.replace("https://", ""))
            sb_json_str = json.dumps(sb_profile, indent=2, ensure_ascii=False)

            p_sb = os.path.join(sub_dir, f"{sub_id}.json")
            with open(p_sb, "w", encoding="utf-8") as f:
                f.write(sb_json_str)
            files_to_index.append((p_sb, f"sub/{sub_id}.json"))

            # Also write under sub/json/{sub_id}.json
            p_sb_alias = os.path.join(sub_json_dir, f"{sub_id}.json")
            with open(p_sb_alias, "w", encoding="utf-8") as f:
                f.write(sb_json_str)
            files_to_index.append((p_sb_alias, f"sub/json/{sub_id}.json"))

            # B. Base64 VLESS text (as .txt and as raw file under vless/{sub_id})
            vless_uris = build_vless(uuid, name, v_host)
            joined_vless = "\n".join(vless_uris)
            b64_vless = base64.b64encode(joined_vless.encode("utf-8")).decode("utf-8")

            p_vless_txt = os.path.join(sub_dir, f"{sub_id}.txt")
            with open(p_vless_txt, "w", encoding="utf-8") as f:
                f.write(b64_vless)
            files_to_index.append((p_vless_txt, f"sub/{sub_id}.txt"))

            # C. Dedicated User Landing Page under user/{sub_id}/index.html
            u_dir = os.path.join(temp_dir, "user", sub_id)
            os.makedirs(u_dir, exist_ok=True)
            perm_json_url = f"{GH_PAGES_BASE}/sub/{sub_id}.json"
            perm_raw_url = f"{GH_PAGES_BASE}/sub/{sub_id}.txt"
            hiddify_deep = f"hiddify://install-sub?url={quote(perm_json_url)}&name={quote('FamilyVPN-' + name)}"

            u_page_html = (
                USER_PAGE_TEMPLATE
                .replace("__USER_NAME__", name)
                .replace("__PERM_SUB_JSON__", perm_json_url)
                .replace("__PERM_SUB_RAW__", perm_raw_url)
                .replace("__HIDDIFY_DEEP_LINK__", hiddify_deep)
                .replace("__ACTIVE_PORTAL_URL__", p_url)
            )
            p_u_page = os.path.join(u_dir, "index.html")
            with open(p_u_page, "w", encoding="utf-8") as f:
                f.write(u_page_html)
            files_to_index.append((p_u_page, f"user/{sub_id}/index.html"))

        # 5. Hash all files and populate git index
        for local_path, git_rel_path in files_to_index:
            blob_hash = subprocess.check_output(["git", "-C", target_repo, "hash-object", "-w", local_path], text=True).strip()
            subprocess.check_call(
                ["git", "-C", target_repo, "update-index", "--add", "--cacheinfo", "100644", blob_hash, git_rel_path],
                env=env, stderr=subprocess.DEVNULL
            )

        # 6. Write git tree and commit
        tree_id = subprocess.check_output(["git", "-C", target_repo, "write-tree"], env=env, text=True).strip()
        commit_msg = f"Deploy zero-leak permanent portal & subscriptions ({len(users)} users) -> {time.strftime('%Y-%m-%d %H:%M')}"
        commit_id = subprocess.check_output(["git", "-C", target_repo, "commit-tree", tree_id, "-m", commit_msg], text=True).strip()

        # 7. Push directly to origin refs/heads/gh-pages
        push_out = subprocess.check_output(
            ["git", "-C", target_repo, "push", "origin", f"{commit_id}:refs/heads/gh-pages", "--force"],
            text=True, stderr=subprocess.STDOUT
        )

        set_last_synced_url(p_url, commit_id)
        print(f"[GH-Pages Sync] Successfully updated gh-pages with {len(users)} users -> {p_url} (commit {commit_id[:8]})")
        return {
            "success": True,
            "skipped": False,
            "url": p_url,
            "vpn_host": v_host,
            "users_count": len(users),
            "commit_id": commit_id,
            "gh_pages_url": GH_PAGES_BASE,
            "push_output": push_out
        }
    except Exception as e:
        print(f"[GH-Pages Sync Error] {e}")
        return {"success": False, "error": str(e)}
    finally:
        # Clean up temporary directory
        try:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

if __name__ == "__main__":
    force_run = "--force" in sys.argv
    result = sync_github_pages(force=force_run)
    print(json.dumps(result, indent=2, ensure_ascii=False))
