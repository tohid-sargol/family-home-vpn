"""
Zero-Leak GitHub Pages Redirector Sync Helper
Publishes ONLY static redirect files (index.html, 404.html, .nojekyll) to gh-pages branch.
PRIVACY GUARANTEE: Never commits or leaks user tokens, credentials, databases, or private configs.
"""

import os
import sys
import json
import time
import tempfile
import subprocess
import urllib.request
from typing import Optional, Dict, Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "gh_pages_sync_state.json")
DEFAULT_REPO_DIR = r"C:\Users\Dell\home-vpn-shareable"

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
          var targetPath = isJson ? ("/sub/json/" + encodeURIComponent(token)) : ("/sub/" + encodeURIComponent(token));
          window.location.replace(ACTIVE_URL + targetPath);
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
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    h1 {
      font-size: 1.25rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      color: #ffffff;
    }
    p {
      font-size: 0.9rem;
      color: #94a3b8;
      line-height: 1.6;
      margin-bottom: 1.5rem;
    }
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
    .btn:hover {
      background: #4338ca;
    }
    .en-sub {
      font-size: 0.75rem;
      color: #64748b;
      margin-top: 1rem;
      direction: ltr;
    }
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
  <script>
    try {
      var p = new URLSearchParams(window.location.search);
      if (p.has("sub")) {
        var t = p.get("sub");
        var isJ = p.get("json") === "1" || p.has("json");
        var href = "__ACTIVE_PORTAL_URL__" + (isJ ? ("/sub/json/" + encodeURIComponent(t)) : ("/sub/" + encodeURIComponent(t)));
        document.getElementById("btnFallback").href = href;
      }
    } catch(e) {}
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
    """Attempts to read active portal URL from local API status or log file."""
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

    log_path = os.path.join(BASE_DIR, "logs", "cf-sub.log")
    if os.path.exists(log_path):
        import re
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                for line in reversed(lines[-200:]):
                    m = re.search(r"https://([a-zA-Z0-9-]+\.trycloudflare\.com)", line)
                    if m:
                        return f"https://{m.group(1)}"
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

def sync_github_pages(active_portal_url: Optional[str] = None, repo_dir: Optional[str] = None, force: bool = False) -> Dict[str, Any]:
    """
    Publishes index.html, 404.html, and .nojekyll to the gh-pages branch.
    Guaranteed zero-leak: only static redirect HTML is packaged into a standalone git tree.
    """
    url = (active_portal_url or "").strip().rstrip("/")
    if not url:
        url = detect_active_portal_url()

    if not url or "trycloudflare.com" not in url:
        return {"success": False, "error": f"Invalid or missing portal URL: '{url}'"}

    last_url = get_last_synced_url()
    if not force and last_url == url:
        return {"success": True, "skipped": True, "url": url, "message": "Portal URL unchanged, skipped gh-pages commit"}

    target_repo = find_repo_dir(repo_dir)
    if not target_repo:
        return {"success": False, "error": "Could not locate family-home-vpn git repository"}

    html_content = REDIRECT_HTML_TEMPLATE.replace("__ACTIVE_PORTAL_URL__", url)

    temp_dir = tempfile.mkdtemp(prefix="gh_pages_")
    index_file = os.path.join(temp_dir, "git_index")
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = index_file

    try:
        # 1. Write index.html
        p_index = os.path.join(temp_dir, "index.html")
        with open(p_index, "w", encoding="utf-8") as f:
            f.write(html_content)

        # 2. Write 404.html (for GitHub Pages subpath routing fallback)
        p_404 = os.path.join(temp_dir, "404.html")
        with open(p_404, "w", encoding="utf-8") as f:
            f.write(html_content)

        # 3. Write .nojekyll
        p_nojekyll = os.path.join(temp_dir, ".nojekyll")
        with open(p_nojekyll, "w", encoding="utf-8") as f:
            f.write("")

        # 4. Hash objects into git repository database
        blob_index = subprocess.check_output(["git", "-C", target_repo, "hash-object", "-w", p_index], text=True).strip()
        blob_404 = subprocess.check_output(["git", "-C", target_repo, "hash-object", "-w", p_404], text=True).strip()
        blob_nojekyll = subprocess.check_output(["git", "-C", target_repo, "hash-object", "-w", p_nojekyll], text=True).strip()

        # 5. Populate temporary git index
        subprocess.check_call(["git", "-C", target_repo, "update-index", "--add", "--cacheinfo", "100644", blob_index, "index.html"], env=env, stderr=subprocess.DEVNULL)
        subprocess.check_call(["git", "-C", target_repo, "update-index", "--add", "--cacheinfo", "100644", blob_404, "404.html"], env=env, stderr=subprocess.DEVNULL)
        subprocess.check_call(["git", "-C", target_repo, "update-index", "--add", "--cacheinfo", "100644", blob_nojekyll, ".nojekyll"], env=env, stderr=subprocess.DEVNULL)

        # 6. Write tree and commit
        tree_id = subprocess.check_output(["git", "-C", target_repo, "write-tree"], env=env, text=True).strip()
        commit_msg = f"Deploy zero-leak permanent portal redirect to gh-pages ({time.strftime('%Y-%m-%d %H:%M')})"
        commit_id = subprocess.check_output(["git", "-C", target_repo, "commit-tree", tree_id, "-m", commit_msg], text=True).strip()

        # 7. Push directly to origin refs/heads/gh-pages
        push_out = subprocess.check_output(
            ["git", "-C", target_repo, "push", "origin", f"{commit_id}:refs/heads/gh-pages", "--force"],
            text=True, stderr=subprocess.STDOUT
        )

        set_last_synced_url(url, commit_id)
        print(f"[GH-Pages Sync] Successfully updated gh-pages redirector -> {url} (commit {commit_id[:8]})")
        return {
            "success": True,
            "skipped": False,
            "url": url,
            "commit_id": commit_id,
            "gh_pages_url": "https://tohid-sargol.github.io/family-home-vpn/",
            "push_output": push_out
        }
    except Exception as e:
        print(f"[GH-Pages Sync Error] {e}")
        return {"success": False, "error": str(e)}
    finally:
        # Clean up temporary index and files
        try:
            for fname in ["index.html", "404.html", ".nojekyll", "git_index"]:
                fp = os.path.join(temp_dir, fname)
                if os.path.exists(fp):
                    os.remove(fp)
            os.rmdir(temp_dir)
        except Exception:
            pass

if __name__ == "__main__":
    force_run = "--force" in sys.argv
    result = sync_github_pages(force=force_run)
    print(json.dumps(result, indent=2, ensure_ascii=False))
