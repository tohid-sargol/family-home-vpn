# 🛡️ Home Family VPN Platform | سامانه فیلترشکن اختصاصی خانواده
> **Version 3.0** — Self-Healing, Zero-Touch, Fully Automated Bilingual VPN & Self-Service Portal.  
> **نسخه ۳.۰** — سامانه خودکار، بدون نیاز به تنظیم مودم یا خرید دامنه، مجهز به پنل دوزبانه و سیستم تفکیک ترافیک ایران.

---

## 🌟 Highlights | ویژگی‌های برجسته
- 🔒 **Zero Router Port Forwarding / بدون پورت فورواردینگ**: No need to configure routers or open ports. Uses outbound Cloudflare Zero-Trust Quick Tunnels.
- 💰 **Zero Cost / کاملاً رایگان**: No domain purchase, no static IP, no VPS subscription required. Runs entirely on your home laptop.
- ⚡ **Anti-DPI Resiliency / ضد اختلال**: TLS packet fragmentation (`10-30B`, `10-20ms`), uTLS Firefox fingerprint, and encrypted DoH (`1.1.1.1`).
- 🇮🇷 **Automatic Iran Split-Tunneling / تفکیک خودکار ترافیک ایران**: All `.ir` domains, Iranian banks, and apps (Snapp, Digikala) bypass the VPN automatically with zero manual setup.
- 🔄 **60-Second Auto-Healing Watchdog / سیستم خودترمیمی**: Automatically monitors tunnels, re-establishes broken links within 10 seconds, and syncs client subscriptions.
- 👥 **Bilingual Self-Service Hub / پورتال خودخدمتی دوزبانه**: Family members register using an invite code (e.g. `FAMILY2026`) and get instant 1-tap subscription links & QR codes.
- 📱 **Universal Client Compatibility / سازگار با تمام دستگاه‌ها**: Works seamlessly on Android (Hiddify / v2rayNG), iOS (Streisand / V2Box), Windows, and macOS.
- 💾 **Settings Backup & Restore / پشتیبان‌گیری و بازیابی**: One-click JSON export/restore for users, direct domains, and credentials.
- 📚 **Built-in Knowledge Base / مرکز آموزش یکپارچه**: Comprehensive `/help` page in Persian and English.

---

## 🏗️ Architecture | معماری سیستم

```
[ User in Iran (Phone/PC) ]
           │
           ▼ (TLS 443 Encrypted - Anti-DPI Fragmentation)
[ Cloudflare Global Anycast Edge Network ]
           │
           ▼ (Outbound Encrypted Quick Tunnel)
[ Your Server Laptop (Home / Ireland) ]
           │
           ├── Port 8080:  Bilingual Self-Service Portal & API
           ├── Port 2053:  3x-ui Xray Engine
           └── Port 10000: VLESS + WebSocket / HTTPUpgrade Inbound
           │
           ▼
[ Free Open Global Internet ]
```

---

## ⚡ One-Line Instant Installation | نصب خودکار با یک دستور

### 🪟 Windows (Open PowerShell as Administrator):
```powershell
irm https://raw.githubusercontent.com/tohid-sargol/family-home-vpn/main/setup.ps1 | iex
```

### 🍏 macOS & Linux:
```bash
curl -fsSL https://raw.githubusercontent.com/tohid-sargol/family-home-vpn/main/setup.sh | bash
```

---

## 🚀 Quick Start (Windows) | راه‌اندازی سریع در ویندوز

1. **Clone or Extract** the repository to any folder (e.g. `C:\family-home-vpn` or `~/family-home-vpn`):
   ```powershell
   git clone https://github.com/tohid-sargol/family-home-vpn.git
   cd family-home-vpn
   ```
2. **Right-click** `Install-Family-VPN.bat` and select **Run as Administrator** (یا دوبار کلیک کنید).
3. The installer prompts you for only **3 simple inputs**:
   - `Admin Password`: Press **Enter** to auto-generate a secure random password (or type a custom one).
   - `Family Invite Code`: Press **Enter** for `FAMILY2026` (or type your preferred family code).
   - `Telegram Alerts`: Type `y` to enter Bot Token and Chat ID, or press **Enter** to skip.
4. **Done!** The installer automatically:
   - Verifies Python and dependencies.
   - Scans and resolves port conflicts (8080, 2053, 10000).
   - Adds local firewall rules.
   - Disables laptop sleep when the lid is closed on AC power (`powercfg`).
   - Registers Windows autostart persistence (Scheduled Task).
   - Auto-launches your default browser to `http://127.0.0.1:8080/admin`.

---

## 🍏 Quick Start (macOS & Linux) | راه‌اندازی در لینوکس و مک

```bash
# 1. Navigate to the extracted folder
cd home-vpn

# 2. Grant execute permission and run
chmod +x setup.sh
./setup.sh
```

---

## 📱 How Family Connects | راهنمای اتصال اعضای خانواده

1. **Admin sends the Invite**:
   Open `/admin`, click **"Share via WhatsApp"** or **"Share via Telegram"** to send the signup link and family code to family members.
2. **Family Member Signs Up**:
   Opens the portal link on their phone, types the invite code (`FAMILY2026`), their name, email, and password.
3. **One-Tap Import**:
   - **Android**: Install **Hiddify** or **v2rayNG** from Google Play. Tap **Copy Subscription Link** in the portal, then tap `+` ➔ `Add from clipboard` in Hiddify. Tap Connect!
   - **iOS (iPhone/iPad)**: Install **Streisand** or **V2Box** from the App Store. Tap `+` ➔ `Add Subscription`, paste link, and connect.
   - **Windows / Mac**: Install desktop **Hiddify**, import the subscription link, and connect.

---

## 🛠️ Management & Operation | مدیریت و نگهداری

- **Admin Control Center**: Access via `http://127.0.0.1:8080/admin` (or via the public tunnel link displayed in the banner).
- **Restarting Manually**: Run `Start-Home-VPN.bat` or `Start-Home-VPN.vbs` (runs hidden in the background).
- **Stopping Services**: Terminate the background Python and `3x-ui.exe` processes from Task Manager.
- **Diagnostics Log**: All installation and runtime checks are written to `setup-diagnostics.log`.
- **Telegram Alerts Configuration**: If skipped during setup or updating credentials, add your Bot Token and Chat ID directly in the Admin Portal under Settings, or create `telegram_config.json`:
  ```json
  {
    "enabled": true,
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID"
  }
  ```
  *(The system will also read `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` from `config.json` or `.env` automatically).*
- **Knowledge Base**: Visit `http://127.0.0.1:8080/help` anytime for detailed diagrams and troubleshooting guides.

---

## 🔒 Security & Privacy | امنیت و حریم خصوصی
- Zero port forwarding: Your home router remains fully secured with no exposed open ports.
- Password hashes: Uses PBKDF2-HMAC-SHA256 with unique 16-byte random cryptographic salts.
- Session management: Cryptographically random 256-bit tokens with expiry enforcement.
- Split-tunneling: Iranian domestic services and banking data never route through the proxy.
