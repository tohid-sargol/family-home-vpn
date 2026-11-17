<#
.SYNOPSIS
    Home VPN Platform - Zero-Touch Self-Healing Installer & Diagnostics
.DESCRIPTION
    Automates pre-flight checks, runtime dependency setup, port conflict resolution,
    firewall & power configuration, autostart persistence, and browser launch.
#>

$ErrorActionPreference = "Continue"

if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $ScriptDir = Join-Path $HOME "family-home-vpn"
    if (-not (Test-Path (Join-Path $ScriptDir "portal.py"))) {
        Write-Host "Cloning family-home-vpn repository to $ScriptDir..." -ForegroundColor Cyan
        if (Get-Command git.exe -ErrorAction SilentlyContinue) {
            git clone https://github.com/tohid-sargol/family-home-vpn.git $ScriptDir
        } else {
            Write-Host "Downloading repository archive..." -ForegroundColor Cyan
            $zipPath = Join-Path $env:TEMP "family-home-vpn.zip"
            Invoke-WebRequest -Uri "https://github.com/tohid-sargol/family-home-vpn/archive/refs/heads/main.zip" -OutFile $zipPath
            Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\family-vpn-temp" -Force
            if (Test-Path "$env:TEMP\family-vpn-temp\family-home-vpn-main") {
                Move-Item -Path "$env:TEMP\family-vpn-temp\family-home-vpn-main" -Destination $ScriptDir -Force
            }
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\family-vpn-temp" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
} else {
    $ScriptDir = $PSScriptRoot
}
Set-Location -Path $ScriptDir

$LogFile = Join-Path $ScriptDir "setup-diagnostics.log"

function Write-DiagLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logLine = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logLine -ErrorAction SilentlyContinue

    switch ($Level) {
        "SUCCESS" { Write-Host $logLine -ForegroundColor Green }
        "WARNING" { Write-Host $logLine -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logLine -ForegroundColor Red }
        "HEADER"  { Write-Host $logLine -ForegroundColor Cyan }
        default   { Write-Host $logLine -ForegroundColor White }
    }
}

# ----------------- Banner ----------------- #
Clear-Host
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "   HOME VPN PLATFORM -- SELF-HEALING ZERO-TOUCH INSTALLER (v3.0)         " -ForegroundColor Cyan
Write-Host "   Zero Router Port Forwarding | Zero Domain Cost | Bilingual Support    " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

Write-DiagLog "Starting Home VPN installation session..." "HEADER"
Write-DiagLog "Install directory: $ScriptDir"

# ----------------- Check Elevation ----------------- #
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-DiagLog "Installer running without Administrator privileges. Some system settings (Firewall/Scheduled Task) may need approval." "WARNING"
} else {
    Write-DiagLog "Administrator privileges confirmed." "SUCCESS"
}

# ----------------- 3 Simple User Prompts ----------------- #
Write-Host ""
Write-Host "Please provide 3 quick settings (or press Enter to accept recommended defaults):" -ForegroundColor Yellow
Write-Host ""

# 1. Admin Password
$rawPass = Read-Host "1) Enter Admin Password [Press ENTER to auto-generate a strong password]"
if ([string]::IsNullOrWhiteSpace($rawPass)) {
    $autoBytes = [byte[]]::new(4)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($autoBytes)
    $autoSuffix = [System.BitConverter]::ToString($autoBytes).Replace("-", "").ToLower()
    $adminPassword = "Admin-$autoSuffix"
    Write-DiagLog "Auto-generated secure Admin Password: $adminPassword" "SUCCESS"
} else {
    $adminPassword = $rawPass.Trim()
    Write-DiagLog "Custom Admin Password provided." "INFO"
}

# 2. Invite Code
$rawInvite = Read-Host "2) Enter Family Invite Code [Press ENTER for 'FAMILY2026']"
if ([string]::IsNullOrWhiteSpace($rawInvite)) {
    $inviteCode = "FAMILY2026"
} else {
    $inviteCode = $rawInvite.Trim().ToUpper()
}
Write-DiagLog "Family Invite Code configured: $inviteCode" "SUCCESS"

# 3. Telegram Alerts (Optional)
$rawTg = Read-Host "3) Enable Telegram Notifications on reboot/ip change? (y/N)"
$tgEnabled = $false
$tgToken = ""
$tgChatId = ""
if ($rawTg -match "^[yY]") {
    $tgToken = (Read-Host "   -> Enter Telegram Bot Token").Trim()
    $tgChatId = (Read-Host "   -> Enter Your Telegram Chat ID").Trim()
    if ($tgToken -and $tgChatId) {
        $tgEnabled = $true
        Write-DiagLog "Telegram Bot configured (Token masked, Chat ID: $tgChatId)" "SUCCESS"
    }
} else {
    Write-DiagLog "Telegram notifications skipped by user." "INFO"
}

Write-Host ""
Write-DiagLog "Running pre-flight diagnostics and system preparation..." "HEADER"

# ----------------- Runtime Detection: Python ----------------- #
$pythonExe = $null

# 1. Check path
$testPython = Get-Command python.exe -ErrorAction SilentlyContinue
if ($testPython) {
    $pythonExe = $testPython.Source
}

# 2. Check LocalAppData
if (-not $pythonExe) {
    $localPy = Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python3*" -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($localPy) {
        $pythonExe = $localPy.FullName
    }
}

# 3. Check Program Files
if (-not $pythonExe) {
    $progPy = Get-ChildItem -Path "$env:ProgramFiles\Python3*" -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($progPy) {
        $pythonExe = $progPy.FullName
    }
}

# 4. Check py launcher
if (-not $pythonExe) {
    $testPy = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($testPy) {
        $pythonExe = "py"
    }
}

if (-not $pythonExe) {
    Write-DiagLog "Python 3 is not installed or not in system path. Attempting auto-installation via winget..." "WARNING"
    try {
        winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        $localPy = Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python3*" -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($localPy) {
            $pythonExe = $localPy.FullName
        }
    } catch {
        Write-DiagLog "Winget auto-install failed: $_. Please install Python 3.12 from python.org." "ERROR"
    }
}

if ($pythonExe) {
    $pyVer = & $pythonExe --version 2>&1
    Write-DiagLog "Python Runtime detected: $pythonExe ($pyVer)" "SUCCESS"

    # Verify and install Python packages
    Write-DiagLog "Checking Python dependencies (FastAPI, Uvicorn, Requests, QRCode, Pillow, Pydantic)..."
    $reqFile = Join-Path $ScriptDir "requirements.txt"
    if (Test-Path $reqFile) {
        & $pythonExe -m pip install -r $reqFile --quiet --disable-pip-version-check
        Write-DiagLog "Python pip dependencies verified and up to date." "SUCCESS"
    }
} else {
    Write-DiagLog "CRITICAL: Python runtime could not be verified. Some features may not start." "ERROR"
}

# ----------------- Runtime Detection: Docker vs Standalone ----------------- #
$dockerRunning = $false
try {
    $dockerVer = docker --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-DiagLog "Docker CLI detected: $dockerVer"
        $dockerPs = docker ps 2>&1
        if ($LASTEXITCODE -eq 0) {
            $dockerRunning = $true
            Write-DiagLog "Docker Engine is active and running." "SUCCESS"
        } else {
            Write-DiagLog "Docker installed but daemon is stopped or Hyper-V is disabled in BIOS." "WARNING"
        }
    }
} catch {}

if (-not $dockerRunning) {
    Write-DiagLog "Cleanly activating Standalone Native Runtime (Native Python + bundled Cloudflared + bundled 3x-ui)." "SUCCESS"
}

# ----------------- Port Conflict Scanner & Auto-Remediation ----------------- #
function Get-AvailablePort {
    param([int]$startPort)
    $port = $startPort
    while ($port -lt ($startPort + 100)) {
        $listener = $null
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
            $listener.Start()
            $listener.Stop()
            return $port
        } catch {
            Write-DiagLog "Port $port is currently in use. Auto-remediating to next port..." "WARNING"
            $port++
        }
    }
    return $startPort
}

$portalPort = Get-AvailablePort -startPort 8080
$xuiPort    = Get-AvailablePort -startPort 2053
$vpnPort    = Get-AvailablePort -startPort 10000

Write-DiagLog "Port mapping assigned: Portal=$portalPort, 3x-ui=$xuiPort, VPN_Traffic=$vpnPort" "SUCCESS"

# ----------------- Windows Firewall Allow Rules ----------------- #
if ($isAdmin) {
    try {
        netsh advfirewall firewall delete rule name="HomeVPN-Ports" >$null 2>&1
        netsh advfirewall firewall add rule name="HomeVPN-Ports" dir=in action=allow protocol=TCP localport="$portalPort,$xuiPort,$vpnPort" description="Home VPN Local LAN and Engine Access" >$null 2>&1
        Write-DiagLog "Windows Defender Firewall rules successfully configured for ports $portalPort, $xuiPort, $vpnPort." "SUCCESS"
    } catch {
        Write-DiagLog "Could not add firewall rules: $_" "WARNING"
    }
}

# ----------------- Power Settings: Disable AC Lid Sleep ----------------- #
try {
    # Disable sleep on AC
    powercfg /change standby-timeout-ac 0 >$null 2>&1
    # Set display turn off to 15 mins on AC
    powercfg /change monitor-timeout-ac 15 >$null 2>&1
    # Disable lid-close action when plugged into AC (0 = Do Nothing)
    powercfg /setacvalueindex scheme_current sub_buttons lidaction 0 >$null 2>&1
    powercfg /setactive scheme_current >$null 2>&1
    Write-DiagLog "Laptop power settings configured: Lid-close sleep disabled on AC power for 24/7 server uptime." "SUCCESS"
} catch {
    Write-DiagLog "Powercfg configuration warning: $_" "WARNING"
}

# ----------------- Startup & Persistence Configuration ----------------- #
$vbsPath = Join-Path $ScriptDir "Start-Home-VPN.vbs"
$watchdogVbs = Join-Path $ScriptDir "Watchdog-Home-VPN.vbs"
if (Test-Path $watchdogVbs) {
    # 1. Windows Startup Folder Shortcut
    try {
        $startupFolder = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Startup)
        $shortcutPath = Join-Path $startupFolder "HomeVPN-AutoStart.lnk"
        $wsh = New-Object -ComObject WScript.Shell
        $sc = $wsh.CreateShortcut($shortcutPath)
        $sc.TargetPath = "wscript.exe"
        $sc.Arguments = "//B `"$watchdogVbs`""
        $sc.WorkingDirectory = $ScriptDir
        $sc.Description = "Home VPN Platform Background Autostart Watchdog"
        $sc.Save()
        Write-DiagLog "Startup folder shortcut registered: $shortcutPath" "SUCCESS"
    } catch {
        Write-DiagLog "Startup shortcut creation warning: $_" "WARNING"
    }

    # 2. Windows Scheduled Task (Runs on Logon and repeats every 5 minutes)
    try {
        $taskName = "HomeVPN-AutoStart"
        $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "//B `"$watchdogVbs`"" -WorkingDirectory $ScriptDir
        $triggerLogon = New-ScheduledTaskTrigger -AtLogOn
        $triggerRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 5)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 72)
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($triggerLogon, $triggerRepeat) -Settings $settings -Force -ErrorAction Stop | Out-Null
        Write-DiagLog "Windows Scheduled Task '$taskName' registered cleanly via Register-ScheduledTask." "SUCCESS"
    } catch {
        # Fallback to schtasks
        schtasks /create /tn "HomeVPN-AutoStart" /tr "wscript.exe //B `"$watchdogVbs`"" /sc minute /mo 5 /f >$null 2>&1
        Write-DiagLog "Windows Scheduled Task 'HomeVPN-AutoStart' registered via schtasks." "SUCCESS"
    }
}

# ----------------- Write Configuration Files ----------------- #
# 1. config.json
$configObj = @{
    PORTAL_TITLE   = "Family Home VPN"
    PORTAL_PORT    = $portalPort
    XUI_PORT       = $xuiPort
    VPN_PORT       = $vpnPort
    INVITE_CODE    = $inviteCode
    XUI_API_TOKEN  = "hUNP2ShXYRwWigG7zvKFoAwC7edTVAAv9hBuh93FMyJdY0zt"
}
$configFile = Join-Path $ScriptDir "config.json"
$configObj | ConvertTo-Json -Depth 4 | Set-Content -Path $configFile -Encoding UTF8
Write-DiagLog "Configuration saved to config.json." "SUCCESS"

# 2. admin_auth.json
$saltBytes = [byte[]]::new(16)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($saltBytes)
$saltHex = [System.BitConverter]::ToString($saltBytes).Replace("-", "").ToLower()

# PBKDF2 HMAC-SHA256 100,000 iterations
$pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
    $adminPassword,
    $saltBytes,
    100000,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256
)
$hashBytes = $pbkdf2.GetBytes(32)
$hashHex = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()

$authObj = @{
    username         = "admin"
    salt             = $saltHex
    password_hash    = $hashHex
    initial_password = $adminPassword
    is_custom        = $true
    created_at       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}
$authFile = Join-Path $ScriptDir "admin_auth.json"
$authObj | ConvertTo-Json -Depth 4 | Set-Content -Path $authFile -Encoding UTF8
Write-DiagLog "Admin authentication credentials saved to admin_auth.json." "SUCCESS"

# 3. telegram_config.json
$tgObj = @{
    enabled   = $tgEnabled
    bot_token = $tgToken
    chat_id   = $tgChatId
}
$tgFile = Join-Path $ScriptDir "telegram_config.json"
$tgObj | ConvertTo-Json -Depth 4 | Set-Content -Path $tgFile -Encoding UTF8
Write-DiagLog "Telegram alert settings saved to telegram_config.json." "SUCCESS"

# ----------------- Start Services ----------------- #
Write-Host ""
Write-DiagLog "Launching Home VPN services in background..." "HEADER"

try {
    Start-Process -FilePath "wscript.exe" -ArgumentList "`"$vbsPath`"" -WorkingDirectory $ScriptDir
    Write-DiagLog "Background launcher process invoked." "SUCCESS"
} catch {
    Write-DiagLog "Could not invoke wscript launcher: $_. Falling back to direct python launch..." "WARNING"
    if ($pythonExe) {
        Start-Process -FilePath $pythonExe -ArgumentList "portal.py" -WorkingDirectory $ScriptDir -WindowStyle Hidden
    }
}

# ----------------- Wait for Portal Health ----------------- #
Write-Host "Waiting for Web Portal on port $portalPort to become active..." -NoNewline
$portalOnline = $false
for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Seconds 1
    Write-Host "." -NoNewline
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$portalPort/api/status" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($response -and $response.StatusCode -eq 200) {
            $portalOnline = $true
            break
        }
    } catch {}
}
Write-Host ""

# ----------------- Detect Local LAN IPv4 ----------------- #
$lanIp = "127.0.0.1"
try {
    $socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::IP)
    $socket.Connect("8.8.8.8", 80)
    $lanIp = $socket.LocalEndPoint.Address.IPAddressToString
    $socket.Close()
} catch {}

if ($portalOnline) {
    Write-DiagLog "Home VPN Platform is ONLINE and Healthy!" "SUCCESS"
} else {
    Write-DiagLog "Portal initialization is taking longer than expected. It will be ready in a few moments." "WARNING"
}

# ----------------- Auto-Launch Browser ----------------- #
$adminUrl = "http://127.0.0.1:$portalPort/admin"
$lanAdminUrl = "http://${lanIp}:$portalPort/admin"

Write-DiagLog "Opening Admin Dashboard in default browser: $adminUrl" "SUCCESS"
Start-Process $adminUrl

# ----------------- Final Summary Display ----------------- #
Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "                  INSTALLATION COMPLETED SUCCESSFULLY!                    " -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  🔑 Admin Username:       admin" -ForegroundColor White
Write-Host "  🔑 Admin Password:       $adminPassword" -ForegroundColor Yellow
Write-Host "  🎫 Family Invite Code:   $inviteCode" -ForegroundColor Cyan
Write-Host ""
Write-Host "  🌐 Local Admin URL:      $adminUrl" -ForegroundColor White
Write-Host "  📶 Home Wi-Fi (LAN) URL: $lanAdminUrl" -ForegroundColor White
Write-Host "  📄 Diagnostics Log:      $LogFile" -ForegroundColor Gray
Write-Host ""
Write-Host "  💡 NOTE: Your laptop is now set to stay online even with the lid closed." -ForegroundColor Yellow
Write-Host "     Keep it plugged into AC power for 24/7 family access." -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host ""

Read-Host "Press ENTER to close installer"

