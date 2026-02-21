#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blue Team Honeypot & Trap Toolkit
    Summit Range Consulting — CTF / Blue Team Challenge Edition

.DESCRIPTION
    Deploys honeypot traps for Blue Team defense:
    - Fake port listeners (honeypots)
    - Port scan detection & alerting
    - Tripwire files (alert on access)
    - Fake SMB shares
    - Fake credentials in event logs

.USAGE
    .\BlueTeam-Honeypot.ps1 -Action Deploy   # Deploy all traps
    .\BlueTeam-Honeypot.ps1 -Action Monitor  # Start monitoring
    .\BlueTeam-Honeypot.ps1 -Action Status   # Show trap status
    .\BlueTeam-Honeypot.ps1 -Action Cleanup  # Remove all traps
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Deploy","Monitor","Status","Cleanup","Menu")]
    [string]$Action = "Menu"
)

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
$Config = @{
    # Honeypot ports to listen on (commonly targeted)
    HoneypotPorts    = @(21, 23, 2222, 8080, 3389, 1433, 3306)
    
    # Real ports to exclude from scan detection
    LegitPorts       = @(80, 443, 22, 53)
    
    # Tripwire file locations
    TripwireDir      = "C:\Honeypot\Tripwires"
    TripwireFiles    = @("passwords.txt", "credentials.xlsx", "admin_backup.zip", "ssh_keys.pem", "database.sql")
    
    # SMB honeypot share
    SMBShareName     = "BACKUP$"
    SMBSharePath     = "C:\Honeypot\FakeShare"
    SMBShareDesc     = "Backup Storage"
    
    # Alert log
    AlertLog         = "C:\Honeypot\Logs\alerts.log"
    EventLog         = "BlueTeam-Honeypot"
    
    # Scan detection threshold (connections per minute)
    ScanThreshold    = 5
    
    # Fake credentials to plant in logs
    FakeCredentials  = @(
        @{User="admin";     Pass="Admin@2024!";    Service="RDP"},
        @{User="svcbackup"; Pass="Backup#1234";    Service="SMB"},
        @{User="sa";        Pass="SQLServer2024";  Service="MSSQL"},
        @{User="ftpuser";   Pass="FTP_P@ssw0rd";  Service="FTP"}
    )
}

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   ▲  SUMMIT RANGE CONSULTING                        ║" -ForegroundColor Cyan
    Write-Host "  ║      Blue Team Honeypot & Trap Toolkit               ║" -ForegroundColor Cyan
    Write-Host "  ║      CTF / Blue Team Challenge Edition               ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
function Write-Alert {
    param([string]$Message, [string]$Level = "INFO", [string]$SourceIP = "")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logDir = Split-Path $Config.AlertLog -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    
    $logLine = "[$timestamp] [$Level] $Message"
    if ($SourceIP) { $logLine += " | Source: $SourceIP" }
    
    Add-Content -Path $Config.AlertLog -Value $logLine
    
    $color = switch ($Level) {
        "CRITICAL" { "Red" }
        "WARNING"  { "Yellow" }
        "TRAP"     { "Magenta" }
        default    { "Green" }
    }
    Write-Host "  $logLine" -ForegroundColor $color
}

# ─────────────────────────────────────────────
#  1. HONEYPOT PORT LISTENERS
# ─────────────────────────────────────────────
function Deploy-PortHoneypots {
    Write-Host "`n  [+] Deploying Port Honeypots..." -ForegroundColor Yellow
    
    $jobs = @()
    foreach ($port in $Config.HoneypotPorts) {
        $job = Start-Job -ScriptBlock {
            param($p, $logPath, $threshold)
            
            $connections = @{}
            
            try {
                $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $p)
                $listener.Start()
                
                while ($true) {
                    if ($listener.Pending()) {
                        $client = $listener.AcceptTcpClient()
                        $ip = $client.Client.RemoteEndPoint.Address.ToString()
                        $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        
                        # Track connections for scan detection
                        $minute = (Get-Date).Minute
                        if (-not $connections[$ip]) { $connections[$ip] = @{} }
                        if (-not $connections[$ip][$minute]) { $connections[$ip][$minute] = 0 }
                        $connections[$ip][$minute]++
                        
                        $logDir = Split-Path $logPath -Parent
                        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
                        
                        $level = if ($connections[$ip][$minute] -ge $threshold) { "CRITICAL" } else { "TRAP" }
                        $msg = "[$time] [$level] HONEYPOT HIT Port:$p | Source: $ip | Connections this minute: $($connections[$ip][$minute])"
                        Add-Content -Path $logPath -Value $msg
                        
                        # Send fake banner based on port
                        $banner = switch ($p) {
                            21   { "220 FTP Server Ready`r`n" }
                            23   { "Welcome to Telnet Service`r`n" }
                            2222 { "SSH-2.0-OpenSSH_8.9`r`n" }
                            8080 { "HTTP/1.1 200 OK`r`nServer: Apache/2.4`r`n`r`n<html><body>Admin Panel</body></html>" }
                            1433 { "MSSQL Server 2019`r`n" }
                            3306 { "5.7.38-MySQL Community Server`r`n" }
                            default { "Connected`r`n" }
                        }
                        
                        $stream = $client.GetStream()
                        $bytes = [System.Text.Encoding]::ASCII.GetBytes($banner)
                        $stream.Write($bytes, 0, $bytes.Length)
                        Start-Sleep -Milliseconds 500
                        $client.Close()
                    }
                    Start-Sleep -Milliseconds 100
                }
            } catch {
                Add-Content -Path $logPath -Value "[$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))] [ERROR] Port $p listener failed: $_"
            }
        } -ArgumentList $port, $Config.AlertLog, $Config.ScanThreshold
        
        $jobs += @{Port=$port; Job=$job}
        Write-Host "    ✓ Listening on port $port (Job ID: $($job.Id))" -ForegroundColor Green
    }
    
    # Save job IDs for monitoring
    $jobData = $jobs | ForEach-Object { @{Port=$_.Port; JobId=$_.Job.Id} }
    $jobData | ConvertTo-Json | Set-Content "C:\Honeypot\port_jobs.json"
    
    Write-Alert "Port honeypots deployed on ports: $($Config.HoneypotPorts -join ', ')" "INFO"
    return $jobs
}

# ─────────────────────────────────────────────
#  2. PORT SCAN DETECTOR
# ─────────────────────────────────────────────
function Deploy-ScanDetector {
    Write-Host "`n  [+] Deploying Port Scan Detector..." -ForegroundColor Yellow
    
    $job = Start-Job -ScriptBlock {
        param($logPath, $legitPorts, $threshold)
        
        $connectionTracker = @{}
        
        while ($true) {
            try {
                # Get current TCP connections
                $connections = Get-NetTCPConnection -State SynReceived,Established -ErrorAction SilentlyContinue |
                    Where-Object { $_.LocalPort -notin $legitPorts -and $_.RemoteAddress -ne "127.0.0.1" }
                
                foreach ($conn in $connections) {
                    $ip = $conn.RemoteAddress
                    $port = $conn.LocalPort
                    $key = "$ip-$(Get-Date -Format 'yyyyMMddHHmm')"
                    
                    if (-not $connectionTracker[$key]) { $connectionTracker[$key] = [System.Collections.Generic.List[int]]::new() }
                    if ($port -notin $connectionTracker[$key]) {
                        $connectionTracker[$key].Add($port)
                    }
                    
                    # Alert if scanning multiple ports
                    if ($connectionTracker[$key].Count -ge $threshold) {
                        $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        $ports = $connectionTracker[$key] -join ","
                        $msg = "[$time] [CRITICAL] PORT SCAN DETECTED | Source: $ip | Ports scanned: $ports"
                        Add-Content -Path $logPath -Value $msg
                        $connectionTracker[$key] = [System.Collections.Generic.List[int]]::new() # Reset
                    }
                }
                
                # Clean old entries
                $cutoff = (Get-Date).AddMinutes(-5).ToString("yyyyMMddHHmm")
                $oldKeys = $connectionTracker.Keys | Where-Object { $_ -lt $cutoff }
                $oldKeys | ForEach-Object { $connectionTracker.Remove($_) }
                
            } catch { }
            Start-Sleep -Seconds 2
        }
    } -ArgumentList $Config.AlertLog, $Config.LegitPorts, $Config.ScanThreshold
    
    Write-Host "    ✓ Scan detector active (Job ID: $($job.Id))" -ForegroundColor Green
    Write-Alert "Port scan detector deployed — threshold: $($Config.ScanThreshold) ports/min" "INFO"
    return $job
}

# ─────────────────────────────────────────────
#  3. TRIPWIRE FILES
# ─────────────────────────────────────────────
function Deploy-Tripwires {
    Write-Host "`n  [+] Deploying Tripwire Files..." -ForegroundColor Yellow
    
    # Create tripwire directory
    if (-not (Test-Path $Config.TripwireDir)) {
        New-Item -ItemType Directory -Path $Config.TripwireDir -Force | Out-Null
    }
    
    foreach ($filename in $Config.TripwireFiles) {
        $filepath = Join-Path $Config.TripwireDir $filename
        
        # Create fake content based on file type
        $content = switch -Wildcard ($filename) {
            "*.txt"  { "admin:Admin@2024!`nroot:R00t_P@ss`nsvcbackup:Backup#1234`nftpuser:FTP_P@ssw0rd" }
            "*.pem"  { "-----BEGIN RSA PRIVATE KEY-----`nMIIEowIBAAKCAQEA[FAKE_KEY_DATA]`n-----END RSA PRIVATE KEY-----" }
            "*.sql"  { "-- Database backup`nINSERT INTO users VALUES ('admin','$2y$10$FAKEHASH','administrator');" }
            default  { "CONFIDENTIAL - Internal Use Only`nAccess to this file is monitored and logged." }
        }
        
        Set-Content -Path $filepath -Value $content
        
        # Set up file system audit via scheduled task monitoring
        $acl = Get-Acl $filepath
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            [System.Security.AccessControl.FileSystemRights]::ReadData,
            [System.Security.AccessControl.AuditFlags]::Success
        )
        try {
            $acl.AddAuditRule($auditRule)
            Set-Acl -Path $filepath -AclObject $acl -ErrorAction SilentlyContinue
        } catch { }
        
        Write-Host "    ✓ Tripwire planted: $filepath" -ForegroundColor Green
    }
    
    # Deploy file access monitor job
    $tripwireJob = Start-Job -ScriptBlock {
        param($dir, $files, $logPath)
        
        $watchers = @()
        foreach ($file in $files) {
            $fullPath = Join-Path $dir $file
            if (Test-Path (Split-Path $fullPath -Parent)) {
                $watcher = New-Object System.IO.FileSystemWatcher
                $watcher.Path = Split-Path $fullPath -Parent
                $watcher.Filter = Split-Path $fullPath -Leaf
                $watcher.NotifyFilter = [System.IO.NotifyFilters]::LastAccess -bor [System.IO.NotifyFilters]::LastWrite
                $watcher.EnableRaisingEvents = $true
                
                Register-ObjectEvent -InputObject $watcher -EventName "Accessed" -Action {
                    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    $f = $Event.SourceEventArgs.FullPath
                    $logDir = Split-Path $using:logPath -Parent
                    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
                    Add-Content -Path $using:logPath -Value "[$time] [TRAP] TRIPWIRE TRIGGERED: $f accessed!"
                } | Out-Null
                
                $watchers += $watcher
            }
        }
        
        while ($true) { Start-Sleep -Seconds 1 }
    } -ArgumentList $Config.TripwireDir, $Config.TripwireFiles, $Config.AlertLog
    
    Write-Alert "Tripwire files deployed in: $($Config.TripwireDir)" "INFO"
    return $tripwireJob
}

# ─────────────────────────────────────────────
#  4. FAKE SMB SHARE
# ─────────────────────────────────────────────
function Deploy-SMBHoneypot {
    Write-Host "`n  [+] Deploying SMB Honeypot Share..." -ForegroundColor Yellow
    
    # Create fake share directory with juicy-looking files
    if (-not (Test-Path $Config.SMBSharePath)) {
        New-Item -ItemType Directory -Path $Config.SMBSharePath -Force | Out-Null
    }
    
    # Plant fake files in share
    $fakeFiles = @{
        "Q2_Financial_Report_CONFIDENTIAL.xlsx" = "FAKE FINANCIAL DATA"
        "Employee_Passwords_DO_NOT_SHARE.txt"   = "admin:Admin@2024!`nhr_manager:HR#Pass2024"
        "VPN_Config_AllUsers.ovpn"              = "# OpenVPN Config`nclient`nremote vpn.internal.corp 1194"
        "Active_Directory_Export.csv"           = "Username,Password,Department`nadmin,Admin@2024!,IT"
    }
    
    foreach ($file in $fakeFiles.Keys) {
        Set-Content -Path (Join-Path $Config.SMBSharePath $file) -Value $fakeFiles[$file]
    }
    
    # Create SMB share (remove if exists first)
    try {
        Remove-SmbShare -Name $Config.SMBShareName -Force -ErrorAction SilentlyContinue
        New-SmbShare -Name $Config.SMBShareName `
                     -Path $Config.SMBSharePath `
                     -Description $Config.SMBShareDesc `
                     -FullAccess "Everyone" `
                     -ErrorAction Stop | Out-Null
        
        Write-Host "    ✓ SMB Share created: \\localhost\$($Config.SMBShareName)" -ForegroundColor Green
        Write-Alert "SMB Honeypot share deployed: \\localhost\$($Config.SMBShareName)" "INFO"
    } catch {
        Write-Host "    ✗ SMB Share creation failed (may need elevated privileges): $_" -ForegroundColor Red
    }
    
    # Monitor SMB access via event log
    $smbJob = Start-Job -ScriptBlock {
        param($shareName, $logPath)
        
        $lastCheck = Get-Date
        while ($true) {
            try {
                # Check Security event log for SMB access (Event ID 5140)
                $events = Get-WinEvent -FilterHashtable @{
                    LogName   = 'Security'
                    Id        = 5140
                    StartTime = $lastCheck
                } -ErrorAction SilentlyContinue
                
                foreach ($evt in $events) {
                    if ($evt.Message -like "*$shareName*") {
                        $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        $logDir = Split-Path $logPath -Parent
                        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
                        Add-Content -Path $logPath -Value "[$time] [CRITICAL] SMB HONEYPOT ACCESSED: \\$shareName | $($evt.Message -replace '\s+', ' ')"
                    }
                }
                $lastCheck = Get-Date
            } catch { }
            Start-Sleep -Seconds 5
        }
    } -ArgumentList $Config.SMBShareName, $Config.AlertLog
    
    return $smbJob
}

# ─────────────────────────────────────────────
#  5. FAKE CREDENTIALS IN EVENT LOG
# ─────────────────────────────────────────────
function Plant-FakeCredentials {
    Write-Host "`n  [+] Planting Fake Credentials in Event Logs..." -ForegroundColor Yellow
    
    # Create custom event source if not exists
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Config.EventLog)) {
            New-EventLog -LogName Application -Source $Config.EventLog -ErrorAction SilentlyContinue
        }
    } catch { }
    
    foreach ($cred in $Config.FakeCredentials) {
        $msg = "Authentication attempt logged for service $($cred.Service). " +
               "User: $($cred.User) | Credential hash stored for audit purposes. " +
               "Last successful auth: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        
        try {
            Write-EventLog -LogName Application -Source $Config.EventLog `
                           -EventId 4624 -EntryType Information -Message $msg -ErrorAction SilentlyContinue
            Write-Host "    ✓ Fake cred planted for: $($cred.Service) / $($cred.User)" -ForegroundColor Green
        } catch {
            # Fallback: write to a "system log" file that looks legit
            $logFile = "C:\Windows\Temp\auth_service.log"
            Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') INFO auth_service: $msg"
            Write-Host "    ✓ Fake cred written to: $logFile ($($cred.Service)/$($cred.User))" -ForegroundColor Green
        }
    }
    
    Write-Alert "Fake credentials planted in logs — $($Config.FakeCredentials.Count) entries" "INFO"
}

# ─────────────────────────────────────────────
#  MONITOR — LIVE ALERT DASHBOARD
# ─────────────────────────────────────────────
function Start-Monitor {
    Show-Banner
    Write-Host "  [MONITOR] Live Alert Dashboard — Press Ctrl+C to exit" -ForegroundColor Cyan
    Write-Host "  Log: $($Config.AlertLog)" -ForegroundColor Gray
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    
    $lastSize = 0
    while ($true) {
        if (Test-Path $Config.AlertLog) {
            $content = Get-Content $Config.AlertLog -Raw
            if ($content.Length -gt $lastSize) {
                $newContent = $content.Substring($lastSize)
                foreach ($line in ($newContent -split "`n" | Where-Object { $_.Trim() })) {
                    $color = if ($line -match "CRITICAL") { "Red" }
                             elseif ($line -match "TRAP") { "Magenta" }
                             elseif ($line -match "WARNING") { "Yellow" }
                             else { "Green" }
                    Write-Host "  $line" -ForegroundColor $color
                }
                $lastSize = $content.Length
            }
        } else {
            Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] Waiting for alerts... (log not yet created)" -ForegroundColor DarkGray
        }
        Start-Sleep -Seconds 2
    }
}

# ─────────────────────────────────────────────
#  STATUS
# ─────────────────────────────────────────────
function Show-Status {
    Show-Banner
    Write-Host "  [STATUS] Honeypot Trap Status" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    
    # Check ports
    Write-Host "`n  Port Honeypots:" -ForegroundColor Yellow
    foreach ($port in $Config.HoneypotPorts) {
        $listening = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        $status = if ($listening) { "✓ ACTIVE" } else { "✗ INACTIVE" }
        $color  = if ($listening) { "Green" } else { "Red" }
        Write-Host "    Port $port : $status" -ForegroundColor $color
    }
    
    # Check SMB share
    Write-Host "`n  SMB Honeypot Share:" -ForegroundColor Yellow
    $share = Get-SmbShare -Name $Config.SMBShareName -ErrorAction SilentlyContinue
    if ($share) {
        Write-Host "    ✓ \\localhost\$($Config.SMBShareName) — ACTIVE" -ForegroundColor Green
    } else {
        Write-Host "    ✗ SMB Share not found" -ForegroundColor Red
    }
    
    # Check tripwires
    Write-Host "`n  Tripwire Files:" -ForegroundColor Yellow
    foreach ($f in $Config.TripwireFiles) {
        $path = Join-Path $Config.TripwireDir $f
        $exists = Test-Path $path
        $status = if ($exists) { "✓ IN PLACE" } else { "✗ MISSING" }
        $color  = if ($exists) { "Green" } else { "Red" }
        Write-Host "    $status : $f" -ForegroundColor $color
    }
    
    # Recent alerts
    Write-Host "`n  Recent Alerts (last 10):" -ForegroundColor Yellow
    if (Test-Path $Config.AlertLog) {
        Get-Content $Config.AlertLog -Tail 10 | ForEach-Object {
            $color = if ($_ -match "CRITICAL") { "Red" } elseif ($_ -match "TRAP") { "Magenta" } else { "Green" }
            Write-Host "    $_" -ForegroundColor $color
        }
    } else {
        Write-Host "    No alerts yet." -ForegroundColor DarkGray
    }
    
    # Alert stats
    Write-Host "`n  Alert Summary:" -ForegroundColor Yellow
    if (Test-Path $Config.AlertLog) {
        $allAlerts    = (Get-Content $Config.AlertLog).Count
        $critAlerts   = (Select-String -Path $Config.AlertLog -Pattern "CRITICAL").Count
        $trapAlerts   = (Select-String -Path $Config.AlertLog -Pattern "TRAP").Count
        $scanAlerts   = (Select-String -Path $Config.AlertLog -Pattern "PORT SCAN").Count
        Write-Host "    Total Alerts   : $allAlerts" -ForegroundColor White
        Write-Host "    Critical       : $critAlerts" -ForegroundColor Red
        Write-Host "    Trap Hits      : $trapAlerts" -ForegroundColor Magenta
        Write-Host "    Port Scans     : $scanAlerts" -ForegroundColor Yellow
    }
}

# ─────────────────────────────────────────────
#  CLEANUP
# ─────────────────────────────────────────────
function Start-Cleanup {
    Write-Host "`n  [CLEANUP] Removing all honeypot traps..." -ForegroundColor Yellow
    
    # Stop all background jobs
    Get-Job | Stop-Job -PassThru | Remove-Job
    Write-Host "    ✓ Background jobs stopped" -ForegroundColor Green
    
    # Remove SMB share
    Remove-SmbShare -Name $Config.SMBShareName -Force -ErrorAction SilentlyContinue
    Write-Host "    ✓ SMB share removed" -ForegroundColor Green
    
    # Remove honeypot directories
    if (Test-Path "C:\Honeypot") {
        Remove-Item -Path "C:\Honeypot" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "    ✓ Honeypot files removed" -ForegroundColor Green
    }
    
    # Remove fake auth log
    Remove-Item "C:\Windows\Temp\auth_service.log" -Force -ErrorAction SilentlyContinue
    
    Write-Host "`n  [✓] Cleanup complete. All traps removed." -ForegroundColor Green
}

# ─────────────────────────────────────────────
#  INTERACTIVE MENU
# ─────────────────────────────────────────────
function Show-Menu {
    Show-Banner
    Write-Host "  What would you like to do?`n" -ForegroundColor White
    Write-Host "  [1] Deploy ALL Traps         — Full honeypot deployment" -ForegroundColor Cyan
    Write-Host "  [2] Monitor Live Alerts      — Real-time alert dashboard" -ForegroundColor Cyan
    Write-Host "  [3] Show Status              — Check all trap status" -ForegroundColor Cyan
    Write-Host "  [4] Cleanup All Traps        — Remove everything" -ForegroundColor Cyan
    Write-Host "  [5] Deploy Individual Traps  — Choose specific traps" -ForegroundColor Cyan
    Write-Host "  [Q] Quit`n" -ForegroundColor Gray
    
    $choice = Read-Host "  Select option"
    
    switch ($choice.ToUpper()) {
        "1" { Deploy-AllTraps }
        "2" { Start-Monitor }
        "3" { Show-Status }
        "4" { Start-Cleanup }
        "5" { Show-IndividualMenu }
        "Q" { exit }
        default { Write-Host "  Invalid option." -ForegroundColor Red; Start-Sleep 1; Show-Menu }
    }
}

function Show-IndividualMenu {
    Show-Banner
    Write-Host "  Deploy Individual Traps:`n" -ForegroundColor White
    Write-Host "  [1] Port Honeypots only" -ForegroundColor Cyan
    Write-Host "  [2] Port Scan Detector only" -ForegroundColor Cyan
    Write-Host "  [3] Tripwire Files only" -ForegroundColor Cyan
    Write-Host "  [4] SMB Honeypot Share only" -ForegroundColor Cyan
    Write-Host "  [5] Plant Fake Credentials only" -ForegroundColor Cyan
    Write-Host "  [B] Back`n" -ForegroundColor Gray
    
    $choice = Read-Host "  Select option"
    switch ($choice.ToUpper()) {
        "1" { Deploy-PortHoneypots }
        "2" { Deploy-ScanDetector }
        "3" { Deploy-Tripwires }
        "4" { Deploy-SMBHoneypot }
        "5" { Plant-FakeCredentials }
        "B" { Show-Menu }
    }
    
    Write-Host "`n  Press any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-Menu
}

# ─────────────────────────────────────────────
#  DEPLOY ALL
# ─────────────────────────────────────────────
function Deploy-AllTraps {
    Show-Banner
    Write-Host "  [*] Deploying ALL Blue Team Traps...`n" -ForegroundColor Yellow
    
    # Create base directory
    New-Item -ItemType Directory -Path "C:\Honeypot\Logs" -Force | Out-Null
    
    Write-Alert "=== BLUE TEAM HONEYPOT DEPLOYMENT STARTED ===" "INFO"
    
    $portJobs    = Deploy-PortHoneypots
    $scanJob     = Deploy-ScanDetector
    $tripJob     = Deploy-Tripwires
    $smbJob      = Deploy-SMBHoneypot
    Plant-FakeCredentials
    
    Write-Host "`n  ╔══════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  ✓ ALL TRAPS DEPLOYED SUCCESSFULLY           ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Honeypot Ports : $($Config.HoneypotPorts -join ', ')" -ForegroundColor White
    Write-Host "  SMB Share      : \\localhost\$($Config.SMBShareName)" -ForegroundColor White
    Write-Host "  Tripwires      : $($Config.TripwireDir)" -ForegroundColor White
    Write-Host "  Alert Log      : $($Config.AlertLog)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Run with -Action Monitor to watch live alerts" -ForegroundColor Cyan
    Write-Host "  Run with -Action Status  to check trap status" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Alert "=== ALL TRAPS ACTIVE — READY FOR RED TEAM ===" "INFO"
}

# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
switch ($Action) {
    "Deploy"  { Deploy-AllTraps }
    "Monitor" { Start-Monitor }
    "Status"  { Show-Status }
    "Cleanup" { Start-Cleanup }
    "Menu"    { Show-Menu }
}
