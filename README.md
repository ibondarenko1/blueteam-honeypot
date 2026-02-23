...........# 🛡️ Blue Team Honeypot & Trap Toolkit

**Summit Range Consulting** — CTF / Blue Team Challenge Edition

> Deploy honeypot traps, detect port scans, and catch Red Team attackers in real-time.

---

## ⚡ Quick Deploy

### Windows (PowerShell — Run as Admin)
```powershell
.\BlueTeam-Honeypot.ps1 -Action Deploy    # Deploy all traps
.\BlueTeam-Honeypot.ps1 -Action Monitor   # Live alert dashboard
.\BlueTeam-Honeypot.ps1 -Action Status    # Check trap status
.\BlueTeam-Honeypot.ps1 -Action Cleanup   # Remove everything
```

### Linux (Run as root)
```bash
chmod +x BlueTeam-Honeypot.sh
sudo ./BlueTeam-Honeypot.sh deploy    # Deploy all traps
sudo ./BlueTeam-Honeypot.sh monitor   # Live alert dashboard
sudo ./BlueTeam-Honeypot.sh status    # Check trap status
sudo ./BlueTeam-Honeypot.sh cleanup   # Remove everything
```

---

## 🪤 Traps Deployed

| Trap | Description | Alert Level |
|------|-------------|-------------|
| **Port Honeypots** | Fake listeners on ports 21, 23, 2222, 8080, 1433, 3306 | TRAP |
| **Port Scan Detector** | Alerts when 5+ ports scanned in 60s | CRITICAL |
| **Tripwire Files** | `passwords.txt`, `id_rsa`, `database.sql`, `.env` | TRAP |
| **SMB Honeypot** | Fake `BACKUP$` share with juicy fake files | CRITICAL |
| **Fake Credentials** | Planted in event logs and auth logs | — |

---

## 📊 Alert Levels

- 🔴 **CRITICAL** — Port scan detected, SMB accessed
- 🟣 **TRAP** — Honeypot port hit, tripwire file accessed
- 🟡 **WARNING** — Suspicious activity
- 🟢 **INFO** — Status messages

---

## 🏆 CTF Blue Team Strategy

1. **Deploy first** — run before the challenge starts
2. **Monitor live** — keep monitor running in a separate terminal
3. **Watch for scans** — first thing Red Team does is nmap
4. **SMB is bait** — Red Team loves open shares with "sensitive" files
5. **Tripwires** — plant in directories Red Team might explore

---

## 📋 Prerequisites

### Windows
- PowerShell 5.1+
- Run as Administrator
- Windows Firewall rules may need adjustment

### Linux
```bash
apt install netcat inotify-tools samba   # Ubuntu/Debian
yum install ncat inotify-tools samba     # RHEL/CentOS
```

---

*Summit Range Consulting | WOSB Certified | Built for Blue Team CTF Defense*
