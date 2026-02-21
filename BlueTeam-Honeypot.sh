#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  Blue Team Honeypot & Trap Toolkit — Linux Edition
#  Summit Range Consulting | CTF / Blue Team Challenge
# ─────────────────────────────────────────────────────────────────

HONEYPOT_DIR="/opt/honeypot"
LOG_FILE="$HONEYPOT_DIR/logs/alerts.log"
TRIPWIRE_DIR="$HONEYPOT_DIR/tripwires"
SMB_SHARE_DIR="$HONEYPOT_DIR/fakeshare"
HONEYPOT_PORTS=(21 23 2222 8080 1433 3306)
SCAN_THRESHOLD=5
PID_FILE="$HONEYPOT_DIR/honeypot.pids"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

banner() {
    clear
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║   ▲  SUMMIT RANGE CONSULTING                        ║"
    echo "  ║      Blue Team Honeypot — Linux Edition             ║"
    echo "  ║      CTF / Blue Team Challenge                      ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_alert() {
    local level="$1"; local msg="$2"
    local ts=$(date '+%Y-%m-%d %H:%M:%S')
    mkdir -p "$(dirname $LOG_FILE)"
    echo "[$ts] [$level] $msg" | tee -a "$LOG_FILE"
}

# 1. PORT HONEYPOTS
deploy_port_honeypots() {
    echo -e "\n${YELLOW}  [+] Deploying Port Honeypots...${NC}"
    mkdir -p "$HONEYPOT_DIR/logs"
    
    for port in "${HONEYPOT_PORTS[@]}"; do
        # Check if port available
        if ss -tlnp | grep -q ":$port "; then
            echo -e "    ${YELLOW}⚠ Port $port already in use, skipping${NC}"
            continue
        fi
        
        # Start netcat listener in background
        (while true; do
            banner_text=""
            case $port in
                21)   banner_text="220 FTP Server Ready\r\n" ;;
                23)   banner_text="Welcome to Telnet\r\n" ;;
                2222) banner_text="SSH-2.0-OpenSSH_8.9\r\n" ;;
                8080) banner_text="HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n\r\n<html><body>Admin Panel</body></html>" ;;
                1433) banner_text="MSSQL Server 2019\r\n" ;;
                3306) banner_text="5.7.38-MySQL Community Server\r\n" ;;
            esac
            
            conn=$(echo -e "$banner_text" | nc -lvp $port -w 2 2>&1)
            if [ $? -eq 0 ]; then
                src_ip=$(echo "$conn" | grep -oP 'connect to \[\K[^\]]+' | head -1)
                [ -z "$src_ip" ] && src_ip="unknown"
                log_alert "TRAP" "HONEYPOT HIT Port:$port | Source: $src_ip"
            fi
        done) &
        echo $! >> "$PID_FILE"
        echo -e "    ${GREEN}✓ Listening on port $port (PID: $!)${NC}"
    done
    log_alert "INFO" "Port honeypots deployed: ${HONEYPOT_PORTS[*]}"
}

# 2. PORT SCAN DETECTOR (using iptables + logging)
deploy_scan_detector() {
    echo -e "\n${YELLOW}  [+] Deploying Port Scan Detector...${NC}"
    
    if command -v iptables &>/dev/null; then
        # Log new TCP SYN packets to uncommon ports
        iptables -I INPUT -p tcp --syn -m recent --name PORTSCAN --set 2>/dev/null
        iptables -I INPUT -p tcp --syn -m recent --name PORTSCAN --rcheck --seconds 60 --hitcount $SCAN_THRESHOLD \
                 -j LOG --log-prefix "[PORTSCAN] " --log-level 4 2>/dev/null
        echo -e "    ${GREEN}✓ iptables scan detection active (threshold: $SCAN_THRESHOLD ports/60s)${NC}"
        log_alert "INFO" "Port scan detector deployed via iptables"
        
        # Monitor kernel log for scan alerts
        (tail -f /var/log/kern.log 2>/dev/null || journalctl -kf 2>/dev/null) | \
        while read line; do
            if echo "$line" | grep -q "PORTSCAN"; then
                src=$(echo "$line" | grep -oP 'SRC=\K\S+')
                log_alert "CRITICAL" "PORT SCAN DETECTED | Source: $src | $line"
            fi
        done &
        echo $! >> "$PID_FILE"
    else
        echo -e "    ${YELLOW}⚠ iptables not available — using connection monitoring${NC}"
        # Fallback: monitor /proc/net/tcp
        (declare -A tracker
        while true; do
            while read line; do
                ip_hex=$(echo "$line" | awk '{print $3}' | cut -d: -f1)
                if [ -n "$ip_hex" ] && [ "$ip_hex" != "00000000" ]; then
                    ip=$(printf '%d.%d.%d.%d' 0x${ip_hex:6:2} 0x${ip_hex:4:2} 0x${ip_hex:2:2} 0x${ip_hex:0:2})
                    key="${ip}_$(date +%H%M)"
                    tracker[$key]=$((${tracker[$key]:-0}+1))
                    if [ ${tracker[$key]} -ge $SCAN_THRESHOLD ]; then
                        log_alert "CRITICAL" "PORT SCAN DETECTED | Source: $ip"
                        tracker[$key]=0
                    fi
                fi
            done < /proc/net/tcp
            sleep 2
        done) &
        echo $! >> "$PID_FILE"
    fi
    echo -e "    ${GREEN}✓ Scan detector active${NC}"
}

# 3. TRIPWIRE FILES
deploy_tripwires() {
    echo -e "\n${YELLOW}  [+] Deploying Tripwire Files...${NC}"
    mkdir -p "$TRIPWIRE_DIR"
    
    declare -A files=(
        ["passwords.txt"]="admin:Admin@2024!\nroot:R00t_P@ss\nsvcbackup:Backup#1234\nftpuser:FTP_P@ssw0rd"
        ["credentials.csv"]="service,username,password\nRDP,admin,Admin@2024!\nSSH,root,R00t_P@ss\nDB,sa,SQLServer2024"
        ["id_rsa"]="-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA[FAKE_KEY_DATA_DO_NOT_USE]\n-----END RSA PRIVATE KEY-----"
        ["database_backup.sql"]="-- DB Backup $(date +%Y-%m-%d)\n-- CONFIDENTIAL\nINSERT INTO users VALUES ('admin','\$2y\$10\$FAKEHASH','1');"
        [".env"]="DB_PASSWORD=Super$3cr3t2024\nAPI_KEY=sk-fake-key-honeypot\nAWS_SECRET=FAKESECRET123honeypot"
    )
    
    for filename in "${!files[@]}"; do
        filepath="$TRIPWIRE_DIR/$filename"
        printf "${files[$filename]}" > "$filepath"
        chmod 644 "$filepath"
        echo -e "    ${GREEN}✓ Tripwire planted: $filepath${NC}"
    done
    
    # Monitor access with inotifywait
    if command -v inotifywait &>/dev/null; then
        (inotifywait -m -r -e access,open "$TRIPWIRE_DIR" --format '%T %w%f %e' --timefmt '%Y-%m-%d %H:%M:%S' 2>/dev/null | \
        while read timestamp filepath event; do
            log_alert "TRAP" "TRIPWIRE TRIGGERED: $filepath ($event)"
        done) &
        echo $! >> "$PID_FILE"
        echo -e "    ${GREEN}✓ File access monitor active (inotifywait)${NC}"
    else
        echo -e "    ${YELLOW}⚠ inotifywait not found. Install with: apt install inotify-tools${NC}"
        # Fallback: periodic stat check
        (declare -A last_access
        for f in "$TRIPWIRE_DIR"/*; do
            last_access["$f"]=$(stat -c %X "$f" 2>/dev/null)
        done
        while true; do
            for f in "$TRIPWIRE_DIR"/*; do
                current=$(stat -c %X "$f" 2>/dev/null)
                if [ "${current}" != "${last_access[$f]}" ]; then
                    log_alert "TRAP" "TRIPWIRE TRIGGERED: $f accessed!"
                    last_access["$f"]=$current
                fi
            done
            sleep 3
        done) &
        echo $! >> "$PID_FILE"
    fi
    
    log_alert "INFO" "Tripwire files deployed in: $TRIPWIRE_DIR"
}

# 4. FAKE SMB SHARE
deploy_smb_honeypot() {
    echo -e "\n${YELLOW}  [+] Deploying SMB Honeypot Share...${NC}"
    mkdir -p "$SMB_SHARE_DIR"
    
    # Plant fake files
    echo -e "admin:Admin@2024!\nhr_manager:HR#Pass2024\nsa:SQLServer2024" > "$SMB_SHARE_DIR/Employee_Passwords_CONFIDENTIAL.txt"
    echo -e "# OpenVPN Config\nclient\nremote vpn.internal.corp 1194\n" > "$SMB_SHARE_DIR/VPN_Config_AllUsers.ovpn"
    echo -e "Username,Password,Department\nadmin,Admin@2024!,IT\nhr_admin,HR#Pass,HR" > "$SMB_SHARE_DIR/AD_Export_CONFIDENTIAL.csv"
    
    if command -v samba &>/dev/null || command -v smbd &>/dev/null; then
        cat > /tmp/honeypot_smb.conf << EOF
[global]
    workgroup = WORKGROUP
    server string = File Server
    log level = 2
    log file = $HONEYPOT_DIR/logs/smb.log

[BACKUP\$]
    path = $SMB_SHARE_DIR
    comment = Backup Storage
    browseable = yes
    read only = no
    guest ok = yes
EOF
        smbd -D --configfile=/tmp/honeypot_smb.conf 2>/dev/null && \
            echo -e "    ${GREEN}✓ SMB honeypot share active: //localhost/BACKUP\$${NC}" || \
            echo -e "    ${YELLOW}⚠ SMB server start failed — files planted at $SMB_SHARE_DIR${NC}"
        
        # Monitor smb log
        (tail -f "$HONEYPOT_DIR/logs/smb.log" 2>/dev/null | while read line; do
            if echo "$line" | grep -qiE "connect|open|read"; then
                log_alert "CRITICAL" "SMB HONEYPOT ACCESSED: $line"
            fi
        done) &
        echo $! >> "$PID_FILE"
    else
        echo -e "    ${YELLOW}⚠ Samba not installed — fake files planted at: $SMB_SHARE_DIR${NC}"
        echo -e "    ${YELLOW}  Install with: apt install samba${NC}"
    fi
    log_alert "INFO" "SMB honeypot deployed"
}

# 5. FAKE CREDENTIALS IN LOGS
plant_fake_credentials() {
    echo -e "\n${YELLOW}  [+] Planting Fake Credentials in Logs...${NC}"
    
    declare -A creds=(
        ["RDP/admin"]="Admin@2024!"
        ["SSH/root"]="R00t_P@ss"
        ["MSSQL/sa"]="SQLServer2024"
        ["FTP/ftpuser"]="FTP_P@ssw0rd"
        ["HTTP/admin"]="WebAdmin#123"
    )
    
    # Plant in auth.log style
    FAKE_LOG="/var/log/auth_service.log"
    for service_user in "${!creds[@]}"; do
        service=$(echo $service_user | cut -d/ -f1)
        user=$(echo $service_user | cut -d/ -f2)
        pass="${creds[$service_user]}"
        ts=$(date '+%b %d %H:%M:%S')
        echo "$ts $(hostname) sshd[$$]: Accepted password for $user from 192.168.1.$(shuf -i 10-200 -n 1) port $(shuf -i 30000-60000 -n 1) $service" >> "$FAKE_LOG"
        echo -e "    ${GREEN}✓ Fake cred planted: $service / $user${NC}"
    done
    
    # Also write to a .bash_history style honeypot
    cat > "$HONEYPOT_DIR/.bash_history_backup" << 'EOF'
ssh admin@192.168.1.50 -p 2222
mysql -u sa -pSQLServer2024 -h db.internal
ftp ftpuser@192.168.1.30
# password: FTP_P@ssw0rd
smbclient //fileserver/BACKUP$ -U admin%Admin@2024!
EOF
    echo -e "    ${GREEN}✓ Fake bash history planted${NC}"
    log_alert "INFO" "Fake credentials planted in logs"
}

# LIVE MONITOR
monitor() {
    banner
    echo -e "  ${CYAN}[MONITOR] Live Alert Dashboard — Ctrl+C to exit${NC}"
    echo -e "  Log: $LOG_FILE"
    echo "  ─────────────────────────────────────────────────────"
    
    if [ ! -f "$LOG_FILE" ]; then
        echo -e "  ${YELLOW}Waiting for alerts...${NC}"
    fi
    
    tail -f "$LOG_FILE" 2>/dev/null | while read line; do
        if echo "$line" | grep -q "CRITICAL"; then
            echo -e "  ${RED}$line${NC}"
        elif echo "$line" | grep -q "TRAP"; then
            echo -e "  ${MAGENTA}$line${NC}"
        elif echo "$line" | grep -q "WARNING"; then
            echo -e "  ${YELLOW}$line${NC}"
        else
            echo -e "  ${GREEN}$line${NC}"
        fi
    done
}

# STATUS
status() {
    banner
    echo -e "  ${CYAN}[STATUS] Honeypot Trap Status${NC}"
    echo "  ─────────────────────────────────────────────────────"
    
    echo -e "\n  ${YELLOW}Port Honeypots:${NC}"
    for port in "${HONEYPOT_PORTS[@]}"; do
        if ss -tlnp 2>/dev/null | grep -q ":$port " || netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            echo -e "    ${GREEN}✓ Port $port : ACTIVE${NC}"
        else
            echo -e "    ${RED}✗ Port $port : INACTIVE${NC}"
        fi
    done
    
    echo -e "\n  ${YELLOW}Tripwire Files:${NC}"
    for f in passwords.txt credentials.csv id_rsa database_backup.sql .env; do
        path="$TRIPWIRE_DIR/$f"
        [ -f "$path" ] && echo -e "    ${GREEN}✓ IN PLACE: $f${NC}" || echo -e "    ${RED}✗ MISSING: $f${NC}"
    done
    
    echo -e "\n  ${YELLOW}Recent Alerts (last 10):${NC}"
    if [ -f "$LOG_FILE" ]; then
        tail -10 "$LOG_FILE" | while read line; do
            echo -e "    $line"
        done
        echo -e "\n  ${YELLOW}Alert Summary:${NC}"
        total=$(wc -l < "$LOG_FILE")
        critical=$(grep -c "CRITICAL" "$LOG_FILE" 2>/dev/null || echo 0)
        traps=$(grep -c "TRAP" "$LOG_FILE" 2>/dev/null || echo 0)
        scans=$(grep -c "PORT SCAN" "$LOG_FILE" 2>/dev/null || echo 0)
        echo -e "    Total: $total | Critical: ${RED}$critical${NC} | Traps: ${MAGENTA}$traps${NC} | Scans: ${YELLOW}$scans${NC}"
    else
        echo -e "    ${YELLOW}No alerts yet.${NC}"
    fi
}

# CLEANUP
cleanup() {
    echo -e "\n${YELLOW}  [CLEANUP] Removing all honeypot traps...${NC}"
    
    # Kill all honeypot processes
    if [ -f "$PID_FILE" ]; then
        while read pid; do
            kill $pid 2>/dev/null && echo -e "    ${GREEN}✓ Killed PID $pid${NC}"
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    
    # Remove iptables rules
    iptables -D INPUT -p tcp --syn -m recent --name PORTSCAN --set 2>/dev/null
    iptables -D INPUT -p tcp --syn -m recent --name PORTSCAN --rcheck --seconds 60 --hitcount $SCAN_THRESHOLD \
             -j LOG --log-prefix "[PORTSCAN] " --log-level 4 2>/dev/null
    
    # Remove honeypot directory
    rm -rf "$HONEYPOT_DIR"
    rm -f /var/log/auth_service.log /tmp/honeypot_smb.conf
    
    echo -e "\n  ${GREEN}[✓] All traps removed.${NC}"
}

# DEPLOY ALL
deploy_all() {
    banner
    echo -e "  ${YELLOW}[*] Deploying ALL Blue Team Traps...${NC}\n"
    mkdir -p "$HONEYPOT_DIR/logs"
    > "$PID_FILE"
    
    log_alert "INFO" "=== BLUE TEAM HONEYPOT DEPLOYMENT STARTED ==="
    
    deploy_port_honeypots
    deploy_scan_detector
    deploy_tripwires
    deploy_smb_honeypot
    plant_fake_credentials
    
    echo -e "\n${GREEN}  ╔══════════════════════════════════════════════╗"
    echo    "  ║  ✓ ALL TRAPS DEPLOYED SUCCESSFULLY           ║"
    echo -e "  ╚══════════════════════════════════════════════╝${NC}\n"
    echo -e "  Honeypot Ports : ${HONEYPOT_PORTS[*]}"
    echo -e "  Tripwires      : $TRIPWIRE_DIR"
    echo -e "  Alert Log      : $LOG_FILE"
    echo -e "\n  Run: ./BlueTeam-Honeypot.sh monitor   — watch live alerts"
    echo -e "  Run: ./BlueTeam-Honeypot.sh status    — check trap status\n"
    log_alert "INFO" "=== ALL TRAPS ACTIVE — READY FOR RED TEAM ==="
}

# ENTRY POINT
case "${1:-menu}" in
    deploy)  deploy_all ;;
    monitor) monitor ;;
    status)  status ;;
    cleanup) cleanup ;;
    menu|*)
        banner
        echo -e "  ${CYAN}Usage:${NC}"
        echo "    sudo ./BlueTeam-Honeypot.sh deploy   — Deploy all traps"
        echo "    sudo ./BlueTeam-Honeypot.sh monitor  — Live alert dashboard"
        echo "    sudo ./BlueTeam-Honeypot.sh status   — Check trap status"
        echo "    sudo ./BlueTeam-Honeypot.sh cleanup  — Remove all traps"
        echo ""
        ;;
esac
