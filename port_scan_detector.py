from scapy.all import sniff, IP, TCP, get_if_list, AsyncSniffer
from collections import defaultdict
import time
import subprocess
import json
import threading

# Configuration
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 5  # seconds
BLOCK_DURATION = 5 * 60  # auto unblock after 5 mins
LOG_FILE = "log.txt"
JSON_FILE = "alerts.json"

# Track scans and blocks
scan_tracker = defaultdict(lambda: {'ports': set(), 'last_seen': time.time()})
blocked_ips = {}

# --- Helper: Desktop Notification ---
def show_desktop_notification(title, message):
    try:
        subprocess.run(["notify-send", title, message])
    except Exception as e:
        print(f"[ERROR] Notification failed: {e}")

# --- Helper: Log Alert ---
def log_alert(message, data=None):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    entry = f"[{timestamp}] {message}"
    print(entry)

    # Desktop popup
    show_desktop_notification("Attack Alert", message)

    # Save to log file
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

    # Save to JSON file
    if data:
        with open(JSON_FILE, "a") as jf:
            json.dump(data, jf)
            jf.write("\n")

# --- Detect scan type based on TCP flags ---
def detect_scan_type(flags):
    if flags == 0:
        return "NULL Scan"
    elif flags == 0x01:
        return "FIN Scan"
    elif flags == 0x29:
        return "XMAS Scan"
    elif flags == 0x02:
        return "SYN Scan"
    return None

# --- Deep Packet Inspection ---
def inspect_packet_payload(packet):
    try:
        if packet.haslayer(TCP) and hasattr(packet[TCP], "payload"):
            raw_payload = bytes(packet[TCP].payload)

            # HTTP keyword detection
            if b"login" in raw_payload or b"password" in raw_payload or b"/admin" in raw_payload:
                log_alert(f"[DPI] Suspicious HTTP keyword from {packet[IP].src}", {
                    "ip": packet[IP].src,
                    "type": "http_inspection",
                    "content": raw_payload[:100].decode('utf-8', errors='ignore')
                })

            # FTP detection
            if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                if b"USER" in raw_payload or b"PASS" in raw_payload:
                    log_alert(f"[DPI] FTP credentials leak from {packet[IP].src}", {
                        "ip": packet[IP].src,
                        "type": "ftp_auth",
                        "content": raw_payload.decode('utf-8', errors='ignore')
                    })

            # Telnet detection
            if packet[TCP].dport == 23 or packet[TCP].sport == 23:
                log_alert(f"[DPI] Telnet usage from {packet[IP].src}", {
                    "ip": packet[IP].src,
                    "type": "telnet",
                    "content": raw_payload[:100].decode('utf-8', errors='ignore')
                })
    except Exception as e:
        log_alert(f"[ERROR] DPI failed: {e}")

# --- Unblock IP after timeout ---
def unblock_ip(ip):
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        log_alert(f"[ACTION] Unblocked IP {ip}")
        blocked_ips.pop(ip, None)
    except subprocess.CalledProcessError as e:
        log_alert(f"[ERROR] Failed to unblock IP {ip}: {e.stderr.decode()}")

# --- Block IP and set unblock timer ---
def block_ip(ip):
    if ip not in blocked_ips:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            log_alert(f"[ACTION] Blocked IP {ip}")
            blocked_ips[ip] = time.time()

            # Start unblock timer
            timer = threading.Timer(BLOCK_DURATION, unblock_ip, [ip])
            timer.start()
        except subprocess.CalledProcessError as e:
            log_alert(f"[ERROR] Failed to block IP {ip}: {e.stderr.decode()}")

# --- Packet Callback ---
def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        scan_type = detect_scan_type(flags)

        if scan_type:
            now = time.time()
            scan_tracker[src_ip]['ports'].add(dport)
            scan_tracker[src_ip]['last_seen'] = now

            if len(scan_tracker[src_ip]['ports']) >= PORT_SCAN_THRESHOLD:
                ports_list = list(scan_tracker[src_ip]['ports'])
                log_alert(
                    f"{scan_type} detected from {src_ip} on ports: {ports_list}",
                    {
                        "ip": src_ip,
                        "scan_type": scan_type,
                        "ports": ports_list,
                        "timestamp": now
                    }
                )
                block_ip(src_ip)
                scan_tracker[src_ip]['ports'].clear()

        # Deep Packet Inspection
        inspect_packet_payload(packet)

# --- Interface Setup ---
interfaces = [iface for iface in get_if_list() if iface != 'any']
print("[*] Monitoring interfaces:", interfaces)

# Start sniffers
sniffers = []
for iface in interfaces:
    try:
        sniffer = AsyncSniffer(filter="tcp", prn=detect_port_scan, store=0, iface=iface)
        sniffer.start()
        sniffers.append(sniffer)
    except Exception as e:
        print(f"[ERROR] Could not start sniffer on {iface}: {e}")

# --- Run until Ctrl+C ---
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Stopping sniffers...")
    for s in sniffers:
        s.stop()
    print("[*] Exited cleanly.")
