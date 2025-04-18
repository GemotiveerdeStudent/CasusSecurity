import socket
import psutil
import re
import os
import subprocess

FIREWALL_LOG_PATH = r"C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"

IP_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

def parse_firewall_log(path=FIREWALL_LOG_PATH):
    ip_data = {}  # IP -> {'hits': int, 'bytes': int, 'protocol': str, 'port': int, 'action': str}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if line.startswith("#") or not line.strip():
                    continue  # Skip header or empty lines

                parts = line.strip().split()
                if len(parts) < 10:
                    continue

                try:
                    action = parts[2]  # ALLOW or DROP
                    protocol = parts[3]
                    src_ip = parts[4]
                    dst_ip = parts[5]
                    dst_port = parts[7]
                    size = int(parts[9]) if parts[9].isdigit() else 0
                except (IndexError, ValueError):
                    continue

                if not IP_REGEX.match(dst_ip):
                    continue

                key = (dst_ip, protocol, dst_port, action)
                if key not in ip_data:
                    ip_data[key] = {"hits": 1, "bytes": size}
                else:
                    ip_data[key]["hits"] += 1
                    ip_data[key]["bytes"] += size

        return [(ip, data["hits"], proto, port, action, data["bytes"]) for (ip, proto, port, action), data in ip_data.items()]

    except Exception as e:
        print(f"[Fout] Kan firewall log niet lezen: {e}")
        return []

def is_firewall_logging_enabled():
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "currentprofile"],
            capture_output=True, text=True, check=True
        )
        return "LogAllowedConnections                 Enable" in result.stdout
    except Exception as e:
        print("[firewall check] Fout:", e)
        return False

def enable_firewall_logging():
    try:
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "logging", "allowedconnections", "enable"],
            check=True
        )
        subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "logging", "droppedconnections", "enable"],
            check=True
        )
        print("✅ Firewall logging is ingeschakeld.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[enable_logging] Fout bij inschakelen logging: {e}")
        return False

def get_outgoing_connections():
    results = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "ESTABLISHED" and conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                process_name = proc.name()
            except Exception:
                process_name = "Onbekend"

            ip = conn.raddr.ip
            port = conn.raddr.port
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Onbekend"

            results.append((ip, hostname, port, process_name))
    return results
