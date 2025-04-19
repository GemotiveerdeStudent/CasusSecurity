import psutil
import socket
from ipaddress import ip_address


def is_public_ip(ip):
    try:
        return ip_address(ip).is_global
    except ValueError:
        return False


def get_outgoing_connections():
    results = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "ESTABLISHED" and conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                process_name = proc.name()
            except:
                process_name = "Onbekend"

            ip = conn.raddr.ip
            port = conn.raddr.port
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Onbekend"

            results.append((ip, hostname, port, process_name))
    return results


def get_incoming_connections():
    results = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status in ("LISTEN", "ESTABLISHED") and not conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                process_name = proc.name()
            except:
                process_name = "Onbekend"

            ip = conn.laddr.ip
            port = conn.laddr.port

            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Onbekend"

            if is_public_ip(ip):
                results.append((ip, hostname, port, process_name))
            else:
                results.append((ip, "Lokaal", port, process_name))
    return results

def get_outgoing_connections_with_bytes():
    results = []

    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "ESTABLISHED" and conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                process_name = proc.name()
                io_counters = proc.io_counters()
                bytes_sent = io_counters.bytes_sent if io_counters else 0
            except Exception:
                process_name = "Onbekend"
                bytes_sent = 0

            ip = conn.raddr.ip
            port = conn.raddr.port
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Onbekend"

            results.append((ip, hostname, port, process_name, bytes_sent))
    
    return results