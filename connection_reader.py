import psutil
import socket

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

            results.append((ip, hostname, port, process_name, "Uitgaand"))
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
            results.append((ip, "-", port, process_name, "Inkomend"))
    return results
