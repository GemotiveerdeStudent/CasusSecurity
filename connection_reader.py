# connection_reader.py
import psutil

def get_active_remote_ips():
    results = []
    connections = psutil.net_connections(kind='inet')

    for conn in connections:
        if conn.status == 'ESTABLISHED' and conn.raddr:
            ip = conn.raddr.ip
            pid = conn.pid
            try:
                proc = psutil.Process(pid)
                process_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "Onbekend"

            if not ip.startswith("127.") and not ip.startswith("::1"):
                results.append((ip, process_name))

    return results
