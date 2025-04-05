# connection_reader.py
import psutil

def get_active_remote_ips():
    remote_ips = set()
    connections = psutil.net_connections(kind='inet')

    for conn in connections:
        # Alleen actieve verbindingen met remote adres
        if conn.status == 'ESTABLISHED' and conn.raddr:
            ip = conn.raddr.ip
            if not ip.startswith("127.") and not ip.startswith("::1"):  # Geen localhost
                remote_ips.add(ip)

    return list(remote_ips)
