import csv
import sys
import re
import socket
import requests

IOC_LIST_PATH = "iocs.csv"

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(10 * 1024 * 1024)

class IOCChecker:
    def __init__(self, csv_file=IOC_LIST_PATH):
        self.malicious_ips = set()
        self.load(csv_file)

    def load(self, csv_file):
        try:
            with open(csv_file, newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row:
                        self.malicious_ips.add(row[0].strip())
        except FileNotFoundError:
            print("[IOCChecker] Geen IOC-bestand gevonden.")
        except Exception as e:
            print(f"[IOCChecker] Fout bij laden IOC's: {e}")

    def is_malicious(self, ip):
        return ip in self.malicious_ips

IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def extract_ip(line):
    line = line.strip()
    if IP_REGEX.match(line):
        return line
    if line.startswith("http"):
        try:
            hostname = re.findall(r"https?://([^/]+)", line)[0]
            ip = socket.gethostbyname(hostname)
            return ip
        except:
            return None
    return None

def _download_ip_feed(url, source_name):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return False, f"❌ Fout bij ophalen {source_name} (status {response.status_code})"

        ioc_set = set()
        for line in response.text.splitlines():
            ip = extract_ip(line)
            if ip:
                ioc_set.add(ip)

        with open(IOC_LIST_PATH, "a", newline='') as f:
            writer = csv.writer(f)
            for ip in ioc_set:
                writer.writerow([ip])

        return True, f"✔️ {len(ioc_set)} IOCs toegevoegd vanuit {source_name}"
    except Exception as e:
        return False, f"❌ Fout bij ophalen {source_name}: {e}"

def clear_ioc_list():
    open(IOC_LIST_PATH, "w").close()

def update_ioc_list_from_feodo():
    return _download_ip_feed("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "Feodo Tracker")

def update_ioc_list_from_threatfox():
    return _download_ip_feed(
        "https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/main/ips.txt",
        "ThreatFox (GitHub mirror)"
    )

def update_ioc_list_from_openphish():
    return _download_ip_feed("https://openphish.com/feed.txt", "OpenPhish")
