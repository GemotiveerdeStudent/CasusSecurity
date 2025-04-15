# linux_ssh_analyzer.py

import re
from geo_lookup import get_geolocation
from ioc_checker import IOCChecker
from country_utils import get_country_iso_code

LOG_PATH = "/var/log/auth.log"

def parse_ssh_log():
    ioc = IOCChecker()
    entries = []

    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "Failed password" in line or "Accepted password" in line:
                    result = extract_ssh_entry(line)
                    if result:
                        ip, user, status = result
                        geo = get_geolocation(ip)
                        country = get_country_iso_code(geo.get("country", "Onbekend"))
                        city = geo.get("city", "")
                        ioc_status = "JA" if ioc.is_malicious(ip) else "NEE"
                        entries.append((ip, user, status, country, city, ioc_status))
    except FileNotFoundError:
        print(f"❌ Bestand {LOG_PATH} niet gevonden.")
    return entries

def extract_ssh_entry(line):
    match = re.search(r"(Failed|Accepted) password for (invalid user )?(\w+) from ([\d.]+)", line)
    if match:
        status = match.group(1)
        user = match.group(3)
        ip = match.group(4)
        return ip, user, status
    return None
