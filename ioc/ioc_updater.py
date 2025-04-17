# ioc_updater.py
import requests
import csv
from datetime import datetime

IOC_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
IOC_LOCAL_FILE = "malicious_ips.csv"

def update_ioc_list_from_feodo():
    try:
        response = requests.get(IOC_FEED_URL, timeout=10)
        response.raise_for_status()

        lines = response.text.splitlines()
        updated = 0

        with open(IOC_LOCAL_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "type", "source", "date", "description"])
            for line in lines:
                if line.startswith("#") or not line.strip():
                    continue
                writer.writerow([line.strip(), "C2", "Feodo Tracker", datetime.utcnow().date(), "Geautomatiseerde IOC-feed"])
                updated += 1

        return True, f"✅ IOC-lijst bijgewerkt ({updated} IP’s toegevoegd)"
    
    except Exception as e:
        return False, f"❌ Fout bij bijwerken IOC-lijst: {e}"
