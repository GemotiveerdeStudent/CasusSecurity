# ioc_checker.py
import csv

class IOCChecker:
    def __init__(self, csv_file="malicious_ips.csv"):
        self.malicious_ips = set()
        self.load(csv_file)

    def load(self, csv_file):
        try:
            with open(csv_file, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.malicious_ips.add(row["ip"].strip())
        except FileNotFoundError:
            print("[IOCChecker] Geen IOC-bestand gevonden.")
        except Exception as e:
            print(f"[IOCChecker] Fout bij laden IOC's: {e}")

    def is_malicious(self, ip):
        return ip in self.malicious_ips
