# ioc_checker.py
import csv

class IOCChecker:
    def __init__(self, ioc_file="malicious_ips.csv"):
        self.iocs = set()
        try:
            with open(ioc_file, newline='') as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    ip = row[0].strip()
                    self.iocs.add(ip)
        except FileNotFoundError:
            print(f"[!] IOC-bestand niet gevonden: {ioc_file}")

    def is_malicious(self, ip):
        return ip in self.iocs