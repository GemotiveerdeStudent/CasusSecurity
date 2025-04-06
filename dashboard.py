# run application from environment with the following 2 commando's:
# .venv\Scripts\activate
# python dashboard.py


# dashboard.py
import tkinter as tk
import threading
import time
from tkinter import ttk
from geo_lookup import get_geolocation
from ioc_checker import IOCChecker
from connection_reader import get_active_remote_ips



ip_process_list = get_active_remote_ips()


ioc = IOCChecker()

def analyse_ips():
    for row in tree.get_children():
        tree.delete(row)

    test_ips = get_active_remote_ips()
    land_teller = {}

    for ip, process_name in ip_process_list:
        geo = get_geolocation(ip)
        country = geo.get('country', 'Onbekend')
        city = geo.get('city', '')
        verdacht = "JA" if ioc.is_malicious(ip) else "NEE"

        tree.insert("", "end", values=(ip, process_name, country, city, verdacht))

        land_teller[country] = land_teller.get(country, 0) + 1


        # Zet resultaat in het label
        stats = "\n".join(f"{land}: {count} verbinding(en)" for land, count in land_teller.items())
        stats_label.config(text="🌍 Verbindingshits per land:\n" + stats)


def auto_refresh(): 
    while True:
        time.sleep(60)  # wacht 60 seconden
        analyse_ips()   # herlaad data


# GUI setup
root = tk.Tk()
root.title("Digitale Diefstal – IP Analyse")
root.geometry("900x500")

tree = ttk.Treeview(root, columns=("IP", "Proces", "Land", "Stad", "IOC"), show="headings")
tree.heading("IP", text="IP")
tree.heading("Proces", text="Proces")
tree.heading("Land", text="Land")
tree.heading("Stad", text="Stad")
tree.heading("IOC", text="Verdacht")
tree.pack(fill=tk.BOTH, expand=True)

# Label met hits per land
stats_label = tk.Label(root, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label.pack(fill=tk.X, padx=10, pady=10)


btn = ttk.Button(root, text="Analyse starten", command=analyse_ips)
btn.pack(pady=10)

threading.Thread(target=auto_refresh, daemon=True).start()
root.mainloop()