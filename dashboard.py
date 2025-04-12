import tkinter as tk
import threading
from tkinter import ttk
from geo_lookup import get_geolocation
from ioc_checker import IOCChecker
from connection_reader import get_incoming_connections, get_outgoing_connections
from firewall_log_parser import parse_firewall_log
from country_utils import get_country_iso_code


ioc = IOCChecker()

# Analyse van IP-verkeer (inkomend/uitgaand)
def analyse_ips(ip_process_list, tree, label):
    for row in tree.get_children():
        tree.delete(row)

    if not ip_process_list:
        label.config(text="Geen verbindingen gevonden.")
        return

    land_teller = {}

    for ip, hostname, port, process_name, direction in ip_process_list:
        try:
            geo = get_geolocation(ip)
            country = geo.get('country', 'Onbekend')
            city = geo.get('city', '')
            verdacht = "JA" if ioc.is_malicious(ip) else "NEE"

            tree.insert("", "end", values=(ip, hostname, port, process_name, country, city, verdacht, direction))
            land_teller[country] = land_teller.get(country, 0) + 1
        except Exception as e:
            print(f"[analyse_ips] Fout bij IP {ip}: {e}")

    stats = "\n".join(f"{land}: {count} verbinding(en)" for land, count in land_teller.items())
    label.config(text="🌍 Verbindingshits per land:\n" + stats)

def analyse_outgoing():
    analyse_ips(get_outgoing_connections(), tree_out, stats_label_out)

def analyse_incoming():
    analyse_ips(get_incoming_connections(), tree_in, stats_label_in)

def analyse_firewall_log():
    for row in tree_fw.get_children():
        tree_fw.delete(row)

    data = parse_firewall_log()
    if not data:
        stats_label_fw.config(text="Geen firewall logs gevonden.")
        return

    land_teller = {}

    for ip, hits in data.items():
        try:
            geo = get_geolocation(ip)
            raw_country = geo.get("country", "Onbekend")
            country = get_country_iso_code(raw_country)
            city = geo.get("city", "")
            verdacht = "JA" if ioc.is_malicious(ip) else "NEE"

            tree_fw.insert("", "end", values=(ip, hits, country, city, verdacht))
            land_teller[country] = land_teller.get(country, 0) + hits
        except Exception as e:
            print(f"[firewall_log] Fout bij IP {ip}: {e}")

    stats = "\n".join(f"{land}: {count} verbinding(en)" for land, count in land_teller.items())
    stats_label_fw.config(text="🌍 Verbindingshits per land:\n" + stats)

# Periodieke refresh (elke 60 sec)
def refresh_tabs():
    try:
        analyse_outgoing()
    except Exception as e:
        print("[refresh] analyse_outgoing() error:", e)

    try:
        analyse_incoming()
    except Exception as e:
        print("[refresh] analyse_incoming() error:", e)

    try:
        analyse_firewall_log()
    except Exception as e:
        print("[refresh] analyse_firewall_log() error:", e)

    root.after(60000, refresh_tabs)

# GUI Setup
root = tk.Tk()
root.title("Digitale Diefstal – IP Analyse")
root.geometry("1000x600")

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

# Tabs
tab_outgoing = ttk.Frame(notebook)
tab_incoming = ttk.Frame(notebook)
tab_firewall = ttk.Frame(notebook)
notebook.add(tab_outgoing, text="Uitgaand verkeer")
notebook.add(tab_incoming, text="Inkomend verkeer")
notebook.add(tab_firewall, text="Firewall Log")

# Outgoing
columns = ("IP", "Hostnaam", "Poort", "Proces", "Land", "Stad", "IOC", "Richting")
tree_out = ttk.Treeview(tab_outgoing, columns=columns, show="headings")
for col in columns:
    tree_out.heading(col, text=col)
tree_out.pack(fill=tk.BOTH, expand=True)
stats_label_out = tk.Label(tab_outgoing, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label_out.pack(fill=tk.X, padx=10, pady=10)

# Incoming
tree_in = ttk.Treeview(tab_incoming, columns=columns, show="headings")
for col in columns:
    tree_in.heading(col, text=col)
tree_in.pack(fill=tk.BOTH, expand=True)
stats_label_in = tk.Label(tab_incoming, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label_in.pack(fill=tk.X, padx=10, pady=10)

# Firewall Log
columns_fw = ("IP", "Hits", "Land", "Stad", "IOC")
tree_fw = ttk.Treeview(tab_firewall, columns=columns_fw, show="headings")
for col in columns_fw:
    tree_fw.heading(col, text=col)
tree_fw.pack(fill=tk.BOTH, expand=True)
stats_label_fw = tk.Label(tab_firewall, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label_fw.pack(fill=tk.X, padx=10, pady=10)

# Initieel laden in aparte thread
def initial_load():
    try:
        analyse_outgoing()
        analyse_incoming()
        analyse_firewall_log()
        refresh_tabs()
    except Exception as e:
        print("[init] Error:", e)

threading.Thread(target=initial_load, daemon=True).start()

root.mainloop()
