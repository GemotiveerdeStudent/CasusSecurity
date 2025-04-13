import tkinter as tk
import threading
import ctypes
import sys
import os
from tkinter import ttk
from functools import lru_cache
from geo_lookup import get_geolocation
from ioc_checker import IOCChecker
from connection_reader import get_incoming_connections, get_outgoing_connections
from firewall_log_parser import parse_firewall_log, is_firewall_logging_enabled, enable_firewall_logging
from country_utils import get_country_iso_code

ioc = IOCChecker()

stop_requested = False

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def restart_as_admin():
    if not is_admin():
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])

        # Start nieuwe admin-instantie
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )

        # Stop deze GUI volledig
        root.quit()
        root.destroy()
        sys.exit()


@lru_cache(maxsize=1000)
def cached_geolocation(ip):
    return get_geolocation(ip)

def analyse_ips(ip_process_list, tree, label, progress=None):
    for row in tree.get_children():
        tree.delete(row)

    if not ip_process_list:
        label.config(text="Geen verbindingen gevonden.")
        if progress: progress.stop()
        return

    land_teller = {}

    for ip, hostname, port, process_name in ip_process_list:
        if stop_requested:
            if progress: progress.stop()
            return

        try:
            geo = cached_geolocation(ip)
            raw_country = geo.get('country', 'Onbekend')
            country = get_country_iso_code(raw_country)
            city = geo.get('city', '')
            verdacht = "JA" if ioc.is_malicious(ip) else "NEE"

            tree.insert("", "end", values=(ip, hostname, port, process_name, country, city, verdacht))
            land_teller[country] = land_teller.get(country, 0) + 1

        except Exception as e:
            print(f"[analyse_ips] Fout bij IP {ip}: {e}")

    stats = "\n".join(f"{land}: {count} verbinding(en)" for land, count in land_teller.items())
    label.config(text="🌍 Verbindingshits per land:\n" + stats)
    if progress: progress.stop()

def analyse_outgoing():
    progress_out.start()
    analyse_ips(get_outgoing_connections(), tree_out, stats_label_out, progress_out)

def analyse_incoming():
    analyse_ips(get_incoming_connections(), tree_in, stats_label_in)

def analyse_firewall_log():
    from firewall_log_parser import parse_firewall_log, is_firewall_logging_enabled

    # Eerst: check of firewall logging actief is
    if not is_firewall_logging_enabled():
        firewall_status_label.config(
            text="⚠️ Firewall logging staat UIT.",
            fg="orange"
        )
        # Laat de inschakelknop alleen zien als gebruiker admin is
        if is_admin():
            enable_logging_button.pack(pady=5)
            restart_admin_button.pack_forget()
        else:
            enable_logging_button.pack_forget()
            restart_admin_button.pack(pady=5)
        return

    # Logging staat aan, toon dit
    firewall_status_label.config(
        text="✅ Firewall logging is actief.",
        fg="green"
    )
    enable_logging_button.pack_forget()

    # Check of gebruiker géén admin is, maar log wel actief is
    if not is_admin():
        restart_admin_button.pack(pady=5)
    else:
        restart_admin_button.pack_forget()

    # Probeer te lezen
    for row in tree_fw.get_children():
        tree_fw.delete(row)

    try:
        data = parse_firewall_log()
        if not data:
            stats_label_fw.config(text="Geen firewall logs gevonden.")
            return

        land_teller = {}
        for ip, hits, protocol, port, action in data:
            if stop_requested:
                return
            geo = cached_geolocation(ip)
            raw_country = geo.get("country", "Onbekend")
            country = get_country_iso_code(raw_country)
            city = geo.get("city", "")
            verdacht = "JA" if ioc.is_malicious(ip) else "NEE"
            tree_fw.insert("", "end", values=(ip, hits, protocol, port, action, country, city, verdacht))
            land_teller[country] = land_teller.get(country, 0) + hits

        stats = "\n".join(f"{land}: {count} verbinding(en)" for land, count in land_teller.items())
        stats_label_fw.config(text="🌍 Verbindingshits per land:\n" + stats)

    except PermissionError:
        firewall_status_label.config(
            text="🚫 Geen toegang tot firewall log. Start de applicatie als administrator.",
            fg="red"
        )
    except Exception as e:
        firewall_status_label.config(
            text=f"❌ Fout bij lezen firewall log: {e}",
            fg="red"
        )

def stop_analysis():
    global stop_requested
    stop_requested = True

def resume_analysis():
    global stop_requested
    stop_requested = False
    analyse_all_tabs()

def handle_enable_logging():
    success = enable_firewall_logging()
    if success:
        firewall_status_label.config(
            text="✅ Firewall logging is nu ingeschakeld. Analyse wordt opnieuw gestart.",
            fg="green"
        )
        enable_logging_button.pack_forget()
        analyse_firewall_log()
    else:
        firewall_status_label.config(
            text="❌ Kan firewall logging niet inschakelen. Start als admin.",
            fg="red"
        )

def analyse_all_tabs():
    threading.Thread(target=analyse_outgoing, daemon=True).start()
    threading.Thread(target=analyse_incoming, daemon=True).start()
    threading.Thread(target=analyse_firewall_log, daemon=True).start()

def schedule_periodic_refresh():
    analyse_all_tabs()
    root.after(60000, schedule_periodic_refresh)

root = tk.Tk()
root.title("Digitale Diefstal – IP Analyse")
root.geometry("1500x900")

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

# Adminstatus label
admin_status = tk.Label(root, text=" Niet als administrator🔒", fg="red", font=("Segoe UI", 9, "italic"))
admin_status.pack(anchor="ne", padx=10, pady=5)

if is_admin():
    admin_status.config(text="Administratormodus actief🛡️", fg="green")

tab_outgoing = ttk.Frame(notebook)
tab_incoming = ttk.Frame(notebook)
tab_firewall = ttk.Frame(notebook)
notebook.add(tab_outgoing, text="Uitgaand verkeer")
notebook.add(tab_incoming, text="Inkomend verkeer")
notebook.add(tab_firewall, text="Firewall Log")

columns = ("IP", "Hostnaam", "Poort", "Proces", "Land", "Stad", "IOC")
tree_out = ttk.Treeview(tab_outgoing, columns=columns, show="headings")
for col in columns:
    tree_out.heading(col, text=col)
tree_out.pack(fill=tk.BOTH, expand=True)
stats_label_out = tk.Label(tab_outgoing, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label_out.pack(fill=tk.X, padx=10, pady=5)
progress_out = ttk.Progressbar(tab_outgoing, mode="indeterminate")
progress_out.pack(fill=tk.X, padx=10, pady=2)
btn_out = ttk.Button(tab_outgoing, text="▶ Analyse uitgaand verkeer", command=lambda: threading.Thread(target=analyse_outgoing, daemon=True).start())
btn_out.pack(pady=5)

tree_in = ttk.Treeview(tab_incoming, columns=columns, show="headings")
for col in columns:
    tree_in.heading(col, text=col)
tree_in.pack(fill=tk.BOTH, expand=True)
stats_label_in = tk.Label(tab_incoming, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label_in.pack(fill=tk.X, padx=10, pady=5)
btn_in = ttk.Button(tab_incoming, text="▶ Analyse inkomend verkeer", command=lambda: threading.Thread(target=analyse_incoming, daemon=True).start())
btn_in.pack(pady=5)

columns_fw = ("IP", "Hits", "Protocol", "Poort", "Actie", "Land", "Stad", "IOC")
tree_fw = ttk.Treeview(tab_firewall, columns=columns_fw, show="headings")

for col in columns_fw:
    tree_fw.heading(col, text=col)
tree_fw.pack(fill=tk.BOTH, expand=True)
stats_label_fw = tk.Label(tab_firewall, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label_fw.pack(fill=tk.X, padx=10, pady=5)
btn_fw = ttk.Button(tab_firewall, text="▶ Analyse firewall log", command=lambda: threading.Thread(target=analyse_firewall_log, daemon=True).start())
btn_fw.pack(pady=5)

firewall_status_label = tk.Label(tab_firewall, text="", fg="red", font=("Segoe UI", 10, "bold"))
firewall_status_label.pack(pady=5)

restart_admin_button = ttk.Button(tab_firewall, text="Herstart als administrator", command=restart_as_admin)
enable_logging_button = ttk.Button(tab_firewall, text="Firewall logging inschakelen", command=handle_enable_logging)

stop_button = ttk.Button(root, text="⏹ Analyse stoppen", command=stop_analysis)
stop_button.pack(pady=5)

resume_button = ttk.Button(root, text="▶ Analyse hervatten (alles)", command=resume_analysis)
resume_button.pack(pady=5)

schedule_periodic_refresh()

root.mainloop()
