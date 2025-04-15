import csv
import tkinter as tk
import threading
import ctypes
import sys
import os
import platform
from tkinter import ttk, filedialog, messagebox
from functools import lru_cache
from geo_lookup import get_geolocation
from ioc_checker import IOCChecker
from connection_reader import get_incoming_connections, get_outgoing_connections
from firewall_log_parser import parse_firewall_log, is_firewall_logging_enabled, enable_firewall_logging
from country_utils import get_country_iso_code
from linux_ssh_analyzer import parse_ssh_log


ioc = IOCChecker()
# Globale dictionary voor landstatistieken (voor rapportage)
land_stats = {}
all_rows_out = []
all_rows_in = []


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

def analyse_ips(ip_entries, tree, stats_label, progress_bar):
    global all_rows_out, all_rows_in
    global ioc, land_stats  # Voeg land_stats toe aan globale scope

    if not ioc:
        ioc = IOCChecker()

    for row in tree.get_children():
        tree.delete(row)

    # Leeg bijhorende buffer
    if tree == tree_out:
        all_rows_out.clear()
    elif tree == tree_in:
        all_rows_in.clear()

    land_teller = {}
    land_stats = {}  # Reset globale statistiek per analyse

    for entry in ip_entries:
        if stop_requested:
            break

        ip, hostname, port, proc = entry
        geo = cached_geolocation(ip)
        raw_country = geo.get("country", "Onbekend")
        country = get_country_iso_code(raw_country)
        city = geo.get("city", "")

        verdacht = "JA" if ioc.is_malicious(ip) else "NEE"
        tag = "malicious" if verdacht == "JA" else "benign"

        row_data = (ip, hostname, port, proc, country, city, verdacht)
        tree.insert("", "end", values=row_data, tags=(tag,))
        land_teller[country] = land_teller.get(country, 0) + 1

        # Sla op in originele lijst
        if tree == tree_out:
            all_rows_out.append(row_data)
        elif tree == tree_in:
            all_rows_in.append(row_data)

        # ➕ Voeg toe aan land_stats voor rapportage
        if country not in land_stats:
            land_stats[country] = {"hits": 0, "bytes": 0, "malicious": 0}

        land_stats[country]["hits"] += 1
        land_stats[country]["malicious"] += 1 if verdacht == "JA" else 0

    stats = "\n".join(f"{land}: {count} verbinding(en)" for land, count in land_teller.items())
    stats_label.config(text="🌍 Verbindingen per land:\n" + stats)

    progress_bar.stop()



def analyse_outgoing():
    progress_out.start()
    analyse_ips(get_outgoing_connections(), tree_out, stats_label_out, progress_out)

def analyse_incoming():
    progress_in.start()
    analyse_ips(get_incoming_connections(), tree_in, stats_label_in, progress_in)


def analyse_firewall_log():
    from firewall_log_parser import parse_firewall_log, is_firewall_logging_enabled

    if not is_firewall_logging_enabled():
        firewall_status_label.config(
            text="⚠️ Firewall logging staat UIT.",
            fg="orange"
        )
        if is_admin():
            enable_logging_button.pack(pady=5)
            restart_admin_button.pack_forget()
        else:
            enable_logging_button.pack_forget()
            restart_admin_button.pack(pady=5)
        return

    firewall_status_label.config(
        text="✅ Firewall logging is actief.",
        fg="green"
    )
    enable_logging_button.pack_forget()

    if not is_admin():
        restart_admin_button.pack(pady=5)
    else:
        restart_admin_button.pack_forget()

    for row in tree_fw.get_children():
        tree_fw.delete(row)

    try:
        style = ttk.Style()
        style.map("Treeview", background=[('selected', '#ececec')])
        style.configure("malicious.Treeview", background="#ffcccc")
        style.configure("benign.Treeview", background="#ccffcc")

        tree_fw.tag_configure("malicious", background="#ffcccc")
        tree_fw.tag_configure("benign", background="#ccffcc")

        data = parse_firewall_log()
        if not data:
            stats_label_fw.config(text="Geen firewall logs gevonden.")
            return

        land_teller = {}
        for entry in data:
            if stop_requested:
                return

            ip, hits, protocol, port, action = entry
            geo = cached_geolocation(ip)
            raw_country = geo.get("country", "Onbekend")
            country = get_country_iso_code(raw_country)
            city = geo.get("city", "")
            verdacht = "JA" if ioc.is_malicious(ip) else "NEE"
            tag = "malicious" if verdacht == "JA" else "benign"

            tree_fw.insert("", "end", values=(ip, hits, protocol, port, action, country, city), tags=(tag,))
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

def apply_filter(tree, ioc_val, country_val, proc_val):
    ioc_val = ioc_val.strip().upper()
    country_val = country_val.strip().upper()
    proc_val = proc_val.strip().lower()

    # Kies juiste dataset
    if tree == tree_out:
        source_data = all_rows_out
    elif tree == tree_in:
        source_data = all_rows_in
    else:
        return

    for row in tree.get_children():
        tree.delete(row)

    for values in source_data:
        ip, host, port, proc, country, city, ioc = values

        match_ioc = (not ioc_val or ioc.upper() == ioc_val)
        match_country = (not country_val or country.upper() == country_val)
        match_proc = (not proc_val or proc_val in proc.lower())

        if match_ioc and match_country and match_proc:
            tag = "malicious" if ioc == "JA" else "benign"
            tree.insert("", "end", values=values, tags=(tag,))

def apply_filter_fw():
    ioc_val = ioc_filter_fw.get().strip().upper()
    country_val = country_filter_fw.get().strip().upper()
    city_val = city_filter_fw.get().strip().lower()

    for item in tree_fw.get_children():
        values = tree_fw.item(item, "values")
        ip, hits, proto, port, action, country, city = values[:7]
        ioc = "JA" if ioc.is_malicious(ip) else "NEE"

        match_ioc = (not ioc_val or ioc.upper() == ioc_val)
        match_country = (not country_val or country.upper() == country_val)
        match_city = (not city_val or city_val in city.lower())

        if match_ioc and match_country and match_city:
            tree_fw.reattach(item, '', 'end')
        else:
            tree_fw.detach(item)


def handle_update_all_iocs():
    from ioc_checker import (
        update_ioc_list_from_feodo,
        update_ioc_list_from_threatfox,
        update_ioc_list_from_openphish,
        update_ioc_list_from_alienvault,
        clear_ioc_list
    )

    clear_ioc_list()
    messages = []
    success = True

    for updater in [
        update_ioc_list_from_feodo,
        update_ioc_list_from_threatfox,
        update_ioc_list_from_openphish,
        lambda: update_ioc_list_from_alienvault("YOUR_API_KEY_HERE")
    ]:
        ok, msg = updater()
        messages.append(msg)
        if not ok:
            success = False

    ioc_status_label.config(text="\n".join(messages))

    if success:
        global ioc
        ioc = IOCChecker()



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

def export_report_csv():
    import csv
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV-bestand", "*.csv")])
    if not file_path:
        return
    try:
        with open(file_path, mode="w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Land", "Aantal verbindingen", "Totaal bytes", "Malicious hits"])
            for land, info in land_stats.items():
                writer.writerow([land, info["hits"], info["bytes"], info["malicious"]])
        messagebox.showinfo("Succes", f"CSV-rapport opgeslagen als:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Fout", f"Kon CSV niet opslaan:\n{e}")

def export_report_txt():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Tekstbestand", "*.txt")])
    if not file_path:
        return
    try:
        with open(file_path, mode="w", encoding="utf-8") as f:
            for land, info in land_stats.items():
                f.write(f"Land: {land}\n")
                f.write(f"- Aantal verbindingen: {info['hits']}\n")
                f.write(f"- Totaal bytes: {info['bytes']}\n")
                f.write(f"- Malicious hits: {info['malicious']}\n")
                f.write("\n")
        messagebox.showinfo("Succes", f"TXT-rapport opgeslagen als:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Fout", f"Kon TXT niet opslaan:\n{e}")

def reset_filter(tree, ioc_box, country_box, proc_box):
    ioc_box.set("")
    country_box.delete(0, tk.END)
    proc_box.delete(0, tk.END)

    for item in tree.get_children(''):
        tree.reattach(item, '', 'end')


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
# Kleurstijl voor IOC-status in uitgaand verkeer
style = ttk.Style()
style = ttk.Style()

for col in columns:
    tree_out.heading(col, text=col)
tree_out.pack(fill=tk.BOTH, expand=True)
stats_label_out = tk.Label(tab_outgoing, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label_out.pack(fill=tk.X, padx=10, pady=5)
progress_out = ttk.Progressbar(tab_outgoing, mode="indeterminate")
progress_out.pack(fill=tk.X, padx=10, pady=2)
btn_out = ttk.Button(tab_outgoing, text="▶ Analyse uitgaand verkeer", command=lambda: threading.Thread(target=analyse_outgoing, daemon=True).start())
btn_out.pack(pady=5)

style.map("Treeview", background=[('selected', '#ececec')])
style.configure("malicious.Treeview", background="#ffcccc")  # lichtrood
style.configure("benign.Treeview", background="#ccffcc")     # lichtgroen

tree_out.tag_configure("malicious", background="#ffcccc")
tree_out.tag_configure("benign", background="#ccffcc")

tree_in = ttk.Treeview(tab_incoming, columns=columns, show="headings")
for col in columns:
    tree_in.heading(col, text=col)
tree_in.pack(fill=tk.BOTH, expand=True)

stats_label_in = tk.Label(tab_incoming, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label_in.pack(fill=tk.X, padx=10, pady=5)

progress_in = ttk.Progressbar(tab_incoming, mode="indeterminate")
progress_in.pack(fill=tk.X, padx=10, pady=2)

btn_in = ttk.Button(tab_incoming, text="▶ Analyse inkomend verkeer", command=lambda: threading.Thread(target=analyse_incoming, daemon=True).start())
btn_in.pack(pady=5)

tree_in.tag_configure("malicious", background="#ffcccc")
tree_in.tag_configure("benign", background="#ccffcc")
filter_frame_out = ttk.Frame(tab_outgoing)
filter_frame_out.pack(fill=tk.X, padx=10, pady=2)

tk.Label(filter_frame_out, text="Filter op IOC:").pack(side=tk.LEFT)
ioc_filter_out = ttk.Combobox(filter_frame_out, values=["", "JA", "NEE"], width=5)
ioc_filter_out.pack(side=tk.LEFT, padx=5)

tk.Label(filter_frame_out, text="Landcode:").pack(side=tk.LEFT)
country_filter_out = ttk.Entry(filter_frame_out, width=5)
country_filter_out.pack(side=tk.LEFT, padx=5)

tk.Label(filter_frame_out, text="Proces:").pack(side=tk.LEFT)
process_filter_out = ttk.Entry(filter_frame_out, width=15)
process_filter_out.pack(side=tk.LEFT, padx=5)

btn_apply_filter_out = ttk.Button(filter_frame_out, text="🔍 Filter toepassen", command=lambda: apply_filter(tree_out, ioc_filter_out.get(), country_filter_out.get(), process_filter_out.get()))
btn_apply_filter_out.pack(side=tk.LEFT, padx=5)

columns_fw = ("IP", "Hits", "Land", "Stad", "IOC")
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
filter_frame_fw = ttk.Frame(tab_firewall)
filter_frame_fw.pack(fill=tk.X, padx=10, pady=2)

tab_ssh = ttk.Frame(notebook)
notebook.add(tab_ssh, text="Linux SSH Analyse")

# Schakel tab uit indien niet op Linux
if platform.system() != "Linux":
    lbl_disabled = tk.Label(tab_ssh, text="🚫 Alleen beschikbaar op Linux-systemen.", fg="red", font=("Segoe UI", 10, "italic"))
    lbl_disabled.pack(pady=20)
else:
    tree_ssh = ttk.Treeview(tab_ssh, columns=("IP", "User", "Status", "Land", "Stad", "IOC"), show="headings")
    for col in ("IP", "User", "Status", "Land", "Stad", "IOC"):
        tree_ssh.heading(col, text=col)
    tree_ssh.pack(fill=tk.BOTH, expand=True)

    tree_ssh.tag_configure("malicious", background="#ffcccc")
    tree_ssh.tag_configure("benign", background="#ccffcc")

    btn_ssh = ttk.Button(tab_ssh, text="▶ Analyseer SSH-log", command=lambda: threading.Thread(target=analyse_ssh, daemon=True).start())
    btn_ssh.pack(pady=5)

columns_ssh = ("IP", "User", "Status", "Land", "Stad", "IOC")
tree_ssh = ttk.Treeview(tab_ssh, columns=columns_ssh, show="headings")
for col in columns_ssh:
    tree_ssh.heading(col, text=col)
tree_ssh.pack(fill=tk.BOTH, expand=True)

stats_label_ssh = tk.Label(tab_ssh, text="", justify="left", anchor="w", font=("Segoe UI", 10))
stats_label_ssh.pack(fill=tk.X, padx=10, pady=5)

def analyse_ssh():
    for row in tree_ssh.get_children():
        tree_ssh.delete(row)

    land_teller = {}
    data = parse_ssh_log()
    for entry in data:
        ip, user, status, country, city, ioc = entry
        tag = "malicious" if ioc == "JA" else "benign"
        tree_ssh.insert("", "end", values=(ip, user, status, country, city, ioc), tags=(tag,))
        land_teller[country] = land_teller.get(country, 0) + 1

    stats = "\n".join(f"{land}: {count} pogingen" for land, count in land_teller.items())
    stats_label_ssh.config(text="🌍 SSH-pogingen per land:\n" + stats)

btn_ssh = ttk.Button(tab_ssh, text="▶ Analyseer SSH-log", command=lambda: threading.Thread(target=analyse_ssh, daemon=True).start())
btn_ssh.pack(pady=5)

tree_ssh.tag_configure("malicious", background="#ffcccc")
tree_ssh.tag_configure("benign", background="#ccffcc")


tk.Label(filter_frame_fw, text="Filter op IOC:").pack(side=tk.LEFT)
ioc_filter_fw = ttk.Combobox(filter_frame_fw, values=["", "JA", "NEE"], width=5)
ioc_filter_fw.pack(side=tk.LEFT, padx=5)

tk.Label(filter_frame_fw, text="Landcode:").pack(side=tk.LEFT)
country_filter_fw = ttk.Entry(filter_frame_fw, width=5)
country_filter_fw.pack(side=tk.LEFT, padx=5)

tk.Label(filter_frame_fw, text="Stad:").pack(side=tk.LEFT)
city_filter_fw = ttk.Entry(filter_frame_fw, width=10)
city_filter_fw.pack(side=tk.LEFT, padx=5)

btn_apply_filter_fw = ttk.Button(filter_frame_fw, text="🔍 Filter toepassen", command=lambda: apply_filter_fw())
btn_apply_filter_fw.pack(side=tk.LEFT, padx=5)

btn_reset_filter_fw = ttk.Button(filter_frame_fw, text="🔄 Reset filters", command=lambda: reset_filter(tree_fw, ioc_filter_fw, country_filter_fw, city_filter_fw))
btn_reset_filter_fw.pack(side=tk.LEFT, padx=5)

stop_button = ttk.Button(root, text="⏹ Analyse stoppen", command=stop_analysis)
stop_button.pack(pady=5)

resume_button = ttk.Button(root, text="▶ Analyse hervatten (alles)", command=resume_analysis)
resume_button.pack(pady=5)

update_iocs_button = ttk.Button(root, text="🔄 Update IOC-lijst (alle bronnen)", command=handle_update_all_iocs)
update_iocs_button.pack(pady=5)

ioc_status_label = tk.Label(root, text="", font=("Segoe UI", 9, "italic"))
ioc_status_label.pack(pady=2)

btn_export_csv = ttk.Button(root, text="📁 Exporteer rapport (CSV)", command=export_report_csv)
btn_export_csv.pack(pady=2)

btn_export_txt = ttk.Button(root, text="📝 Exporteer rapport (TXT)", command=export_report_txt)
btn_export_txt.pack(pady=2)


schedule_periodic_refresh()

root.mainloop()
