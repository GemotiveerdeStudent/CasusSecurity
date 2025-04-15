import tkinter as tk
from tkinter import ttk
from gui.tabs.outgoing_tab import build_outgoing_tab
from gui.tabs.incoming_tab import build_incoming_tab
from gui.tabs.firewall_tab import build_firewall_tab
from gui.tabs.ssh_tab import build_ssh_tab
from gui.gui_controls import build_controls
from gui.gui_styles import apply_treeview_styles
from utils.system_privileges import is_admin
from scheduler.refresh import set_root_reference
from scheduler.refresh import schedule_periodic_refresh

def build_gui(ioc, land_stats, all_rows_out, all_rows_in, stop_requested_func):
    root = tk.Tk()
    root.title("Digitale Diefstal – IP Analyse")
    root.geometry("1500x900")

    set_root_reference(root)

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both")

    admin_status = tk.Label(root, text=" Niet als administrator🔒", fg="red", font=("Segoe UI", 9, "italic"))
    admin_status.pack(anchor="ne", padx=10, pady=5)

    if is_admin():
        admin_status.config(text="Administratormodus actief🛡️", fg="green")

    # Tabs toepassen middels de tabs folder
    tab_outgoing, tab_incoming, tab_firewall, tab_ssh = [ttk.Frame(notebook) for _ in range(4)]

    notebook.add(tab_outgoing, text="Uitgaand verkeer")
    notebook.add(tab_incoming, text="Inkomend verkeer")
    notebook.add(tab_firewall, text="Firewall Log")
    notebook.add(tab_ssh, text="Linux SSH Analyse")

    # Stijlen toepassen via gui_styles
    apply_treeview_styles()

    # Tabs opbouwen
    build_outgoing_tab(tab_outgoing, ioc, all_rows_out, land_stats, stop_requested_func)
    build_incoming_tab(tab_incoming, ioc, all_rows_in, land_stats, stop_requested_func)
    build_firewall_tab(tab_firewall, ioc, land_stats, stop_requested_func)
    build_ssh_tab(tab_ssh, ioc)

    # Algemene knoppen & status
    ioc_status_label = build_controls(root, land_stats)

    schedule_periodic_refresh()
    return root, ioc_status_label