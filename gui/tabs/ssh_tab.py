import tkinter as tk
from tkinter import ttk
import threading
from ssh.linux_ssh_analyzer import parse_ssh_log

def analyse_ssh(tree, stats_label, ioc):
    tree.delete(*tree.get_children())
    stats_label.config(text="SSH-log wordt geanalyseerd...")

    entries = parse_ssh_log(ioc)
    land_teller = {}

    for entry in entries:
        ip, user, status, country, city, ioc_flag = entry
        tag = "malicious" if ioc_flag == "JA" else "benign"
        tree.insert("", "end", values=entry, tags=(tag,))
        land_teller[country] = land_teller.get(country, 0) + 1

    if entries:
        summary = "\n".join(f"{land}: {count} poging(en)" for land, count in land_teller.items())
        stats_label.config(text="🌍 SSH-pogingen per land:\n" + summary)
    else:
        stats_label.config(text="Geen relevante SSH-logregels gevonden.")

def build_ssh_tab(tab, ioc):
    columns = ("IP", "User", "Status", "Land", "Stad", "IOC")
    tree_ssh = ttk.Treeview(tab, columns=columns, show="headings")
    for col in columns:
        tree_ssh.heading(col, text=col)
    tree_ssh.pack(fill=tk.BOTH, expand=True)
    tree_ssh.tag_configure("malicious", background="#ffcccc")
    tree_ssh.tag_configure("benign", background="#ccffcc")

    stats_label = tk.Label(tab, text="", justify="left", anchor="w", font=("Segoe UI", 10))
    stats_label.pack(fill=tk.X, padx=10, pady=5)

    ttk.Button(
        tab,
        text="▶ Analyseer SSH-log",
        command=lambda: threading.Thread(target=analyse_ssh, args=(tree_ssh, stats_label, ioc), daemon=True).start()
    ).pack(pady=5)
