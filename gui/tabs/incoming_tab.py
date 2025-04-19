import tkinter as tk
from tkinter import ttk
import threading
from analyzer.ip_analyzer import analyse_ips
from filters.filter_handler import apply_filter_incoming, reset_filter
from utils.connection_reader import get_incoming_connections

def build_incoming_tab(tab, ioc, all_rows_in, land_stats, stop_requested_func):
    columns = ("IP", "Hostnaam", "Poort", "Proces", "IOC")
    tree_in = ttk.Treeview(tab, columns=columns, show="headings")
    for col in columns:
        tree_in.heading(col, text=col)
    tree_in.pack(fill=tk.BOTH, expand=True)
    tree_in.tag_configure("malicious", background="#ffcccc")
    tree_in.tag_configure("benign", background="#ccffcc")

    stats_label_in = tk.Label(tab, text="", justify="left", anchor="w", font=("Segoe UI", 10))
    stats_label_in.pack(fill=tk.X, padx=10, pady=5)

    progress_in = ttk.Progressbar(tab, mode="indeterminate")
    progress_in.pack(fill=tk.X, padx=10, pady=2)

    def run_analysis():
        progress_in.start()
        connections = get_incoming_connections()
        enriched = []

        for ip, host, port, proc in connections:
            verdacht = "JA" if ioc.is_malicious(ip) else "NEE"
            enriched.append((ip, host, port, proc, verdacht))

        tree_in.delete(*tree_in.get_children())
        all_rows_in.clear()

        for entry in enriched:
            ip, host, port, proc, verdacht = entry
            tag = "malicious" if verdacht == "JA" else "benign"
            tree_in.insert("", "end", values=entry, tags=(tag,))
            all_rows_in.append(entry)

        stats_label_in.config(text=f"🌍 Aantal lokale listeners: {len(enriched)}")
        progress_in.stop()

    btn_in = ttk.Button(
        tab,
        text="▶ Analyse lokale listeners",
        command=lambda: threading.Thread(target=run_analysis, daemon=True).start()
    )
    btn_in.pack(pady=5)

    filter_frame_in = ttk.Frame(tab)
    filter_frame_in.pack(fill=tk.X, padx=10, pady=2)

    host_filter_in = ttk.Entry(filter_frame_in, width=15)
    port_filter_in = ttk.Entry(filter_frame_in, width=6)
    process_filter_in = ttk.Entry(filter_frame_in, width=15)

    ttk.Label(filter_frame_in, text="Hostnaam:").pack(side=tk.LEFT)
    host_filter_in.pack(side=tk.LEFT, padx=5)
    ttk.Label(filter_frame_in, text="Poort:").pack(side=tk.LEFT)
    port_filter_in.pack(side=tk.LEFT, padx=5)
    ttk.Label(filter_frame_in, text="Proces:").pack(side=tk.LEFT)
    process_filter_in.pack(side=tk.LEFT, padx=5)

    ttk.Button(filter_frame_in, text="🔍 Filter toepassen", command=lambda: apply_filter_incoming(
        tree_in, all_rows_in, host_filter_in.get(), port_filter_in.get(), process_filter_in.get())).pack(side=tk.LEFT, padx=5)