import tkinter as tk
from tkinter import ttk
import threading
import time
from analyzer.ip_analyzer import analyse_ips
from filters.filter_handler import apply_filter, reset_filter
from utils.connection_reader import get_outgoing_connections

def build_outgoing_tab(tab, ioc, all_rows_out, land_stats, stop_requested_func):
    columns = ("IP", "Hostnaam", "Poort", "Proces", "Land", "Stad", "IOC")
    tree = ttk.Treeview(tab, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
    tree.pack(fill=tk.BOTH, expand=True)
    tree.tag_configure("malicious", background="#ffcccc")
    tree.tag_configure("benign", background="#ccffcc")

    stats_label = tk.Label(tab, text="", justify="left", anchor="w", font=("Segoe UI", 10))
    stats_label.pack(fill=tk.X, padx=10, pady=5)

    progress = ttk.Progressbar(tab, mode="indeterminate")
    progress.pack(fill=tk.X, padx=10, pady=2)

    def run_analysis():
        start_time = time.time()
        print("[DEBUG] Start analyse uitgaand verkeer")
        progress.start()

        ip_entries = get_outgoing_connections()
        print(f"[DEBUG] Aantal actieve uitgaande connecties gevonden: {len(ip_entries)}")

        analyse_ips(
            ip_entries=ip_entries,
            tree=tree,
            stats_label=stats_label,
            progress_bar=progress,
            ioc=ioc,
            all_rows_buffer=all_rows_out,
            land_stats=land_stats,
            stop_requested=stop_requested_func
        )

        end_time = time.time()
        print(f"[DEBUG] Analyse uitgaand verkeer voltooid in {end_time - start_time:.2f} seconden")

    btn_analyse = ttk.Button(tab, text="▶ Analyse uitgaand verkeer", command=lambda: threading.Thread(target=run_analysis, daemon=True).start())
    btn_analyse.pack(pady=5)

    # === Filtersectie ===
    filter_frame = ttk.Frame(tab)
    filter_frame.pack(fill=tk.X, padx=10, pady=2)

    ioc_filter = ttk.Combobox(filter_frame, values=["", "JA", "NEE"], width=5)
    country_filter = ttk.Entry(filter_frame, width=5)
    process_filter = ttk.Entry(filter_frame, width=15)

    ttk.Label(filter_frame, text="Filter op IOC:").pack(side=tk.LEFT)
    ioc_filter.pack(side=tk.LEFT, padx=5)
    ttk.Label(filter_frame, text="Landcode:").pack(side=tk.LEFT)
    country_filter.pack(side=tk.LEFT, padx=5)
    ttk.Label(filter_frame, text="Proces:").pack(side=tk.LEFT)
    process_filter.pack(side=tk.LEFT, padx=5)

    ttk.Button(filter_frame,
                text="🔍 Filter toepassen",
                command=lambda:apply_filter(
                    tree, 
                    all_rows_out,
                    ioc_filter.get(), 
                    country_filter.get(), 
                    process_filter.get() 
                    )
                ).pack(side=tk.LEFT, padx=5)

    
    ttk.Button(filter_frame, text="🔄 Reset filters", command=lambda: reset_filter(tree, ioc_filter, country_filter, process_filter)).pack(side=tk.LEFT, padx=5)
