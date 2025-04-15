import tkinter as tk
from tkinter import ttk
import threading
from analyzer.firewall_handler import analyse_firewall_log, handle_enable_logging
from filters.filter_handler import apply_filter_fw, reset_filter
from utils.system_privileges import restart_as_admin

def build_firewall_tab(tab, ioc, land_stats, stop_requested_func):
    columns_fw = ("IP", "Hits", "Protocol", "Poort", "Actie", "Land", "Stad")
    tree_fw = ttk.Treeview(tab, columns=columns_fw, show="headings")
    for col in columns_fw:
        tree_fw.heading(col, text=col)
    tree_fw.pack(fill=tk.BOTH, expand=True)
    tree_fw.tag_configure("malicious", background="#ffcccc")
    tree_fw.tag_configure("benign", background="#ccffcc")

    stats_label_fw = tk.Label(tab, text="", justify="left", anchor="w", font=("Segoe UI", 10))
    stats_label_fw.pack(fill=tk.X, padx=10, pady=5)

    firewall_status_label = tk.Label(tab, text="", fg="red", font=("Segoe UI", 10, "bold"))
    firewall_status_label.pack(pady=5)

    restart_admin_button = ttk.Button(tab, text="Herstart als administrator", command=restart_as_admin)
    enable_logging_button = ttk.Button(tab, text="Firewall logging inschakelen",
                                           command=lambda: handle_enable_logging(
                                           firewall_status_label,
                                           enable_logging_button,
                                           restart_admin_button,
                                           lambda: analyse_firewall_log(
                                               tree_fw,
                                               stats_label_fw,
                                               firewall_status_label,
                                               enable_logging_button,
                                               restart_admin_button,
                                               stop_requested_func,
                                               ioc,
                                               land_stats
                                           )
                                       ))

    btn_fw = ttk.Button(
        tab,
        text="▶ Analyse firewall log",
        command=lambda: threading.Thread(
            target=analyse_firewall_log,
            args=(tree_fw, stats_label_fw, firewall_status_label, enable_logging_button,
                  restart_admin_button, stop_requested_func, ioc, land_stats),
            daemon=True
        ).start()
    )
    btn_fw.pack(pady=5)

    # Filtersectie
    filter_frame_fw = ttk.Frame(tab)
    filter_frame_fw.pack(fill=tk.X, padx=10, pady=2)

    ioc_filter_fw = ttk.Combobox(filter_frame_fw, values=["", "JA", "NEE"], width=5)
    country_filter_fw = ttk.Entry(filter_frame_fw, width=5)
    city_filter_fw = ttk.Entry(filter_frame_fw, width=10)

    ttk.Label(filter_frame_fw, text="Filter op IOC:").pack(side=tk.LEFT)
    ioc_filter_fw.pack(side=tk.LEFT, padx=5)
    ttk.Label(filter_frame_fw, text="Landcode:").pack(side=tk.LEFT)
    country_filter_fw.pack(side=tk.LEFT, padx=5)
    ttk.Label(filter_frame_fw, text="Stad:").pack(side=tk.LEFT)
    city_filter_fw.pack(side=tk.LEFT, padx=5)

    ttk.Button(filter_frame_fw, text="🔍 Filter toepassen", command=lambda: apply_filter_fw(
        tree_fw,
        ioc_filter_fw.get(),
        country_filter_fw.get(),
        city_filter_fw.get(),
        ioc 
    )).pack(side=tk.LEFT, padx=5)



    ttk.Button(filter_frame_fw, text="🔄 Reset filters", command=lambda: reset_filter(
        tree_fw, ioc_filter_fw, country_filter_fw, city_filter_fw)).pack(side=tk.LEFT, padx=5)