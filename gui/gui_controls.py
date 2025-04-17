import tkinter as tk
from tkinter import ttk
from export.export_report_csv import export_report_csv
from export.export_report_txt import export_report_txt
from ioc.ioc_handler import handle_update_all_iocs
from scheduler.refresh import stop_analysis, resume_analysis
from heatmap.heatmap_generator import generate_ip_heatmap

def build_controls(root, land_stats):
    ttk.Button(root, text="⏹ Analyse stoppen", command=stop_analysis).pack(pady=5)
    ttk.Button(root, text="▶ Analyse hervatten (alles)", command=resume_analysis).pack(pady=5)
    ttk.Button(root, text="🔄 Update IOC-lijst (alle bronnen)", command=lambda: handle_update_all_iocs(ioc_status_label)).pack(pady=5)


    ioc_status_label = tk.Label(root, text="", font=("Segoe UI", 9, "italic"))
    ioc_status_label.pack(pady=2)

    ttk.Button(root, text="📁 Exporteer rapport (CSV)", command=lambda: export_report_csv(land_stats)).pack(pady=2)
    ttk.Button(root, text="📝 Exporteer rapport (TXT)", command=lambda: export_report_txt(land_stats)).pack(pady=2)
    ttk.Button(root, text="🗺️ Genereer Heatmap", command=lambda: generate_ip_heatmap(land_stats)).pack(pady=2)


    return ioc_status_label
