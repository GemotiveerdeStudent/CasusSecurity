# gui_controls.py
import tkinter as tk
from tkinter import ttk
from export.export_report_csv import export_report_csv
from export.export_report_txt import export_report_txt
from ioc.ioc_handler import handle_update_all_iocs
from scheduler.refresh import stop_analysis, resume_analysis
from gui.heatmap_gui_handler import handle_generate_heatmap

def build_controls(root, land_stats):
    """
    Bouwt de knoppen voor de GUI:
    - Analyse stoppen/hervatten
    - IOC-lijst updaten
    - Rapport exporteren (CSV/TXT)
    - Heatmap genereren via handler
    """
    ttk.Button(root, text="⏹ Analyse stoppen", command=stop_analysis).pack(pady=5)
    ttk.Button(root, text="▶ Analyse hervatten (alles)", command=resume_analysis).pack(pady=5)

    ioc_status_label = tk.Label(root, text="", font=("Segoe UI", 9, "italic"))
    ttk.Button(
        root, text="🔄 Update IOC-lijst (alle bronnen)",
        command=lambda: handle_update_all_iocs(ioc_status_label)
    ).pack(pady=5)
    ioc_status_label.pack(pady=2)

    ttk.Button(
        root, text="📁 Exporteer rapport (CSV)",
        command=lambda: export_report_csv(land_stats)
    ).pack(pady=2)
    ttk.Button(
        root, text="📝 Exporteer rapport (TXT)",
        command=lambda: export_report_txt(land_stats)
    ).pack(pady=2)

    ttk.Button(
        root, text="🗺️ Genereer Heatmap",
        command=lambda: handle_generate_heatmap(land_stats)
    ).pack(pady=2)

    return ioc_status_label
