from tkinter import messagebox
from heatmap.heatmap_generatorr import generate_ip_heatmap
from heatmap_helper import enrich_land_stats_with_location

def handle_generate_heatmap(land_stats):
    if not land_stats or all("example_ip" not in d for d in land_stats.values()):
        messagebox.showwarning("Geen data", "Voer eerst een analyse uit voordat je een heatmap genereert.")
        return

    enrich_land_stats_with_location(land_stats)
    generate_ip_heatmap(land_stats)
