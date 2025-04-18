from tkinter import messagebox
from heatmap.heatmap_generator import generate_ip_heatmap
from heatmap.heatmap_helper import enrich_land_stats_with_location

def handle_generate_heatmap(land_stats):
    """
    Callback voor de "Genereer Heatmap"-knop:
    1. Controle of er land_stats data is
    2. Verrijk met lat/lon via heatmap_helper
    3. Genereer de heatmap
    """

    if not land_stats or all("example_ip" not in d for d in land_stats.values()):
        messagebox.showwarning(
            title="Geen data",
            message="Voer eerst een analyse uit voordat je een heatmap genereert."
        )
        return

    enrich_land_stats_with_location(land_stats)

    generate_ip_heatmap(land_stats)
