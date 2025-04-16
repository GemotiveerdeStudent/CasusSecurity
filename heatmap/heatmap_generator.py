import folium
from folium.plugins import HeatMap
import webbrowser
import os

def generate_ip_heatmap(land_stats, map_path="heatmap.html"):
    locations = []

    for land_info in land_stats.values():
        lat = land_info.get("lat")
        lon = land_info.get("lon")
        hits = land_info.get("hits", 0)

        if lat is not None and lon is not None:
            locations.append([lat, lon, hits])  # lat, lon, weight

    if not locations:
        print("[Heatmap] Geen locatiegegevens beschikbaar.")
        return

    # Startpositie van de kaart
    m = folium.Map(location=[20, 0], zoom_start=2)

    # Voeg heatmap toe
    HeatMap(locations).add_to(m)

    m.save(map_path)
    abs_path = os.path.abspath(map_path)
    webbrowser.open(f"file://{abs_path}")
    print(f"[Heatmap] Heatmap opgeslagen en geopend: {abs_path}")
