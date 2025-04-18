import os
import re
import requests
import folium
from folium.plugins import HeatMap
import webbrowser
import traceback

from utils.country_utils import get_country_iso_code

# -------------------------------------------------
# 1) Pak alle unieke IP’s uit je outgoing log
# -------------------------------------------------
def parse_outgoing_ips(log_path):
    if not os.path.exists(log_path):
        print(f"[Parser][ERROR] Bestand niet gevonden: {log_path}")
        return []

    text = open(log_path, errors="ignore").read()
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    unique = sorted(set(ips))
    print(f"[Parser] {len(ips)} total IP‑hits, {len(unique)} uniek")
    return unique

# -------------------------------------------------
# 2) Batch‑geolocatie via ip‑api.com (max 100 IPs per call)
# -------------------------------------------------
def geolocate_batch(ips):
    endpoint = "http://ip-api.com/batch"
    # chunk in batches van 100
    geo_map = {}
    for i in range(0, len(ips), 100):
        batch = ips[i:i+100]
        payload = [{"query": ip, "fields": "query,status,country,lat,lon"} for ip in batch]
        try:
            resp = requests.post(endpoint, json=payload, timeout=5)
            resp.raise_for_status()
            results = resp.json()
        except Exception as e:
            print(f"[Geo][ERROR] Batch‑geolocatie mislukt voor batch {i//100}: {e}")
            continue

        for rec in results:
            ip = rec.get("query")
            if rec.get("status") == "success":
                country = rec.get("country", "Onbekend")
                iso = get_country_iso_code(country) or "??"
                geo_map[ip] = {
                    "iso": iso,
                    "lat": rec.get("lat"),
                    "lon": rec.get("lon")
                }
            else:
                geo_map[ip] = None

    return geo_map

# -------------------------------------------------
# 3) Tel per land de hits op basis van de volledige log
# -------------------------------------------------
def build_country_stats(log_path, geo_map):
    text = open(log_path, errors="ignore").read()
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

    stats = {}
    for ip in ips:
        info = geo_map.get(ip)
        if not info:
            continue
        iso = info["iso"]
        entry = stats.setdefault(iso, {
            "hits": 0,
            "lat":  info["lat"],
            "lon":  info["lon"]
        })
        entry["hits"] += 1

    print(f"[Stats] Hits per land: {stats}")
    return stats

# -------------------------------------------------
# 4) Genereer altijd een kaart (zelfs zonder data)
# -------------------------------------------------
def generate_ip_heatmap(stats, map_path="heatmap.html"):
    points = [
        [float(i["lat"]), float(i["lon"]), float(i["hits"])]
        for i in stats.values()
        if i.get("lat") is not None and i.get("lon") is not None and i.get("hits", 0) > 0
    ]

    center = [20, 0]
    if points:
        center = [
            sum(p[0] for p in points) / len(points),
            sum(p[1] for p in points) / len(points)
        ]

    try:
        m = folium.Map(location=center, zoom_start=2)
        if points:
            HeatMap(points, radius=25, blur=15, max_zoom=10).add_to(m)
        else:
            print("[Heatmap] Geen hits om te plotten – lege wereldkaart wordt gegenereerd.")
        m.save(map_path)

        uri = f"file:///{os.path.abspath(map_path).replace(os.sep, '/')}"
        webbrowser.open(uri)
        print(f"[Heatmap] Kaart opgeslagen en geopend: {map_path}")

    except Exception:
        print("[Heatmap][ERROR] Fout bij heatmap:")
        traceback.print_exc()

# -------------------------------------------------
# 5) Centrale functie om vanuit je GUI aan te roepen
# -------------------------------------------------
def run_heatmap_from_log(log_path, map_path="heatmap.html"):
    """
    Volledige pipeline: parse, geolocate, stats bouwen en heatmap maken.
    Roep deze functie aan in je button‑callback.
    """
    # 1) Unieke IP’s
    unique_ips = parse_outgoing_ips(log_path)
    if not unique_ips:
        print("[Heatmap] Stop: geen IP’s gevonden.")
        generate_ip_heatmap({}, map_path)  # genereer lege kaart
        return

    # 2) Batch‑geolocatie
    geo_map = geolocate_batch(unique_ips)

    # 3) Stats per land
    stats = build_country_stats(log_path, geo_map)

    # 4) Heatmap
    generate_ip_heatmap(stats, map_path)
