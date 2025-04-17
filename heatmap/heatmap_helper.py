from utils.geolocation import cached_geolocation

def enrich_land_stats_with_location(land_stats):
    """
    Voeg lat/lon toe aan elke land_stats entry, als dat nog niet is gebeurd.
    """
    for country_code, data in land_stats.items():
        # Skip als al aanwezig
        if "lat" in data and "lon" in data:
            continue

        try:
            # We gebruiken een fictief IP van dat land voor geo-opzoeking
            example_ip = data.get("example_ip", None)
            if not example_ip:
                continue

            geo = cached_geolocation(example_ip)
            data["lat"] = geo.get("lat")
            data["lon"] = geo.get("lon")

        except Exception as e:
            print(f"[heatmap_helper] Fout bij geolocatie voor {country_code}: {e}")
