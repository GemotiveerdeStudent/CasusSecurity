from ioc.ioc_checker import IOCChecker
from utils.geolocation import cached_geolocation
from utils.country_utils import get_country_iso_code
from utils.connection_reader import get_incoming_connections, get_outgoing_connections

def analyse_ips(ip_entries, tree, stats_label, progress_bar, all_rows_buffer, land_stats, stop_requested, ioc):
    for row in tree.get_children():
        tree.delete(row)

    all_rows_buffer.clear()
    land_teller = {}
    land_stats.clear()

    for entry in ip_entries:
        if stop_requested():
            break

        ip, hostname, port, proc = entry
        geo = cached_geolocation(ip)
        raw_country = geo.get("country", "Onbekend")
        country = get_country_iso_code(raw_country)
        city = geo.get("city", "")

        verdacht = "JA" if ioc.is_malicious(ip) else "NEE"
        tag = "malicious" if verdacht == "JA" else "benign"

        row_data = (ip, hostname, port, proc, country, city, verdacht)
        tree.insert("", "end", values=row_data, tags=(tag,))
        tree.update_idletasks()  # Forceer UI update voor snellere feedback
        all_rows_buffer.append(row_data)

        if country not in land_stats:
            land_stats[country] = {
                "hits": 0,
                "bytes": 0,
                "malicious": 0,
                "example_ip": ip
            }


        land_stats[country]["hits"] += 1
        land_stats[country]["malicious"] += 1 if verdacht == "JA" else 0

        land_teller[country] = land_teller.get(country, 0) + 1

    stats = "\n".join(f"{land}: {count} verbinding(en)" for land, count in land_teller.items())
    stats_label.config(text="🌍 Verbindingen per land:\n" + stats)
    progress_bar.stop()

def analyse_outgoing(tree_out, stats_label_out, progress_out, all_rows_out, land_stats, stop_requested, ioc):
    progress_out.start()
    analyse_ips(get_outgoing_connections(), tree_out, stats_label_out, progress_out, all_rows_out, land_stats, stop_requested, ioc)

def analyse_incoming(tree_in, stats_label_in, progress_in, all_rows_in, land_stats, stop_requested, ioc):
    progress_in.start()
    analyse_ips(get_incoming_connections(), tree_in, stats_label_in, progress_in, all_rows_in, land_stats, stop_requested, ioc)