from analyzer.firewall_log_parser import parse_firewall_log, is_firewall_logging_enabled, enable_firewall_logging
from ioc.ioc_checker import IOCChecker
from utils.geolocation import cached_geolocation
from utils.country_utils import get_country_iso_code
from utils.system_privileges import is_admin

def analyse_firewall_log(tree_fw, stats_label_fw, firewall_status_label, enable_logging_button, restart_admin_button, stop_requested, ioc, land_stats):
    if not is_firewall_logging_enabled():
        firewall_status_label.config(text="⚠️ Firewall logging staat UIT.", fg="orange")
        if is_admin():
            enable_logging_button.pack(pady=5)
            restart_admin_button.pack_forget()
        else:
            enable_logging_button.pack_forget()
            restart_admin_button.pack(pady=5)
        return

    firewall_status_label.config(text="✅ Firewall logging is actief.", fg="green")
    enable_logging_button.pack_forget()

    if not is_admin():
        restart_admin_button.pack(pady=5)
    else:
        restart_admin_button.pack_forget()

    for row in tree_fw.get_children():
        tree_fw.delete(row)

    try:
        data = parse_firewall_log()
        if not data:
            stats_label_fw.config(text="Geen firewall logs gevonden.")
            return

        land_teller = {}
        land_stats.clear()

        for entry in data:
            if stop_requested():
                return

            ip, hits, protocol, port, action, bytes_sent = entry
            geo = cached_geolocation(ip)
            country = get_country_iso_code(geo.get("country", "Onbekend"))
            city = geo.get("city", "")
            verdacht = "JA" if ioc.is_malicious(ip) else "NEE"
            tag = "malicious" if verdacht == "JA" else "benign"

            tree_fw.insert("", "end", values=(ip, hits, protocol, port, action, country, city, bytes_sent), tags=(tag,))
            land_teller[country] = land_teller.get(country, 0) + hits

            if country not in land_stats:
                land_stats[country] = {"hits": 0, "bytes": 0, "malicious": 0}

            land_stats[country]["hits"] += hits
            land_stats[country]["bytes"] += bytes_sent
            land_stats[country]["malicious"] += 1 if verdacht == "JA" else 0

        stats = "\n".join(f"{land}: {count} verbinding(en)" for land, count in land_teller.items())
        stats_label_fw.config(text="🌍 Verbindingshits per land:\n" + stats)

    except Exception as e:
        firewall_status_label.config(text=f"❌ Fout bij lezen firewall log: {e}", fg="red")

def handle_enable_logging(firewall_status_label, enable_logging_button, restart_admin_button, analyse_callback):
    success = enable_firewall_logging()
    if success:
        firewall_status_label.config(
            text="✅ Firewall logging is nu ingeschakeld. Analyse wordt opnieuw gestart.",
            fg="green"
        )
        enable_logging_button.pack_forget()
        analyse_callback()
    else:
        firewall_status_label.config(
            text="❌ Kan firewall logging niet inschakelen. Start als admin.",
            fg="red"
        )