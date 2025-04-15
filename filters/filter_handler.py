
import tkinter as tk
from ioc.ioc_checker import IOCChecker

ioc = IOCChecker()


def apply_filter_incoming(tree, all_rows, host_val, port_val, proc_val):
    host_val = host_val.strip().lower()
    port_val = port_val.strip()
    proc_val = proc_val.strip().lower()

    for row in tree.get_children():
        tree.delete(row)

    for values in all_rows:
        ip, host, port, proc, ioc_val = values

        match_host = not host_val or host_val in host.lower()
        match_port = not port_val or str(port) == port_val
        match_proc = not proc_val or proc_val in proc.lower()

        if match_host and match_port and match_proc:
            tag = "malicious" if ioc_val.upper() == "JA" else "benign"
            tree.insert("", "end", values=values, tags=(tag,))



def apply_filter(tree, all_rows, ioc_val, country_val, proc_val):
    ioc_val = ioc_val.strip().upper()
    country_val = country_val.strip().upper()
    proc_val = proc_val.strip().lower()

    for row in tree.get_children():
        tree.delete(row)

    for values in all_rows:
        ip, host, port, proc, country, city, ioc_val_in_row = values

        match_ioc = not ioc_val or ioc_val_in_row.upper() == ioc_val
        match_country = not country_val or country.upper() == country_val
        match_proc = not proc_val or proc_val in proc.lower()

        if match_ioc and match_country and match_proc:
            tag = "malicious" if ioc_val_in_row.upper() == "JA" else "benign"
            tree.insert("", "end", values=values, tags=(tag,))



def apply_filter_fw(tree_fw, ioc_val, country_val, city_val, ioc):
    ioc_val = ioc_val.strip().upper()
    country_val = country_val.strip().upper()
    city_val = city_val.strip().lower()

    for item in tree_fw.get_children():
        values = tree_fw.item(item, "values")
        ip, hits, proto, port, action, country, city = values[:7]
        ioc_result = "JA" if ioc.is_malicious(ip) else "NEE"

        match_ioc = not ioc_val or ioc_result == ioc_val
        match_country = not country_val or country.upper() == country_val
        match_city = not city_val or city_val in city.lower()

        if match_ioc and match_country and match_city:
            tree_fw.reattach(item, '', 'end')
        else:
            tree_fw.detach(item)



def reset_filter(tree, ioc_box, country_box, proc_box):
    ioc_box.set("")
    country_box.delete(0, tk.END)
    proc_box.delete(0, tk.END)

    for item in tree.get_children(''):
        tree.reattach(item, '', 'end')
