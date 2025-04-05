# run application from environment with the following 2 commando's:
# .venv\Scripts\activate
# python dashboard.py


# dashboard.py
import tkinter as tk
import threading
import time
from tkinter import ttk
from geo_lookup import get_geolocation
from ioc_checker import IOCChecker
from connection_reader import get_active_remote_ips



test_ips = get_active_remote_ips()

ioc = IOCChecker()

def analyse_ips():
    for row in tree.get_children():
        tree.delete(row)
    
    for ip in test_ips:
        geo = get_geolocation(ip)
        verdacht = "JA" if ioc.is_malicious(ip) else "NEE"
        tree.insert("", "end", values=(ip, geo['country'], geo['city'], verdacht))

# GUI setup
root = tk.Tk()
root.title("Digitale Diefstal – IP Analyse")
root.geometry("600x300")

tree = ttk.Treeview(root, columns=("IP", "Land", "Stad", "IOC"), show="headings")
tree.heading("IP", text="IP")
tree.heading("Land", text="Land")
tree.heading("Stad", text="Stad")
tree.heading("IOC", text="Verdacht")
tree.pack(fill=tk.BOTH, expand=True)

btn = ttk.Button(root, text="Analyse starten", command=analyse_ips)
btn.pack(pady=10)

root.mainloop()