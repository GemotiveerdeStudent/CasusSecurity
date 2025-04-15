import threading
from tkinter import Tk

root = None
stop_requested = False

def set_root_reference(rtk):
    global root
    root = rtk

def stop_analysis():
    global stop_requested
    stop_requested = True

def resume_analysis():
    global stop_requested
    stop_requested = False
    print("🔁 Analyse hervat. Start handmatig de gewenste analyses via de GUI.")

def schedule_periodic_refresh():
    if root:
        # No automatic refresh anymore — optional to reimplement per tab
        root.after(60000, schedule_periodic_refresh)
    else:
        print("❌ Root venster is niet ingesteld. Gebruik set_root_reference(root).")
