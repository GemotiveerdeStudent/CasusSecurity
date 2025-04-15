from tkinter import ttk

def create_tabs(notebook):
    tab_outgoing = ttk.Frame(notebook)
    tab_incoming = ttk.Frame(notebook)
    tab_firewall = ttk.Frame(notebook)
    tab_ssh = ttk.Frame(notebook)

    notebook.add(tab_outgoing, text="Uitgaand verkeer")
    notebook.add(tab_incoming, text="Local Listeners")
    notebook.add(tab_firewall, text="Firewall Log")
    notebook.add(tab_ssh, text="Linux SSH Analyse")

    return tab_outgoing, tab_incoming, tab_firewall, tab_ssh
