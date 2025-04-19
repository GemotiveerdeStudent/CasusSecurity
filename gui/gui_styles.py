from tkinter import ttk

def apply_treeview_styles():
    style = ttk.Style()
    style.map("Treeview", background=[('selected', '#ececec')])
    style.configure("Treeview", font=("Segoe UI", 10))
    style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    style.configure("malicious.Treeview", background="#ffcccc")  # lichtrood
    style.configure("benign.Treeview", background="#ccffcc")     # lichtgroen

