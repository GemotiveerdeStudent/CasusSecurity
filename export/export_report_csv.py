import csv
from tkinter import filedialog, messagebox

def export_report_csv(land_stats):
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV-bestand", "*.csv")]
    )
    if not file_path:
        return

    try:
        with open(file_path, mode="w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Land", "Aantal verbindingen", "Totaal bytes", "Malicious hits"])
            for land, info in land_stats.items():
                writer.writerow([
                    land,
                    info.get("hits", 0),
                    info.get("bytes", 0),
                    info.get("malicious", 0)
                ])
        messagebox.showinfo("Succes", f"CSV-rapport opgeslagen als:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Fout", f"Kon CSV niet opslaan:\n{e}")
