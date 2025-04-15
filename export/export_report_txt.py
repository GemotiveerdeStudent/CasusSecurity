from tkinter import filedialog, messagebox

def export_report_txt(land_stats):
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Tekstbestand", "*.txt")]
    )
    if not file_path:
        return

    try:
        with open(file_path, mode="w", encoding="utf-8") as f:
            for land, info in land_stats.items():
                f.write(f"Land: {land}\n")
                f.write(f"- Aantal verbindingen: {info.get('hits', 0)}\n")
                f.write(f"- Totaal bytes: {info.get('bytes', 0)}\n")
                f.write(f"- Malicious hits: {info.get('malicious', 0)}\n")
                f.write("\n")
        messagebox.showinfo("Succes", f"TXT-rapport opgeslagen als:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Fout", f"Kon TXT niet opslaan:\n{e}")
