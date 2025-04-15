from ioc.ioc_checker import IOCChecker
from gui.gui_setup import build_gui
import sys
sys.path.append('./gui')

from gui_setup import build_gui


# Initieer globale configuraties
ioc = IOCChecker()
land_stats = {}
all_rows_out = []
all_rows_in = []
stop_requested = False

# Start GUI
if __name__ == "__main__":
    root, _ = build_gui(
        ioc=ioc,
        land_stats=land_stats,
        all_rows_out=all_rows_out,
        all_rows_in=all_rows_in,
        stop_requested_func=lambda: stop_requested
    )
    root.mainloop()