import os
import sys


def gui():
    """
    Starts the Ghidra GUI
    """
    if not "GHIDRA_INSTALL_DIR" in os.environ:
        import tkinter.messagebox
        msg = "GHIDRA_INSTALL_DIR not set.\nPlease see the README for setup instructions"
        tkinter.messagebox.showerror("Improper Setup", msg)
        sys.exit()
    import pyhidra
    pyhidra.GuiPyhidraLauncher().start()
