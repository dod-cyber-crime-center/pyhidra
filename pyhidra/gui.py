import os
import sys
import warnings

from pyhidra import get_current_interpreter as _get_current_interpreter

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


def get_current_interpreter():
    warnings.warn(
        "get_current_interpreter has been moved. Please use pyhidra.get_current_interpreter",
        DeprecationWarning
    )
    return _get_current_interpreter()

