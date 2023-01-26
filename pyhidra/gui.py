
import logging
import os
import platform
import sys
import warnings

from pyhidra import get_current_interpreter as _get_current_interpreter

logger = logging.getLogger(__name__)


def _gui():
    if platform.system() == 'Windows':
        # gui_script works like it is supposed to on windows
        gui()
        return

    pid = os.fork()
    if pid != 0:
        # original process can exit
        return

    # close stdin, stdout and stderr so the jvm can't use the terminal
    # these must be closed using os.close and not sys.stdout.close()
    os.close(sys.stdin.fileno())
    os.close(sys.stdout.fileno())
    os.close(sys.stderr.fileno())

    # run the application
    gui()


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

