import argparse
import io
import os
from pathlib import Path
import platform
import sys
import traceback
import warnings

import pyhidra


class _GuiOutput(io.StringIO):

    def __init__(self, title: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title = title

    def close(self):
        import tkinter.messagebox
        tkinter.messagebox.showinfo(self.title, self.getvalue())
        super().close()


class _GuiArgumentParser(argparse.ArgumentParser):
    def exit(self, status=0, *_):
        sys.exit(status)

    def print_usage(self, file=None):
        if file is None:
            file = _GuiOutput("Usage")
        self._print_message(self.format_usage(), file)

    def print_help(self, file=None):
        if file is None:
            file = _GuiOutput("Help")
        self._print_message(self.format_help(), file)


def _gui():
    # this is the entry from the gui script
    # there may or may not be an attached terminal
    # depending on the current operating system

    # This check handles the edge case of having a corrupt Python installation
    # where tkinter can't be imported. Since there may not be an attached
    # terminal, the problem still needs to be reported somehow.
    try:
        # This import creates problems for macOS
        if platform.system() != 'Darwin':
            import tkinter.messagebox as _
    except ImportError as e:
        if platform.system() == 'Windows':
            # there is no console/terminal to report the error
            import ctypes
            MessageBox = ctypes.windll.user32.MessageBoxW
            MessageBox(None, str(e), "Import Error", 0)
            sys.exit(1)
        # report this before detaching from the console or no
        # errors will be reported if they occur
        raise

    try:
        parser = _GuiArgumentParser(prog="pyhidraw")
        parser.add_argument(
            "--install-dir",
            type=Path,
            default=None,
            dest="install_dir",
            metavar="",
            help="Path to Ghidra installation. "\
                "(defaults to the GHIDRA_INSTALL_DIR environment variable)"
        )
        args = parser.parse_args()
        install_dir = args.install_dir
    except Exception as e:
        import tkinter.messagebox
        msg = "".join(traceback.format_exception(type(e), value=e, tb=e.__traceback__))
        tkinter.messagebox.showerror(type(e), msg)
        sys.exit(1)

    if platform.system() == 'Windows':
        # gui_script works like it is supposed to on windows
        gui(install_dir)
        return

    pid = os.fork()
    if pid != 0:
        # original process can exit
        return

    fd = os.open(os.devnull, os.O_RDWR)
    # redirect stdin, stdout and stderr to /dev/null so the jvm can't use the terminal
    # this also prevents errors from attempting to write to a closed sys.stdout #21
    os.dup2(fd, sys.stdin.fileno(), inheritable=False)
    os.dup2(fd, sys.stdout.fileno(), inheritable=False)
    os.dup2(fd, sys.stderr.fileno(), inheritable=False)

    # run the application
    gui(install_dir)


def gui(install_dir: Path = None):
    """
    Starts the Ghidra GUI

    :param install_dir: The path to the Ghidra installation directory.
        (Defaults to the GHIDRA_INSTALL_DIR environment variable)
    """
    pyhidra.GuiPyhidraLauncher(install_dir=install_dir).start()


def get_current_interpreter():
    warnings.warn(
        "get_current_interpreter has been moved. Please use pyhidra.get_current_interpreter",
        DeprecationWarning
    )
    return pyhidra.get_current_interpreter()

