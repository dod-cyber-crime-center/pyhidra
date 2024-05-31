"""
Script to install Ghidra (pyhidra) desktop shortcut.
"""

import argparse
import sys
from pathlib import Path
import logging


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser("Install Pyhidra launcher on desktop")
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

    if sys.platform == "win32":
        from pyhidra.win_shortcut import create_shortcut
    elif sys.platform == "linux":
        from pyhidra.linux_shortcut import create_shortcut
    elif sys.platform == "darwin":
        from pyhidra.mac_shortcut import create_shortcut
    else:
        sys.exit("Unsupported platform")

    create_shortcut(args.install_dir)
