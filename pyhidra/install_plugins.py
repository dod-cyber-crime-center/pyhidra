"""
Script to install Ghidra plugins.
"""

import argparse
from pathlib import Path
import logging

import pyhidra


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # spin everything up to ensure all new plugins are installed and exit
    parser = argparse.ArgumentParser("Install Ghidra Plugins")
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
    pyhidra.DeferredPyhidraLauncher(install_dir=args.install_dir).start()
