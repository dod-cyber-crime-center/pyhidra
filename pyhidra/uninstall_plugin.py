"""
Script to uninstall a Ghidra plugin.
"""

import argparse
import logging
from pathlib import Path
import warnings

import pyhidra


if __name__ == "__main__":
    warnings.warn('"python -m pyhidra.uninstall_plugins"'
                  ' has been removed in pyghidra', DeprecationWarning, 2)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser("Uninstall Ghidra Plugin")
    parser.add_argument(
        "PLUGIN_NAME",
        help="Name of plugin to uninstall"
    )
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

    plugin_name = args.PLUGIN_NAME
    launcher = pyhidra.DeferredPyhidraLauncher(install_dir=args.install_dir)
    launcher.start()
    install_path = launcher.get_install_path(plugin_name)
    if install_path.exists():
        launcher.uninstall_plugin(plugin_name)
        if install_path.exists():
            print(f"Failed to uninstall {plugin_name}")
        else:
            print(f"{plugin_name} has been uninstalled.")
    else:
        print(f"{plugin_name} not installed.")
