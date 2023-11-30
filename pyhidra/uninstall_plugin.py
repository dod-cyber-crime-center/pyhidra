"""
Script to uninstall a Ghidra plugin.
"""

import argparse

import pyhidra

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Uninstall Ghidra Plugin")
    parser.add_argument("PLUGIN_NAME", help="Name of plugin to uninstall")
    args = parser.parse_args()

    plugin_name = args.PLUGIN_NAME
    launcher = pyhidra.HeadlessPyhidraLauncher()
    install_path = launcher.get_install_path(plugin_name)
    if install_path.exists():
        launcher.uninstall_plugin(plugin_name)
        if install_path.exists():
            print(f"Failed to uninstall {plugin_name}")
        else:
            print(f"{plugin_name} has been uninstalled.")
    else:
        print(f"{plugin_name} not installed.")
