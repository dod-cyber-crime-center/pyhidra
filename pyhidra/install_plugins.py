"""
Script to install Ghidra plugins.
"""

import pyhidra

if __name__ == "__main__":
    # spin everything up to ensure all new plugins are installed and exit
    pyhidra.HeadlessPyhidraLauncher().start()
