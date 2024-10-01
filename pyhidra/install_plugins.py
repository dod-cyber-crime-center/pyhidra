"""
Script to install Ghidra plugins.
"""

import warnings


if __name__ == "__main__":
    warnings.warn('"python -m pyhidra.install_plugins" is no longer required'
                  ' and has been removed in pyghidra', DeprecationWarning, 2)
    # do nothing
