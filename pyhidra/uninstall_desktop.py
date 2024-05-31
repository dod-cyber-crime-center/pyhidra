
import sys


if __name__ == "__main__":
    if sys.platform == "win32":
        from pyhidra.win_shortcut import remove_shortcut
    elif sys.platform == "linux":
        from pyhidra.linux_shortcut import remove_shortcut
    elif sys.platform == "darwin":
        from pyhidra.mac_shortcut import remove_shortcut
    else:
        sys.exit("Unsupported platform")

    remove_shortcut()
