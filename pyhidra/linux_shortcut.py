import os
import shlex
import sys
import sysconfig
from pathlib import Path

desktop_entry = """\
[Desktop Entry]
Name=Ghidra (pyhidra)
Comment=Ghidra Software Reverse Engineering Suite (pyhidra launcher)
Type=Application
Categories=Application;Development;
Terminal=false
StartupNotify=true
StartupWMClass=ghidra-Ghidra
Icon={icon}
Exec={exec}
"""

desktop_path = Path(os.environ.get("XDG_DATA_HOME", "~/.local/share")).expanduser() / "applications" / "pyhidra.desktop"


def extract_png(install_dir: Path) -> Path:
    """Extracts the png image from the given install path."""
    ico_path = install_dir / "support" / "ghidra.ico"
    png_path = ico_path.with_suffix(".png")
    if png_path.exists():
        return png_path

    data = ico_path.read_bytes()
    magic = data.find(b"\x89PNG")
    if magic == -1:
        sys.exit("Could not find magic number")
    png_path.write_bytes(data[magic:])
    return png_path


def create_shortcut(install_dir: Path = None):
    """Install a desktop entry on Linux machine."""
    pyhidra_exec = Path(sysconfig.get_path("scripts")) / "pyhidra"
    if not pyhidra_exec.exists():
        sys.exit("pyhidra executable is not installed.")

    command = [str(pyhidra_exec), "--gui"]
    if install_dir:
        command += ["--install-dir", str(install_dir.expanduser())]
    elif install_dir := os.environ.get("GHIDRA_INSTALL_DIR"):
        install_dir = Path(install_dir)
    else:
        sys.exit(
            "Unable to determine Ghidra installation directory. "
            "Please set the GHIDRA_INSTALL_DIR environment variable."
        )

    icon = extract_png(install_dir)
    desktop_path.write_text(desktop_entry.format(icon=icon, exec=shlex.join(command)))
    print(f"Installed {desktop_path}")


def remove_shortcut():
    if desktop_path.exists():
        desktop_path.unlink()
        print(f"Removed {desktop_path}")
