from base64 import b64encode
from functools import cached_property
from hashlib import sha1, sha256
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory

from pyhidra.linux_shortcut import extract_png


applications = Path("~/Applications").expanduser()


class AppBuilder:
    
    APP_NAME = "Ghidra (pyhidra).app"
    ICON_NAME = "ghidra.icns"
    
    def __init__(self, install_dir: Path):
        self._tmpdir = TemporaryDirectory()
        self.tmpdir = Path(self._tmpdir.name)
        self.install_dir = install_dir
    
    @property
    def desktop_path(self) -> Path:
        app_dir = applications
        app_dir.mkdir(exist_ok=True)
        return app_dir / self.APP_NAME

    @cached_property
    def contents(self) -> Path:
        return self.tmpdir / self.APP_NAME / "Contents"
    
    @cached_property
    def icon_path(self) -> Path:
        return self.contents / "Resources" / self.ICON_NAME
    
    def create_icon(self):
        icon_dir = self.tmpdir / "ghidra.iconset"
        icon_dir.mkdir()
        extract_png(self.install_dir).rename(icon_dir / "icon_256x256.png")
        cmd = ["/usr/bin/iconutil", "--convert", "icns", "ghidra.iconset"]
        subprocess.check_call(cmd, cwd=self.tmpdir)
        resources = self.contents / "Resources"
        resources.mkdir(parents=True)
        icon = self.tmpdir / self.ICON_NAME
        icon.rename(self.icon_path)
    
    def create_code_resources(self):
        icon_data = self.icon_path.read_bytes()
        hash1 = b64encode(sha1(icon_data).digest()).decode("utf-8")
        hash2 = b64encode(sha256(icon_data).digest()).decode("utf-8")
        sigdir = self.contents / "_CodeSignature"
        sigdir.mkdir(parents=True)
        code_resources = sigdir / "CodeResources"
        data = CODE_RESOURCES.format(hash1=hash1, hash2=hash2)
        code_resources.write_text(data, encoding="utf-8")
    
    def create_info_plist(self):
        info_plist = self.contents / "Info.plist"
        data = INFO_PLIST.format(install_dir=self.install_dir)
        info_plist.write_text(data, encoding="utf-8")
    
    def create_exe(self):
        exe_dir = self.contents / "MacOS"
        exe_dir.mkdir(parents=True)
        script_path = exe_dir / "pyhidra"

        # NOTE: using sys.executable allows venv to work properly
        data = PYHIDRA_SCRIPT.format(python=sys.executable)
        script_path.write_text(data, encoding="utf-8")
        
        # chmod +x
        mode = script_path.stat().st_mode | stat.S_IXUSR
        script_path.chmod(mode)
    
    def move(self):
        # remove the existing one first if present
        if self.desktop_path.exists():
            shutil.rmtree(self.desktop_path)
        app_dir = self.tmpdir / self.APP_NAME
        app_dir.rename(self.desktop_path)
    
    def __enter__(self):
        self._tmpdir.__enter__()
        return self
    
    def __exit__(self, *args):
        return self._tmpdir.__exit__(*args)


def create_shortcut(install_dir: Path = None):
    """Install a desktop entry on Mac machine."""
    if install_dir is None:
        install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir is None:
        sys.exit(
            "Unable to determine Ghidra installation directory. "
            "Please set the GHIDRA_INSTALL_DIR environment variable."
        )
    install_dir = Path(install_dir)

    with AppBuilder(install_dir) as builder:
        builder.create_icon()
        builder.create_code_resources()
        builder.create_info_plist()
        builder.create_exe()
        builder.move()


def remove_shortcut():
    desktop_path = applications / AppBuilder.APP_NAME
    if desktop_path.exists():
        shutil.rmtree(desktop_path)
        print(f"Removed {desktop_path}")


CODE_RESOURCES = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>files</key>
	<dict>
		<key>Resources/ghidra.icns</key>
		<data>
		{hash1}
		</data>
	</dict>
	<key>files2</key>
	<dict>
		<key>Resources/ghidra.icns</key>
		<dict>
			<key>hash</key>
			<data>
			{hash1}
			</data>
			<key>hash2</key>
			<data>
			{hash2}
			</data>
		</dict>
	</dict>
</dict>
</plist>
"""

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>pyhidra</string>
	<key>CFBundleGetInfoString</key>
	<string>Ghidra (pyhidra)</string>
	<key>CFBundleIconFile</key>
	<string>ghidra.icns</string>
	<key>CFBundleIdentifier</key>
	<string>ghidra.Ghidra</string>
	<key>CFBundleName</key>
	<string>Ghidra</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>LSEnvironment</key>
	<dict>
		<key>GHIDRA_INSTALL_DIR</key>
		<string>{install_dir}</string>
	</dict>
	<key>LSMultipleInstancesProhibited</key>
	<true/>
</dict>
</plist>
"""

PYHIDRA_SCRIPT = """#!{python}
# -*- coding: utf-8 -*-
import pyhidra.gui


if __name__ == '__main__':
    pyhidra.gui.gui()

"""