
from dataclasses import dataclass, asdict, field
import re
from datetime import datetime

from pathlib import Path

from pyhidra import __version__
from pyhidra.constants import GHIDRA_INSTALL_DIR

if GHIDRA_INSTALL_DIR is not None:
    _APPLICATION_PATTERN = re.compile(r"^application\.(\S+?)=(.*)$")
    _APPLICATION_PATH = GHIDRA_INSTALL_DIR / "Ghidra" / "application.properties"


# this is not a NamedTuple as the fields may change
class ApplicationInfo:
    """
    Ghidra Application Properties
    """
    revision_ghidra_src: str = None
    build_date: str = None
    build_date_short: str = None
    name: str
    version: str
    release_name: str
    layout_version: str = None
    gradle_min: str = None
    java_min: str = None
    java_max: str = None
    java_compiler: str = None

    def __init__(self):
        for line in _APPLICATION_PATH.read_text(encoding="utf8").splitlines():
            match = _APPLICATION_PATTERN.match(line)
            if not match:
                continue
            attr = match.group(1).replace('.', '_').replace('-', '_')
            value = match.group(2)
            super().__setattr__(attr, value)

    def __setattr__(self, *attr):
        raise AttributeError(f"cannot assign to field '{attr[0]}'")

    def __delattr__(self, attr):
        raise AttributeError(f"cannot delete field '{attr}'")

    @property
    def extension_path(self) -> Path:
        """
        Path to the user's Ghidra extensions folder
        """
        root = Path.home() / f".{self.name.lower()}"
        return root / f"{root.name}_{self.version}_{self.release_name}" / "Extensions"


_CURRENT_APPLICATION: ApplicationInfo = None
_CURRENT_GHIDRA_VERSION: str = None
MINIMUM_GHIDRA_VERSION = "10.1.1"


def get_current_application() -> ApplicationInfo:
    global _CURRENT_APPLICATION
    if _CURRENT_APPLICATION is None:
        _CURRENT_APPLICATION = ApplicationInfo()
    return _CURRENT_APPLICATION


def get_ghidra_version() -> str:
    global _CURRENT_GHIDRA_VERSION
    if _CURRENT_GHIDRA_VERSION is None:
        _CURRENT_GHIDRA_VERSION = get_current_application().version
    return _CURRENT_GHIDRA_VERSION


@dataclass
class ExtensionDetails:
    """
    Python side ExtensionDetails
    """
    name: str
    description: str
    author: str
    createdOn: str = field(default_factory=lambda: str(datetime.now()))
    version: str = field(default_factory=get_ghidra_version)
    plugin_version: str = "0.0.1"

    @classmethod
    def from_file(cls, ext_path: Path):
        def cast(key, value):
            return cls.__annotations__[key](value)
        lines = ext_path.read_text().splitlines()
        kwargs = {
            key: cast(key, value)
            for key, value in map(lambda l: l.split("="), lines)
            if key in cls.__annotations__
        }
        return cls(**kwargs)

    def __repr__(self):
        return "\n".join(f"{key}={value}" for key, value in asdict(self).items())
