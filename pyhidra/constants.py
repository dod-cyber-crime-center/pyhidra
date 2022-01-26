import os
import pathlib

GHIDRA_INSTALL_DIR = pathlib.Path(os.environ["GHIDRA_INSTALL_DIR"])
LAUNCH_PROPERTIES = GHIDRA_INSTALL_DIR / "support" / "launch.properties"
UTILITY_JAR = GHIDRA_INSTALL_DIR / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
LAUNCHSUPPORT = GHIDRA_INSTALL_DIR / "support" / "LaunchSupport.jar"
