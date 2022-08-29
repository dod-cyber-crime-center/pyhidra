import os
import pathlib

if "GHIDRA_INSTALL_DIR" in os.environ:
    GHIDRA_INSTALL_DIR = pathlib.Path(os.environ["GHIDRA_INSTALL_DIR"])
    LAUNCH_PROPERTIES = GHIDRA_INSTALL_DIR / "support" / "launch.properties"
    UTILITY_JAR = GHIDRA_INSTALL_DIR / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    LAUNCHSUPPORT = GHIDRA_INSTALL_DIR / "support" / "LaunchSupport.jar"
else:
    GHIDRA_INSTALL_DIR = None
    LAUNCH_PROPERTIES = None
    UTILITY_JAR = None
    LAUNCHSUPPORT = None
