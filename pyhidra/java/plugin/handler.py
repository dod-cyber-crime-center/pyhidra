import shutil
from pathlib import Path

from ghidra import GhidraLauncher
from pyhidra.java.plugin.plugin import PyPhidraPlugin
from pyhidra.javac import java_compile
from pyhidra.version import get_current_application, ExtensionDetails
from utility.application import ApplicationLayout


PLUGIN_NAME = "pyhidra"
_SCRIPTS_FOLDER = "ghidra_scripts"


def _get_extension_details(layout: ApplicationLayout):
    return ExtensionDetails(
        PLUGIN_NAME,
        "Native Python Plugin",
        "Department of Defense Cyber Crime Center (DC3)",
        "",
        layout.getApplicationProperties().getApplicationVersion()
    )


def install(launcher):
    """
    Install the plugin in Ghidra
    """
    path = get_current_application().extension_path / PLUGIN_NAME
    ext = path / "extension.properties"
    manifest = path / "Module.manifest"
    root = Path(__file__).parent
    if not manifest.exists():
        jar_path = path / "lib" / (PLUGIN_NAME + ".jar")
        java_compile(root.parent, jar_path)

        ext.write_text(str(ExtensionDetails()))

        # required empty file
        manifest.touch()

        shutil.copytree(root / _SCRIPTS_FOLDER, path / _SCRIPTS_FOLDER)

        # "restart" Ghidra
        launcher.layout = GhidraLauncher.initializeGhidraEnvironment()

    PyPhidraPlugin.register()
