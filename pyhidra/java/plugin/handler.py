from pathlib import Path

from java.lang import ClassLoader
from utility.application import ApplicationLayout

from pyhidra.java.plugin.plugin import PyPhidraPlugin
from pyhidra.javac import java_compile
from pyhidra.version import get_current_application, ExtensionDetails



PACKAGE = "dc3.pyhidra.plugin"
PLUGIN_NAME = "pyhidra"


def _get_extension_details(layout: ApplicationLayout):
    return ExtensionDetails(
        PLUGIN_NAME,
        "Native Python Plugin",
        "Department of Defense Cyber Crime Center (DC3)",
        "",
        layout.getApplicationProperties().getApplicationVersion()
    )


def install():
    """
    Install the plugin in Ghidra
    """
    path = get_current_application().extension_path / "pyhidra"
    ext = path / "extension.properties"
    manifest = path / "Module.manifest"
    if not manifest.exists():
        jar_path = path / "lib" / (PLUGIN_NAME + ".jar")
        java_compile(Path(__file__).parent.parent, jar_path)
        ClassLoader.getSystemClassLoader().addPath(jar_path.absolute())

    if not manifest.exists():
        ext.write_text(str(ExtensionDetails()))
        # required empty file, might be usable for version control in the future
        manifest.touch()

    PyPhidraPlugin.register()
