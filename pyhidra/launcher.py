import contextlib
import importlib.metadata
import inspect
import logging
import platform
import re
import shutil
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from typing import NoReturn

import jpype
from jpype import imports, _jpype
from importlib.machinery import ModuleSpec

from . import __version__
from .constants import LAUNCH_PROPERTIES, LAUNCHSUPPORT, GHIDRA_INSTALL_DIR, UTILITY_JAR
from .javac import java_compile
from .script import PyGhidraScript
from .version import get_current_application, get_ghidra_version, MINIMUM_GHIDRA_VERSION, \
    ExtensionDetails


logger = logging.getLogger(__name__)


_GET_JAVA_HOME = f'java -cp "{LAUNCHSUPPORT}" LaunchSupport "{GHIDRA_INSTALL_DIR}" -jdk_home -save'


def _jvm_args():
    suffix = "_" + platform.system().upper()
    option_pattern: re.Pattern = re.compile(fr"VMARGS(?:{suffix})?=(.+)")
    properties = []

    if GHIDRA_INSTALL_DIR is None:
        # reported in the launcher so it is displayed properly when using the gui_script
        return None

    with open(LAUNCH_PROPERTIES, "r", encoding='utf-8') as fd:
        # this file is small so just read it at once
        for line in fd.readlines():
            match = option_pattern.match(line)
            if match:
                properties.append(match.group(1))

    return properties


@contextlib.contextmanager
def _silence_java_output(stdout=True, stderr=True):
    from java.io import OutputStream, PrintStream
    from java.lang import System
    out = System.out
    err = System.err
    null = PrintStream(OutputStream.nullOutputStream())

    # The user's Java SecurityManager might not allow this
    with contextlib.suppress(jpype.JException):
        if stdout:
            System.setOut(null)
        if stderr:
            System.setErr(null)

    try:
        yield
    finally:
        with contextlib.suppress(jpype.JException):
            System.setOut(out)
            System.setErr(err)


def _get_libjvm_path(java_home: Path) -> Path:
    for p in java_home.glob("*/server/*jvm.*"):
        if p.suffix != ".debuginfo":
            return p


def _load_entry_points(group: str, *args):
    """
    Loads any entry point callbacks registered by external python packages.
    """
    entry_points = importlib.metadata.entry_points()
    if hasattr(entry_points, 'select'):
        entries = entry_points.select(group=group)
    else:
        entries = entry_points.get(group, None)
        if entries is None:
            return

    for entry in entries:
        name = entry.name
        callback = entry.load()
        try:
            # Give launcher to callback so they can edit vmargs, install plugins, etc.
            logger.debug(f"Calling {group} entry point: {name}")
            callback(*args)
        except Exception as e:
            logger.error(f"Failed to run {group} entry point {name} with error: {e}")


class _PyhidraImportLoader:
    """ (internal) Finder hook for importlib to handle Python mod conflicts. """

    def find_spec(self, name, path, target=None):

        # If jvm is not started then there is nothing to find.
        if not _jpype.isStarted():
            return None

        if name.endswith('_') and _jpype.isPackage(name[:-1]):
            return ModuleSpec(name, self)

    def create_module(self, spec):
        return _jpype._JPackage(spec.name[:-1])

    def exec_module(self, fullname):
        pass


class PyhidraLauncher:
    """
    Base pyhidra launcher
    """

    def __init__(self, verbose):
        self._plugins = []
        self.verbose = verbose
        self.java_home = None
        self.class_path = [str(UTILITY_JAR)]
        self.class_files = []
        self.vm_args = _jvm_args()
        self.layout = None
        self.args = []

    def add_classpaths(self, *args):
        """
        Add additional entries to the classpath when starting the JVM
        """
        self.class_path += args

    def add_vmargs(self, *args):
        """
        Add additional vmargs for launching the JVM
        """
        self.vm_args += args

    def add_class_files(self, *args):
        """
        Add additional entries to be added the classpath after Ghidra has been fully loaded.
        This ensures that all of Ghidra is available so classes depending on it can be properly loaded.
        """
        self.class_files += args

    @classmethod
    def _report_fatal_error(cls, title: str, msg: str) -> NoReturn:
        sys.exit(f"{title}: {msg}")

    @classmethod
    def check_ghidra_version(cls):
        """
        Checks if the currently installed Ghidra version is supported.
        The launcher will report the problem and terminate if it is not supported.
        """
        if get_ghidra_version() < MINIMUM_GHIDRA_VERSION:
            cls._report_fatal_error(
                "Unsupported Version",
                textwrap.dedent(f"""\
                    Ghidra version {get_ghidra_version()} is not supported
                    The minimum required version is {MINIMUM_GHIDRA_VERSION}
                """).rstrip()
            )

    def start(self, **jpype_kwargs):
        """
        Starts Jpype connection to Ghidra (if not already started).
        """
        if jpype.isJVMStarted():
            return

        if GHIDRA_INSTALL_DIR is None:
            self._report_fatal_error(
                "GHIDRA_INSTALL_DIR is not set",
                textwrap.dedent("""\
                    Please set the GHIDRA_INSTALL_DIR environment variable
                    to the directory where Ghidra is installed
                """).rstrip()
            )

        self.check_ghidra_version()

        # Before starting up, give launcher to installed entry points so they can do their thing.
        _load_entry_points("pyhidra.setup", self)

        if self.java_home is None:
            java_home = subprocess.check_output(_GET_JAVA_HOME, encoding="utf-8", shell=True)
            self.java_home = Path(java_home.rstrip())

        jvm = _get_libjvm_path(self.java_home)

        pyhidra_details = ExtensionDetails(
            name="pyhidra",
            description="Native Python Plugin",
            author="Department of Defense Cyber Crime Center (DC3)",
            plugin_version=__version__,
        )

        # uninstall any outdated plugins before starting the JVM to ensure they are loaded correctly
        self._uninstall_old_plugin(pyhidra_details)

        for _, details in self._plugins:
            self._uninstall_old_plugin(details)

        # Merge classpath
        jpype_kwargs['classpath'] = self.class_path + jpype_kwargs.get('classpath', [])

        # force convert strings (required by pyhidra)
        jpype_kwargs['convertStrings'] = True

        jpype.startJVM(
            str(jvm),
            *self.vm_args,
            **jpype_kwargs
        )

        # Install hook into python importlib
        sys.meta_path.append(_PyhidraImportLoader())

        imports.registerDomain("ghidra")

        from ghidra import GhidraLauncher
        self.layout = GhidraLauncher.initializeGhidraEnvironment()

        # install the Pyhidra plugin.
        from pyhidra.java import plugin
        needs_reload = self._install_plugin(Path(plugin.__file__).parent, pyhidra_details)

        if needs_reload:
            # "restart" Ghidra
            self.layout = GhidraLauncher.initializeGhidraEnvironment()
            needs_reload = False

        # import it at the end so interfaces in our java code may be implemented
        from pyhidra.java.plugin.plugin import PyPhidraPlugin
        PyPhidraPlugin.register()

        # Add extra class paths
        # Do this before installing plugins incase dependencies are needed
        if self.class_files:
            from java.lang import ClassLoader
            gcl = ClassLoader.getSystemClassLoader()
            for path in self.class_files:
                gcl.addPath(path)

        # Install extra plugins.
        for source_path, details in self._plugins:
            needs_reload = self._install_plugin(source_path, details) or needs_reload

        if needs_reload:
            # "restart" Ghidra
            self.layout = GhidraLauncher.initializeGhidraEnvironment()

        # import properties to register the property customizer
        from . import properties as _

        _load_entry_points("pyhidra.pre_launch")

        self._launch()

    def get_install_path(self, plugin_name: str) -> Path:
        """
        Obtains the path for installation of a given plugin.
        """
        return get_current_application().extension_path / plugin_name

    def uninstall_plugin(self, plugin_name: str):
        """
        Uninstalls given plugin.
        """
        path = self.get_install_path(plugin_name)
        if path.exists():
            # delete the existing extension so it will be up-to-date
            try:
                shutil.rmtree(path)
            except:  # pylint: disable=bare-except
                title = "Plugin Update Failed"
                msg = f"Could not delete existing plugin at\n{path}"
                logger.exception(msg)
                self._report_fatal_error(title, msg)

    def _uninstall_old_plugin(self, details: ExtensionDetails):
        """
        Automatically uninstalls an outdated plugin if it exists.
        """
        plugin_name = details.name
        path = self.get_install_path(plugin_name)
        ext = path / "extension.properties"
        manifest = path / "Module.manifest"

        # Uninstall old version.
        if manifest.exists() and ext.exists():
            orig_details = ExtensionDetails.from_file(ext)
            if not orig_details.plugin_version or orig_details.plugin_version != details.plugin_version:
                self.uninstall_plugin(plugin_name)
                logger.info(f"Uninstalled older plugin: {plugin_name} {orig_details.plugin_version}")

    def _install_plugin(self, source_path: Path, details: ExtensionDetails):
        """
        Compiles and installs a Ghidra extension.
        Automatically updates old plugin installation if it exists.
        """
        plugin_name = details.name
        path = self.get_install_path(plugin_name)
        ext = path / "extension.properties"
        manifest = path / "Module.manifest"
        root = source_path

        if not manifest.exists():
            jar_path = path / "lib" / (plugin_name + ".jar")
            java_compile(root.parent, jar_path)

            ext.write_text(str(details))

            # required empty file
            manifest.touch()

            # Copy over ghidra_scripts if included.
            ghidra_scripts = root / "ghidra_scripts"
            if ghidra_scripts.exists():
                shutil.copytree(ghidra_scripts, path / "ghidra_scripts")

            logger.info(f"Installed plugin: {plugin_name} {details.plugin_version}")
            return True

        return False

    def install_plugin(self, source_path: Path, details: ExtensionDetails):
        """
        Compiles and installs a Ghidra extension when launcher is started.
        """
        self._plugins.append((source_path, details))

    def _launch(self):
        pass

    @staticmethod
    def has_launched() -> bool:
        """
        Checks if jpype has started and if Ghidra has been fully initialized.
        """
        if not jpype.isJVMStarted():
            return False

        from ghidra.framework import Application
        return Application.isInitialized()


class DeferredPyhidraLauncher(PyhidraLauncher):
    """
    PyhidraLauncher which allows full Ghidra initialization to be deferred.
    initialize_ghidra must be called before all Ghidra classes are fully available.
    """

    def __init__(self, verbose=False):
        super().__init__(verbose)

    def initialize_ghidra(self, headless=True):
        """
        Finished Ghidra initialization

        :param headless: whether or not to initialize Ghidra in headless mode.
            (Defaults to True)
        """
        from ghidra import GhidraRun
        from ghidra.framework import Application, HeadlessGhidraApplicationConfiguration
        with _silence_java_output(not self.verbose, not self.verbose):
            if headless:
                config = HeadlessGhidraApplicationConfiguration()
                Application.initializeApplication(self.layout, config)
            else:
                GhidraRun().launch(self.layout, self.args)


class HeadlessPyhidraLauncher(PyhidraLauncher):
    """
    Headless pyhidra launcher
    """

    def __init__(self, verbose=False):
        super().__init__(verbose)

    def _launch(self):
        from ghidra.framework import Application, HeadlessGhidraApplicationConfiguration
        with _silence_java_output(not self.verbose, not self.verbose):
            config = HeadlessGhidraApplicationConfiguration()
            Application.initializeApplication(self.layout, config)


def _popup_error(header: str, msg: str) -> NoReturn:
    import tkinter.messagebox
    tkinter.messagebox.showerror(header, msg)
    sys.exit(msg)


class _PyhidraStdOut:

    def __init__(self, stream):
        self._stream = stream

    def _get_current_script(self) -> "PyGhidraScript":
        for entry in inspect.stack():
            f_globals = entry.frame.f_globals
            if isinstance(f_globals, PyGhidraScript):
                return f_globals

    def flush(self):
        script = self._get_current_script()
        if script is not None:
            writer = script._script.writer
            if writer is not None:
                writer.flush()
                return

        self._stream.flush()

    def write(self, s: str) -> int:
        script = self._get_current_script()
        if script is not None:
            writer = script._script.writer
            if writer is not None:
                writer.write(s)
                return len(s)

        return self._stream.write(s)


class GuiPyhidraLauncher(PyhidraLauncher):
    """
    GUI pyhidra launcher
    """

    def __init__(self, verbose=False):
        super().__init__(verbose)

    @classmethod
    def _report_fatal_error(cls, title: str, msg: str) -> NoReturn:
        _popup_error(title, msg)

    @staticmethod
    def _get_thread(name: str):
        from java.lang import Thread
        for t in Thread.getAllStackTraces().keySet():
            if t.getName() == name:
                return t
        return None

    def _launch(self):
        import ctypes
        from ghidra import GhidraRun
        from java.lang import Runtime, Thread

        if sys.platform == "win32":
            appid = ctypes.c_wchar_p(get_current_application().name)
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(appid)

        stdout = _PyhidraStdOut(sys.stdout)
        stderr = _PyhidraStdOut(sys.stderr)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            jpype.setupGuiEnvironment(lambda: GhidraRun().launch(self.layout, self.args))
            is_exiting = threading.Event()
            Runtime.getRuntime().addShutdownHook(Thread(is_exiting.set))
            try:
                is_exiting.wait()
            finally:
                jpype.shutdownGuiEnvironment()
