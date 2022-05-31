import contextlib
import logging
import platform
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import NoReturn

import jpype
from jpype import imports

from . import __version__
from .constants import LAUNCH_PROPERTIES, LAUNCHSUPPORT, GHIDRA_INSTALL_DIR, UTILITY_JAR
from .version import get_current_application, get_ghidra_version, MINIMUM_GHIDRA_VERSION, \
    ExtensionDetails


_GET_JAVA_HOME = f'java -cp "{LAUNCHSUPPORT}" LaunchSupport "{GHIDRA_INSTALL_DIR}" -jdk_home -save'


def _jvm_args():
    suffix = "_" + platform.system().upper()
    option_pattern: re.Pattern = re.compile(fr"VMARGS(?:{suffix})?=(.+)")
    properties = []
    with open(LAUNCH_PROPERTIES, "r", encoding='utf-8') as fd:
        # this file is small so just read it at once
        for line in fd.readlines():
            match = option_pattern.match(line)
            if match:
                properties.append(match.group(1))

    # even though ignoreUnrecognized is True when starting the VM this is still needed
    properties.insert(0, "-XX:+IgnoreUnrecognizedVMOptions")

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


class PyhidraLauncher:
    """
    Base pyhidra launcher
    """

    def __init__(self, verbose):
        self.verbose = verbose
        self.java_home = None
        self.class_path = [str(UTILITY_JAR)]
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

    @classmethod
    def _report_fatal_error(cls, title: str, msg: str) -> NoReturn:
        sys.exit(f"{title}: {msg}")

    @classmethod
    def _update(cls):
        ext = get_current_application().extension_path / "pyhidra" / "extension.properties"
        if ext.exists():
            details = ExtensionDetails(ext)
            if details.pyhidra < __version__:
                # delete the existing extension so it will be up-to-date
                try:
                    shutil.rmtree(ext.parent)
                except:  # pylint: disable=bare-except
                    title = "Plugin Update Failed"
                    msg = f"Could not delete existing plugin at\n{ext.parent}"
                    logging.exception(msg)
                    cls._report_fatal_error(title, msg)

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

    def start(self):
        """
        Starts Jpype connection to Ghidra (if not already started).
        """
        if not jpype.isJVMStarted():

            self.check_ghidra_version()

            if self.java_home is None:
                java_home = subprocess.check_output(_GET_JAVA_HOME, encoding="utf-8", shell=True)
                self.java_home = Path(java_home.rstrip())

            jvm = _get_libjvm_path(self.java_home)

            jpype.startJVM(
                str(jvm),
                *self.vm_args,
                ignoreUnrecognized=True,
                convertStrings=True,
                classpath=self.class_path
            )
            imports.registerDomain("ghidra")

            from ghidra import GhidraLauncher

            self._update()

            self.layout = GhidraLauncher.initializeGhidraEnvironment()

            from pyhidra.java.plugin import install

            install()

            # import properties to register the property customizer
            from . import properties as _

            self._launch()

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

        if sys.platform == "win32":
            appid = ctypes.c_wchar_p(get_current_application().name)
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(appid)
        jpype.setupGuiEnvironment(lambda: GhidraRun().launch(self.layout, self.args))
        try:
            t = GuiPyhidraLauncher._get_thread("main")
            if t is not None:
                try:
                    t.join()
                except RuntimeError as e:
                    if "java.lang.InterruptedException" not in e.args:
                        raise
        finally:
            jpype.shutdownGuiEnvironment()
