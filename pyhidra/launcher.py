import contextlib
import ctypes
import ctypes.util
import importlib.metadata
import inspect
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from importlib.machinery import ModuleSpec
from pathlib import Path
from typing import List, NoReturn, Tuple, Union

import jpype
from jpype import imports, _jpype
from packaging.version import Version


from . import __version__
from .javac import java_compile
from .script import PyGhidraScript
from .version import ApplicationInfo, ExtensionDetails, MINIMUM_GHIDRA_VERSION

logger = logging.getLogger(__name__)


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


def _get_entry_points(group: str):
    entry_points = importlib.metadata.entry_points()
    if hasattr(entry_points, 'select'):
        return entry_points.select(group=group)
    return entry_points.get(group, tuple())


def _load_entry_points(group: str, *args):
    """
    Loads any entry point callbacks registered by external python packages.
    """
    entries = set()
    entries.update(_get_entry_points("pyghidra." + group))
    entries.update(_get_entry_points("pyhidra." + group))

    for entry in entries:
        name = entry.name
        try:
            # Give launcher to callback so they can edit vmargs, install plugins, etc.
            callback = entry.load()
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


@contextlib.contextmanager
def _plugin_lock():
    """
    File lock for processing plugins
    """
    from java.io import RandomAccessFile
    path = Path(tempfile.gettempdir()) / "pyghidra_plugin_lock"
    try:
        # Python doesn't have a file lock except for unix systems
        # so use the one available in Java instead of adding on
        # a third party library
        with RandomAccessFile(str(path), "rw") as fp:
            lock = fp.getChannel().lock()
            try:
                yield
            finally:
                lock.release()
    finally:
        try:
            path.unlink()
        except:
            # if it fails it's ok
            # another pyghidra process has the lock
            # it will be removed by said process when done
            pass


class PyhidraLauncher:
    """
    Base pyhidra launcher
    """

    def __init__(self, verbose=False, *, install_dir: Path = None):
        """
        Initializes a new `PyhidraLauncher`.

        :param verbose: True to enable verbose output when starting Ghidra.
        :param install_dir: Ghidra installation directory.
            (Defaults to the GHIDRA_INSTALL_DIR environment variable)
        :raises ValueError: If the Ghidra installation directory is invalid.
        """
        self._layout = None
        self._java_home = None

        install_dir = install_dir or os.getenv("GHIDRA_INSTALL_DIR")
        self._install_dir = self._validate_install_dir(install_dir)
        self._plugins: List[Tuple[Path, ExtensionDetails]] = []
        self.verbose = verbose

        ghidra_dir = self._install_dir / "Ghidra"
        self.class_path = [str(ghidra_dir / "Framework" / "Utility" / "lib" / "Utility.jar")]
        self.class_files = []
        self.vm_args = self._jvm_args(self._install_dir)
        self.args = []
        self.app_info = ApplicationInfo.from_file(ghidra_dir / "application.properties")

    @classmethod
    def _jvm_args(cls, install_dir: Path) -> List[str]:
        suffix = "_" + platform.system().upper()
        if suffix == "_DARWIN":
            suffix = "_MACOS"
        option_pattern: re.Pattern = re.compile(fr"VMARGS(?:{suffix})?=(.+)")
        properties = []

        launch_properties = install_dir / "support" / "launch.properties"

        with open(launch_properties, "r", encoding='utf-8') as fd:
            # this file is small so just read it at once
            for line in fd.readlines():
                match = option_pattern.match(line)
                if match:
                    arg = match.group(1)
                    name, sep, value = arg.partition('=')
                    # unquote any values because quotes are automatically added during JVM startup
                    if value.startswith('"') and value.endswith('"'):
                        value = value.removeprefix('"').removesuffix('"')
                    properties.append(name + sep + value)
        return properties

    @property
    def extension_path(self) -> Path:
        if not self._layout:
            raise RuntimeError("extension_path cannot be obtained until launcher starts.")
        return Path(self._layout.getUserSettingsDir().getPath()) / "Extensions"

    @property
    def java_home(self) -> Path:
        if not self._java_home:
            launch_support = self.install_dir / "support" / "LaunchSupport.jar"
            if not launch_support.exists():
                raise ValueError(f"{launch_support} does not exist")
            cmd = f'java -cp "{launch_support}" LaunchSupport "{self.install_dir}" -jdk_home -save'
            home = subprocess.check_output(cmd, encoding="utf-8", shell=True)
            self._java_home = Path(home.rstrip())
        return self._java_home

    @java_home.setter
    def java_home(self, path: Path):
        self._java_home = Path(path)

    @property
    def install_dir(self) -> Path:
        return self._install_dir

    @classmethod
    def _validate_install_dir(cls, install_dir: Union[Path, str]) -> Path:
        """
        Validates and sets the Ghidra installation directory.
        """
        if not install_dir:
            msg = (
                "Please set the GHIDRA_INSTALL_DIR environment variable "
                "or `install_dir` during the Launcher construction to the "
                "directory where Ghidra is installed."
            )
            cls._report_fatal_error("GHIDRA_INSTALL_DIR is not set", msg, ValueError(msg))

        # both the directory and the application.properties file must exist
        install_dir = Path(install_dir)
        if not install_dir.exists():
            msg = f"{install_dir} does not exist"
            cls._report_fatal_error("Invalid Ghidra Installation Directory", msg, ValueError(msg))

        path = install_dir / "Ghidra" / "application.properties"
        if not path.exists():
            msg = "The Ghidra installation does not contain the required " + \
                  "application.properties file"
            cls._report_fatal_error("Corrupt Ghidra Installation", msg, ValueError(msg))

        return install_dir

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
    def _report_fatal_error(cls, title: str, msg: str, cause: Exception) -> NoReturn:
        logger.error("%s: %s", title, msg)
        raise cause

    def check_ghidra_version(self):
        """
        Checks if the currently installed Ghidra version is supported.
        The launcher will report the problem and terminate if it is not supported.
        """
        if Version(self.app_info.version) < Version(MINIMUM_GHIDRA_VERSION):
            msg = f"Ghidra version {self.app_info.version} is not supported" + os.linesep + \
                  f"The minimum required version is {MINIMUM_GHIDRA_VERSION}"
            self._report_fatal_error("Unsupported Version", msg, ValueError(msg))

    def _install_pyhidra_plugin(self, source_path: Path, details: ExtensionDetails):
        # cross compatibility hacks
        with tempfile.TemporaryDirectory() as out:
            outdir = Path(out).resolve()
            plugindir = outdir / "plugin"
            shutil.copytree(source_path, outdir, dirs_exist_ok=True)
            if Version(self.app_info.version) < Version("11.2"):
                target = plugindir / "PyScriptProviderOld.java"
                invalid = plugindir / "PyScriptProviderNew.java"
            else:
                target = plugindir / "PyScriptProviderNew.java"
                invalid = plugindir / "PyScriptProviderOld.java"
            target.rename(target.with_name("PyScriptProvider.java"))
            invalid.unlink()
            return self._install_plugin(outdir, details)

    def _setup_java(self, **jpype_kwargs):
        """
        Run setup entry points, start the JVM and prepare ghidra imports
        """
        # Before starting up, give launcher to installed entry points so they can do their thing.
        _load_entry_points("setup", self)

        # Merge classpath
        jpype_kwargs['classpath'] = self.class_path + jpype_kwargs.get('classpath', [])

        # force convert strings (required by pyhidra)
        jpype_kwargs['convertStrings'] = True

        # set the JAVA_HOME environment variable to the correct one so jpype uses it
        os.environ['JAVA_HOME'] = str(self.java_home)

        jpype.startJVM(
            None, # indicates to use JAVA_HOME as the jvm path
            *self.vm_args,
            **jpype_kwargs
        )

        # Install hook into python importlib
        sys.meta_path.append(_PyhidraImportLoader())

        imports.registerDomain("ghidra")

    def _pre_launch_init(self):
        pyhidra_details = ExtensionDetails(
            name="pyhidra",
            description="Native Python Plugin",
            author="Department of Defense Cyber Crime Center (DC3)",
            plugin_version=__version__,
            version=self.app_info.version
        )

        # import and create a temporary GhidraApplicationLayout this can be
        # used without initializing Ghidra to obtain the correct Extension path
        from ghidra import GhidraApplicationLayout
        self._layout = GhidraApplicationLayout()

        # uninstall any outdated plugins before initializing Ghidra to ensure they are loaded correctly
        self._uninstall_old_plugin(pyhidra_details)

        for _, details in self._plugins:
            try:
                self._uninstall_old_plugin(details)
            except:
                logger.warning("failed to uninstall plugin %s", details.name)


        from ghidra import GhidraLauncher
        self._layout = GhidraLauncher.initializeGhidraEnvironment()

        # install the Pyhidra plugin.
        from pyhidra.java import plugin
        java_root = Path(plugin.__file__).parent.parent
        needs_reload = self._install_pyhidra_plugin(java_root, pyhidra_details)

        if needs_reload:
            # "restart" Ghidra
            self._layout = GhidraLauncher.initializeGhidraEnvironment()
            needs_reload = False

        from java.lang import System

        # manually check the classpath for the pyhidra plugin to
        # help diagnose confusing errors (GH #31)
        # this will help in the future too if Extensions are ever moved outside
        # of the Ghidra user settings directory
        jar_path = self._get_plugin_jar_path("pyhidra")

        # NOTE: be very careful not to cause an exception here because there will be
        # no indication of a problem in GUI mode unless started with pyhidra -g -v

        CLASSPATH_PROPERTY = "java.class.path"
        classpath = System.getProperty(CLASSPATH_PROPERTY)
        if classpath is None:
            # this is impossible but a helpful message is
            # better than "'NoneType' object hsas no attribute 'split'"
            msg = f"Required Java property {CLASSPATH_PROPERTY} not found"
            self._report_fatal_error(f"No Classpath", msg, RuntimeError(msg))

        # ensure it is a Python string (not Java string) and then split the classpath
        classpath = str(classpath).split(os.pathsep)
        if str(jar_path) not in classpath:
            title = "Classpath Setup Error"
            msg = "Pyhidra plugin is not in the system classpath"
            # Ghidra uses this property depending on JVM configuration
            ext_classpath = System.getProperty("java.class.path.ext")
            if ext_classpath is None:
                logger.debug("plugin path: %s\nclasspath: %s", jar_path, '\n'.join(classpath))
                self._report_fatal_error(title, msg, RuntimeError(msg))
            classpath = str(ext_classpath).split(os.pathsep)
            if str(jar_path) not in classpath:
                logger.debug("plugin path: %s\nclasspath: %s", jar_path, '\n'.join(classpath))
                self._report_fatal_error(title, msg, RuntimeError(msg))

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
            try:
                needs_reload = self._install_plugin(source_path, details) or needs_reload
            except Exception as e:
                # we should always warn if a plugin failed to compile
                logger.warning(e, exc_info=e)

        if needs_reload:
            # "restart" Ghidra
            self._layout = GhidraLauncher.initializeGhidraEnvironment()

        # import properties to register the property customizer
        from . import properties as _

        _load_entry_points("pre_launch")

    def start(self, **jpype_kwargs):
        """
        Starts Jpype connection to Ghidra (if not already started).
        """
        if jpype.isJVMStarted():
            return

        self.check_ghidra_version()

        try:
            self._setup_java(**jpype_kwargs)
            with _plugin_lock():
                self._pre_launch_init()
            self._launch()
        except Exception as e:
            self._report_fatal_error("An error occured launching Ghidra", str(e), e)

    def get_install_path(self, plugin_name: str) -> Path:
        """
        Obtains the path for installation of a given plugin.
        """
        return self.extension_path / plugin_name

    def _get_plugin_jar_path(self, plugin_name: str) -> Path:
        return self.get_install_path(plugin_name) / "lib" / (plugin_name + ".jar")

    def uninstall_plugin(self, plugin_name: str):
        """
        Uninstalls given plugin.
        """
        path = self.get_install_path(plugin_name)
        if path.exists():
            # delete the existing extension so it will be up-to-date
            try:
                shutil.rmtree(path)
            except Exception as e:
                self._report_fatal_error(
                    "Plugin Update Failed",
                    f"Could not delete existing plugin at\n{path}",
                    e
                )

    def _uninstall_old_plugin(self, details: ExtensionDetails):
        """
        Automatically uninstalls an outdated plugin if it exists.
        """
        plugin_name = details.name
        path = self.get_install_path(plugin_name)
        ext = path / "extension.properties"

        # Uninstall old version.
        if path.exists() and ext.exists():
            orig_details = ExtensionDetails.from_file(ext)
            if not orig_details.plugin_version or orig_details.plugin_version != details.plugin_version:
                self.uninstall_plugin(plugin_name)
                logger.info(f"Uninstalled older plugin: {plugin_name} {orig_details.plugin_version}")

    def _install_plugin(self, source_path: Path, details: ExtensionDetails):
        """
        Compiles and installs a Ghidra extension if not already installed.
        """
        if details.version is None:
            details.version = self.app_info.version
        plugin_name = details.name
        path = self.get_install_path(plugin_name)
        ext = path / "extension.properties"
        manifest = path / "Module.manifest"
        root = source_path
        jar_path = path / "lib" / (plugin_name + ".jar")

        if not jar_path.exists():
            path.mkdir(parents=True, exist_ok=True)

            try:
                java_compile(root, jar_path)
            except:
                shutil.rmtree(path, ignore_errors=True)
                raise

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
                Application.initializeApplication(self._layout, config)
            else:
                GhidraRun().launch(self._layout, self.args)


class HeadlessPyhidraLauncher(PyhidraLauncher):
    """
    Headless pyhidra launcher
    """

    def _launch(self):
        from ghidra.framework import Application, HeadlessGhidraApplicationConfiguration
        with _silence_java_output(not self.verbose, not self.verbose):
            config = HeadlessGhidraApplicationConfiguration()
            Application.initializeApplication(self._layout, config)


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

    @classmethod
    def popup_error(cls, header: str, msg: str) -> NoReturn:
        import tkinter.messagebox
        tkinter.messagebox.showerror(header, msg)
        sys.exit()

    @classmethod
    def _report_fatal_error(cls, title: str, msg: str, cause: Exception) -> NoReturn:
        logger.exception(cause, exc_info=cause)
        cls.popup_error(title, msg)

    @staticmethod
    def _get_thread(name: str):
        from java.lang import Thread
        for t in Thread.getAllStackTraces().keySet():
            if t.getName() == name:
                return t
        return None

    def _launch(self):
        from ghidra import Ghidra
        from java.lang import Runtime, Thread

        if sys.platform == "win32":
            appid = ctypes.c_wchar_p(self.app_info.name)
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(appid)

        stdout = _PyhidraStdOut(sys.stdout)
        stderr = _PyhidraStdOut(sys.stderr)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            Thread(lambda: Ghidra.main(["ghidra.GhidraRun", *self.args])).start()
            is_exiting = threading.Event()
            Runtime.getRuntime().addShutdownHook(Thread(is_exiting.set))
            if sys.platform == "darwin":
                _run_mac_app()
            is_exiting.wait()


def _run_mac_app():
    # this runs the event loop
    # it is required for the GUI to show up
    from ctypes import c_void_p, c_double, c_uint64, c_int64, c_int32, c_bool, CFUNCTYPE

    CoreFoundation = ctypes.cdll.LoadLibrary(ctypes.util.find_library("CoreFoundation"))

    def get_function(name, restype, *argtypes):
        res = getattr(CoreFoundation, name)
        res.argtypes = [arg for arg in argtypes]
        res.restype = restype
        return res

    CFRunLoopTimerCallback = CFUNCTYPE(None, c_void_p, c_void_p)
    kCFRunLoopDefaultMode = c_void_p.in_dll(CoreFoundation, "kCFRunLoopDefaultMode")
    kCFRunLoopRunFinished = c_int32(1)
    NULL = c_void_p(0)
    INF_TIME = c_double(1.0e20)
    FIRE_ONCE = c_double(0)
    kCFAllocatorDefault = NULL

    CFRunLoopGetCurrent = get_function("CFRunLoopGetCurrent", c_void_p)
    CFRelease = get_function("CFRelease", None, c_void_p)

    CFRunLoopTimerCreate = get_function(
        "CFRunLoopTimerCreate",
        c_void_p,
        c_void_p,
        c_double,
        c_double,
        c_uint64,
        c_int64,
        CFRunLoopTimerCallback,
        c_void_p
    )

    CFRunLoopAddTimer = get_function("CFRunLoopAddTimer", None, c_void_p, c_void_p, c_void_p)
    CFRunLoopRunInMode = get_function("CFRunLoopRunInMode", c_int32, c_void_p, c_double, c_bool)

    @CFRunLoopTimerCallback
    def dummy_timer(timer, info):
        # this doesn't need to do anything
        # CFRunLoopTimerCreate just needs a valid callback
        return

    timer = CFRunLoopTimerCreate(kCFAllocatorDefault, INF_TIME, FIRE_ONCE, 0, 0, dummy_timer, NULL)
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode)
    CFRelease(timer)

    while CFRunLoopRunInMode(kCFRunLoopDefaultMode, INF_TIME, False) != kCFRunLoopRunFinished:
        pass
