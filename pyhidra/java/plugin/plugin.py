import contextlib
import ctypes
import enum
import logging
import re
import sys
import threading
from code import InteractiveConsole

from ghidra.app.plugin.core.interpreter import InterpreterConsole, InterpreterPanelService
from ghidra.framework import Application
from ghidra.util.task import CancelledListener
from java.io import BufferedReader, InputStreamReader, PushbackReader
from java.lang import ClassLoader, Runnable, String
from java.util import Collections
from java.util.function import Consumer
from jpype import JClass, JImplements, JOverride
from resources import ResourceManager

from pyhidra.java.plugin.completions import PythonCodeCompleter
from pyhidra.script import PyGhidraScript


logger = logging.getLogger(__name__)


def _get_private_class(path: str) -> JClass:
    gcl = ClassLoader.getSystemClassLoader()
    return JClass(path, loader=gcl)


def _get_plugin_class() -> JClass:
    return _get_private_class("dc3.pyhidra.plugin.PyhidraPlugin")


def _get_provider_class() -> JClass:
    return _get_private_class("dc3.pyhidra.plugin.PyScriptProvider")


def _get_interpreter_class() -> JClass:
    return _get_private_class("dc3.pyhidra.plugin.interpreter.PyhidraInterpreterConnection")


def _set_field(cls, fname, value, obj=None):
    cls = cls.class_
    field = cls.getDeclaredField(fname)
    field.setAccessible(True)
    field.set(obj, value)


def _run_script(script):
    PyGhidraScript(script).run()


@JImplements(CancelledListener)
class InterpreterCanceller:

    def __init__(self, thread):
        self._thread = thread

    @JOverride
    def cancelled(self):
        if self._thread is not None and self._thread.is_alive():
            # raise a KeyboardInterrupt in the interpreter thread
            exc = ctypes.py_object(KeyboardInterrupt)
            ctypes.pythonapi.PyThreadState_SetAsyncExc(self._thread.ident, exc)


class ConsoleState(enum.Enum):
    DISPOSING = enum.auto()
    RUNNING = enum.auto()
    RESET = enum.auto()


class PyConsole(InteractiveConsole):
    """
    Pyhidra Interactive Console
    """

    def __init__(self, py_plugin: "PyPhidraPlugin"):
        super().__init__(locals=PyGhidraScript(py_plugin.script))
        appVersion = Application.getApplicationVersion()
        appName = Application.getApplicationReleaseName()
        self.banner = f"Python Interpreter for Ghidra {appVersion} {appName}\n"
        self.banner += f"Python {sys.version} on {sys.platform}"
        self._plugin = py_plugin
        console = py_plugin.service.createInterpreterPanel(py_plugin, False)
        self._console = console
        self._reader = PushbackReader(InputStreamReader(console.getStdin()))
        self._line_reader = BufferedReader(self._reader)
        self._out = console.getOutWriter()
        self._err = console.getErrWriter()
        self._writer = self._out
        self._thread = None
        self._interact_thread = None
        self._script = self.locals._script
        state = self._script.getState()
        self._script.set(state, self._out)
        self._canceller = None
        self._state = ConsoleState.RESET

    def raw_input(self, prompt=''):
        self._console.setPrompt(prompt)
        c = self._reader.read()
        if c == -1:
            raise EOFError
        if c == ord('\n'):
            return '\n'
        self._reader.unread(c)
        return self._line_reader.readLine()

    def write(self, data: str):
        self._writer.write(String @ data)
        self._writer.flush()

    def dispose(self):
        """
        Release the console resources
        """
        self._state = ConsoleState.DISPOSING
        self.close()
        self._interact_thread.join(timeout=10.0)
        self._interact_thread = None
        self._console.dispose()

    def close(self):
        if self._canceller:
            self._script.monitor.removeCancelledListener(self._canceller)
            self._canceller = None
        if self._thread is not None and self._thread.is_alive():
            # raise a SystemExit in the interpreter thread once it resumes
            # this will force this thread, and only this thread, to begin
            # cleanup routines, __exit__ functions, finalizers, etc. and exit
            exc = ctypes.py_object(SystemExit)
            ctypes.pythonapi.PyThreadState_SetAsyncExc(self._thread.ident, exc)

            # closing stdin will wake up any thread attempting to read from it
            # this is required for the join to complete
            self._console.getStdin().close()

            # if we timeout then io out of our control is blocking it
            # at this point we tried and it will complete properly once it stops blocking
            self._thread.join(timeout=1.0)

            # ditch the locals so the contents may be released
            self.locals = dict()

    def reset(self):
        self._state = ConsoleState.RESET
        self.close()

        # clear any existing output in the window and re-open the console input
        self._console.clear()

        # this resets the locals, and gets a new code compiler
        super().__init__(locals=PyGhidraScript(self._script))

    def restart(self):
        self.reset()
        if not self._interact_thread:
            target = self.interact
            targs = {"banner": self.banner}
            self._interact_thread = threading.Thread(target=target, name="Interpreter", kwargs=targs)
            self._interact_thread.start()
    
    def interact(self, *args, **kwargs):
        while self._state != ConsoleState.DISPOSING:
            # We need a nested thread to handle sys.exit as well as a KeyboardInterrupt which
            # can be injected at anytime. This is the only way to guarentee the interpreter
            # will never be left in a dead state.
            self._thread = threading.Thread(target=super().interact, name="Interpreter", args=args, kwargs=kwargs)
            self._canceller = InterpreterCanceller(self._thread)
            self._script.monitor.addCancelledListener(self._canceller)
            self._state = ConsoleState.RUNNING
            self._thread.start()
            self._thread.join()
            self._thread = None
            self._script.monitor.clearCanceled()
            if self._state == ConsoleState.RUNNING:
                # the user used sys.exit and the thread finished
                # we need to call reset ourselves
                self.reset()
        

    @contextlib.contextmanager
    def redirect_writer(self):
        self._writer = self._err
        try:
            yield
        finally:
            self._writer = self._out

    def showsyntaxerror(self, filename=None):
        with self.redirect_writer():
            super().showsyntaxerror(filename=filename)

    def showtraceback(self) -> None:
        with self.redirect_writer():
            super().showtraceback()

    @contextlib.contextmanager
    def _run_context(self):
        self._script.start()
        success = False
        try:
            # NOTE: redirect stdout to self so we can flush after each write
            with contextlib.redirect_stdout(self), contextlib.redirect_stderr(self._err):
                yield
                success = True
        finally:
            self._script.end(success)

    def runcode(self, code):
        with self._run_context():
            super().runcode(code)
        self._out.flush()
        self._err.flush()


@JImplements("dc3.pyhidra.plugin.interpreter.PyhidraInterpreterConnection")
class PyPhidraPlugin:
    """
    The Python side PyhidraPlugin
    """
    
    _WORD_PATTERN = re.compile(r".*?([\w\.]+)\Z") # get the last word, including '.', from the right

    def __init__(self, plugin):
        if hasattr(self, '_plugin'):
            # this gets entered twice for some reason
            return
        self._plugin = plugin
        self._actions = None
        self._logged_completions_change = False
        plugin_cls = _get_plugin_class()
        _set_field(plugin_cls, "finalizer", Runnable @ self.dispose, plugin)
        self.console = PyConsole(self)
        self.completer = PythonCodeCompleter(self.console)
        _get_interpreter_class().initialize(self)

    @staticmethod
    def register():
        plugin = _get_plugin_class()
        provider = _get_provider_class()
        _set_field(plugin, "initializer", Consumer @ PyPhidraPlugin)
        _set_field(provider, "scriptRunner", Consumer @ _run_script)

    def _set_plugin(self, plugin):
        self._plugin = plugin

    def dispose(self):
        """
        Release the plugin resources
        """
        if self._actions is not None:
            for action in self._actions:
                action.dispose()
        self.console.dispose()

    @property
    def program(self):
        return self._plugin.getCurrentProgram()

    @property
    def script(self):
        return self._plugin.script

    @property
    def service(self):
        return self._plugin.getTool().getService(InterpreterPanelService.class_)

    @JOverride
    def getCompletions(self, *args):
        try:
            if len(args) == 2:
                line, pos = args
                line = line[:pos]
            else:
                # older versions of Ghidra don't have the `end` argument.
                line, = args
            match = self._WORD_PATTERN.match(line)
            if match:
                line = match.group(1)
            return self.completer.get_completions(line)
        except Exception as e:
            if not self._logged_completions_change:
                self._logged_completions_change = True
                logger.exception(e, exc_info=e)
            return Collections.emptyList()

    @JOverride
    def getIcon(self):
        return ResourceManager.loadImage("images/python.png")

    @JOverride
    def getTitle(self):
        return "Pyhidra"

    @JOverride
    def getConsole(self) -> InterpreterConsole:
        return self.console._console

    @JOverride
    def getPlugin(self):
        return self._plugin

    @JOverride
    def close(self):
        self.console.close()

    @JOverride
    def restart(self):
        self.console.restart()

    @JOverride
    def setActions(self, actions):
        if self._actions is not None:
            for action in self._actions:
                action.dispose()
        self._actions = actions
