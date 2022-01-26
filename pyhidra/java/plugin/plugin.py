import contextlib
import itertools
import rlcompleter
import sys
import threading
from code import InteractiveConsole

from ghidra.app.plugin.core.console import CodeCompletion
from ghidra.app.plugin.core.interpreter import InterpreterConnection, InterpreterPanelService
from ghidra.util.task import DummyCancellableTaskMonitor
from java.io import BufferedReader, InputStreamReader, PushbackReader
from java.lang import ClassLoader, Runnable, String
from java.util.function import Consumer
from jpype import JClass, JImplements, JOverride
from resources import ResourceManager
from utility.function import Callback

from pyhidra.java.plugin.completions import PythonCodeCompleter
from pyhidra.script import PyGhidraScript


def _set_field(cls, fname, value, obj=None):
    cls = cls.class_
    field = cls.getDeclaredField(fname)
    field.setAccessible(True)
    field.set(obj, value)
    field.setAccessible(False)


def _run_script(script):
    PyGhidraScript(script).run()


class PyConsole(InteractiveConsole):
    """
    Pyhidra Interactive Console
    """

    def __init__(self, py_plugin) -> None:
        super().__init__(locals=PyGhidraScript(py_plugin.script))
        self._plugin = py_plugin
        console = py_plugin.service.createInterpreterPanel(py_plugin, False)
        self._console = console
        self._reader = PushbackReader(InputStreamReader(console.getStdin()))
        self._line_reader = BufferedReader(self._reader)
        self._out = console.getOutWriter()
        self._err = console.getErrWriter()
        self._writer = self._out
        self._thread = None
        state = self.locals._script.getState()
        self.locals._script.set(state, DummyCancellableTaskMonitor(), console.getOutWriter())
        console.addFirstActivationCallback(Callback @ self.interact)

    def interact(self, banner=None, exitmsg=None):
        from ghidra.framework import Application
        version = Application.getApplicationVersion()
        name = Application.getApplicationReleaseName()
        banner = f"Python Interpreter for Ghidra {version} {name}\n"
        banner += f"Python {sys.version} on {sys.platform}"
        target = super().interact
        targs = {'banner': banner}
        self._thread = threading.Thread(target=target, name="Interpreter", kwargs=targs)
        self._thread.start()

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
        self._console.dispose()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join()

    def showsyntaxerror(self, filename=None):
        self._writer = self._err
        super().showsyntaxerror(filename=filename)
        self._writer = self._out

    def showtraceback(self) -> None:
        self._writer = self._err
        super().showtraceback()
        self._writer = self._out

    @contextlib.contextmanager
    def _run_context(self):
        transaction = -1
        success = False
        program = self._plugin.program
        if program is not None:
            transaction = program.startTransaction("Python command")
        try:
            with contextlib.redirect_stdout(self._out), contextlib.redirect_stderr(self._err):
                yield
                success = True
        finally:
            if transaction != -1:
                program = self._plugin.program
                if program is not None:
                    program.endTransaction(transaction, success)

    def runcode(self, code):
        with self._run_context():
            super().runcode(code)
        self._out.flush()
        self._err.flush()


@JImplements(InterpreterConnection)
class PyPhidraPlugin:
    """
    The Python side PyhidraPlugin
    """

    # pylint: disable=missing-function-docstring, invalid-name

    def __init__(self, plugin):
        if hasattr(self, '_plugin'):
            # this gets entered twice for some reason
            return
        self._plugin = plugin
        gcl = ClassLoader.getSystemClassLoader()
        plugin_cls = JClass("dc3.pyhidra.plugin.PyhidraPlugin", loader=gcl)
        _set_field(plugin_cls, "finalizer", Runnable @ self.dispose, plugin)
        self.console = PyConsole(self)
        self.completer = PythonCodeCompleter(self.console)

    @staticmethod
    def register():
        gcl = ClassLoader.getSystemClassLoader()
        plugin = JClass("dc3.pyhidra.plugin.PyhidraPlugin", loader=gcl)
        provider = JClass("dc3.pyhidra.plugin.PyScriptProvider", loader=gcl)
        _set_field(plugin, "initializer", Consumer @ PyPhidraPlugin)
        _set_field(provider, "scriptRunner", Consumer @ _run_script)

    def _set_plugin(self, plugin):
        self._plugin = plugin

    def dispose(self):
        """
        Release the plugin resources
        """
        self.console.dispose()

    def _gen_completions(self, cmd: str):
        completer = rlcompleter.Completer(namespace=self)
        for state in itertools.count():
            completion = completer.complete(cmd, state)
            if completion is None:
                break
            yield CodeCompletion(cmd, completion, None)

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
    def getCompletions(self, cmd: str):
        return self.completer.get_completions(cmd)

    @JOverride
    def getIcon(self):
        return ResourceManager.loadImage("images/python.png")

    @JOverride
    def getTitle(self):
        return "Pyhidra"
