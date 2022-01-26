import importlib
import importlib.machinery
import importlib.util
import inspect
import logging
import sys
import traceback
from collections.abc import ItemsView, KeysView
from jpype import JClass, JImplementationFor


_NO_ATTRIBUTE = object()


class _StaticMap(dict):

    __slots__ = ('script',)

    def __init__(self, script: "PyGhidraScript"):
        super().__init__()
        self.script = script

    def __getitem__(self, key):
        res = self.get(key, _NO_ATTRIBUTE)
        if res is not _NO_ATTRIBUTE:
            return res
        raise KeyError(key)

    def get(self, key, default=None):
        res = self.script.get_static(key)
        return res if res is not _NO_ATTRIBUTE else default

    def __iter__(self):
        yield from self.script

    def keys(self):
        return KeysView(self)

    def items(self):
        return ItemsView(self)


class _JavaProperty(property):

    def __init__(self, field):
        super().__init__()
        self._field = field

    def __get__(self, obj, cls):
        return self._field.fget(obj)

    def __set__(self, obj, value):
        self._field.fset(obj, value)


#pylint: disable=too-few-public-methods
@JImplementationFor("dc3.pyhidra.plugin.PythonFieldExposer")
class _PythonFieldExposer:

    #pylint: disable=no-member
    def __jclass_init__(self):
        exposer = JClass("dc3.pyhidra.plugin.PythonFieldExposer")
        if self.class_ == exposer:
            return
        try:
            for k, v in exposer.getProperties(self.class_).items():
                self._customize(k, _JavaProperty(v))
        # allowing any exception to escape here may cause the jvm to terminate
        # pylint: disable=bare-except
        except:
            logger = logging.getLogger(__name__)
            logger.error("Failed to add property customizations for %s", self, exc_info=1)


class _GhidraScriptModule:

    def __init__(self, spec: importlib.machinery.ModuleSpec):
        super().__setattr__("__dict__", spec.loader_state["script"])

    def __setattr__(self, attr, value):
        if hasattr(self, attr):
            raise AttributeError(f"readonly attribute {attr}")
        super().__setattr__(attr, value)


class _GhidraScriptLoader(importlib.machinery.SourceFileLoader):

    def __init__(self, script: "PyGhidraScript", spec: importlib.machinery.ModuleSpec):
        super().__init__(spec.name, spec.origin)
        spec.loader_state = {"script": script}

    def create_module(self, spec: importlib.machinery.ModuleSpec):
        return _GhidraScriptModule(spec)


# pylint: disable=missing-function-docstring
class PyGhidraScript(dict):
    """
    Python GhidraScript Wrapper
    """

    def __init__(self, jobj=None):
        super().__init__()
        if jobj is None:
            jobj = JClass("dc3.pyhidra.plugin.PyScriptProvider").PyhidraHeadlessScript()
        self._script = jobj

        # ensure the builtin set takes priority over GhidraScript.set
        super().__setitem__("set", set)

        # ensure that GhidraScript.print is used for print
        # so the output goes to the expected console
        super().__setitem__("print", self._print_wrapper())

        super().__setitem__("__this__", self._script)

    def _print_wrapper(self):
        def _print(*objects, sep=' ', end='\n', file=None, flush=False):
            if file is None:
                file = self._script.writer
            print(*objects, sep=sep, end=end, file=file, flush=flush)
        _print.__doc__ = print.__doc__
        return _print

    def __missing__(self, k):
        attr = getattr(self._script, k, _NO_ATTRIBUTE)
        if attr is not _NO_ATTRIBUTE:
            return attr
        raise KeyError(k)

    def __setitem__(self, k, v):
        attr = inspect.getattr_static(self._script, k, _NO_ATTRIBUTE)
        if attr is not _NO_ATTRIBUTE and isinstance(attr, property):
            setattr(self._script, k, v)
        else:
            super().__setitem__(k, v)

    def __iter__(self):
        yield from super().__iter__()
        yield from dir(self._script)

    def get_static(self, key):
        res = self.get(key, _NO_ATTRIBUTE)
        if res is not _NO_ATTRIBUTE:
            return res
        return inspect.getattr_static(self._script, key, _NO_ATTRIBUTE)

    def get_static_view(self):
        return _StaticMap(self)

    def set(self, state, monitor, writer):
        """
        see GhidraScript.set
        """
        self._script.set(state, monitor, writer)

    def run(self, script_path: str = None, script_args: list = None):
        """
        Run this GhidraScript

        :param script_path: The path of the python script
        :param script_args: The arguments for the python script
        """
        sf = self._script.getSourceFile()
        if sf is None and script_path is None:
            return
        if script_path is None:
            script_path = sf.getAbsolutePath()
            script_args = self._script.getScriptArgs()

        if script_args is None:
            script_args = []

        orig_argv = sys.argv
        try:
            # Temporarily set command line arguments.
            sys.argv = [script_path] + list(script_args)

            spec = importlib.util.spec_from_file_location('__main__', script_path)
            spec.loader = _GhidraScriptLoader(self, spec)
            m = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(m)
            # pylint: disable=bare-except
            except:
                # filter the traceback so that it stops at the script
                exc_type, exc_value, exc_tb = sys.exc_info()
                i = 0
                tb = traceback.extract_tb(exc_tb)
                for fs in tb:
                    if fs.filename == script_path:
                        break
                    i += 1
                ss = traceback.StackSummary.from_list(tb[i:])
                e = traceback.TracebackException(exc_type, exc_value, exc_tb)
                e.stack = ss
                self._script.printerr(''.join(e.format()))
        finally:
            sys.argv = orig_argv
