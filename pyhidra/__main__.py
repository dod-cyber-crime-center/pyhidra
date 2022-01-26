import argparse
import code
import sys
from pathlib import Path

import pyhidra
import pyhidra.gui


def _create_shortcut():
    from pyhidra.win_shortcut import create_shortcut
    create_shortcut(Path(sys.argv[-1]))


def _interpreter(interpreter_globals: dict):
    from ghidra.framework import Application
    version = Application.getApplicationVersion()
    name = Application.getApplicationReleaseName()
    banner = f"Python Interpreter for Ghidra {version} {name}\n"
    banner += f"Python {sys.version} on {sys.platform}"
    code.interact(banner=banner, local=interpreter_globals, exitmsg='')


# pylint: disable=too-few-public-methods
class PyhidraArgs(argparse.Namespace):
    """
    Custom namespace for holding the command line arguments
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.verbose = False
        self.binary_path = None
        self.script_path = None
        self.project_name = None
        self.project_path = None
        self.script_args = []

    def func(self):
        """
        Run script or enter repl
        """
        if self.script_path is not None:
            pyhidra.run_script(
                self.binary_path,
                self.script_path,
                project_location=self.project_path,
                project_name=self.project_name,
                script_args=self.script_args,
                verbose=self.verbose
            )
        elif self.binary_path is not None:
            from .ghidra import _flat_api
            args = self.binary_path, self.project_path, self.project_name, self.verbose
            with _flat_api(*args) as api:
                _interpreter(api)
        else:
            pyhidra.HeadlessPyhidraLauncher(verbose=self.verbose).start()
            _interpreter(globals())


class PathAction(argparse.Action):
    """
    Custom action for handling script and binary paths as positional arguments
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.nargs = '*'
        self.help = "Headless script and/or binary path. "\
            "If neither are provided pyhidra will drop into a repl."
        self.type = Path

    def __call__(self, parser, namespace, values, option_string=None):
        count = 0
        for p in values:
            if p.exists() and p.is_file():
                if p.suffix == ".py":
                    if namespace.script_path is not None:
                        # assume an additional script is meant to be a parameter to the first one
                        break
                    namespace.script_path = p
                else:
                    if namespace.binary_path is not None:
                        if namespace.script_path is None:
                            raise ValueError("binary_path specified multiple times")
                        # assume it is a script parameter
                        break
                    namespace.binary_path = p
                count += 1
            else:
                break
            if count > 1:
                break
        values[:] = values[count:]

def _get_parser():
    parser = argparse.ArgumentParser(prog="pyhidra")
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose output during Ghidra initialization"
    )
    parser.add_argument(
        "-g",
        "--gui",
        action="store_const",
        dest="func",
        const=pyhidra.gui.gui,
        help="Start Ghidra GUI"
    )
    if sys.platform == "win32":
        parser.add_argument(
            "-s",
            "--shortcut",
            action="store_const",
            dest="func",
            const=_create_shortcut,
            help="Creates a shortcut that can be pinned to the taskbar (Windows only)"
        )
    parser.add_argument(
        "script_path | binary_path",
        metavar="script | binary",
        action=PathAction
    )
    parser.add_argument(
        "script_args",
        help="Arguments to be passed to the headless script",
        nargs=argparse.REMAINDER
    )
    parser.add_argument(
        "--project-name",
        type=str,
        dest="project_name",
        metavar="name",
        help="Project name to use. "
        "(defaults to binary filename with \"_ghidra\" suffix if provided else None)"
    )
    parser.add_argument(
        "--project-path",
        type=Path,
        dest="project_path",
        metavar="path",
        help="Location to store project. "
        "(defaults to same directory as binary file if provided else None)"
    )
    return parser


def main():
    """
    pyhidra module main function
    """
    _get_parser().parse_args(namespace=PyhidraArgs()).func()


if __name__ == "__main__":
    main()
