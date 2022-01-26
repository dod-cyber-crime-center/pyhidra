import contextlib
import pathlib
from typing import Union, TYPE_CHECKING, Tuple, ContextManager, List

from pyhidra.converters import *  # pylint: disable=wildcard-import, unused-wildcard-import


if TYPE_CHECKING:
    import ghidra


def start(verbose=False):
    """
    Starts the JVM and loads the Ghidra libraries.
    Full Ghidra initialization is deferred.

    :param verbose: Enable verbose output during JVM startup (Defaults to False)
    :return: The DeferredPhyidraLauncher used to start the JVM
    """
    from pyhidra.launcher import HeadlessPyhidraLauncher
    launcher = HeadlessPyhidraLauncher(verbose=verbose)
    launcher.start()
    return launcher


def _setup_project(
        binary_path: Union[str, pathlib.Path],
        project_location: Union[str, pathlib.Path] = None,
        project_name: str = None
) -> Tuple["ghidra.base.project.GhidraProject", "ghidra.program.model.listing.Program"]:
    from ghidra.base.project import GhidraProject
    from java.io import IOException
    if binary_path is not None:
        binary_path = pathlib.Path(binary_path)
    if project_location:
        project_location = pathlib.Path(project_location)
    else:
        project_location = binary_path.parent
    if not project_name:
        project_name = f"{binary_path.name}_ghidra"
    project_location = project_location / project_name
    project_location.mkdir(exist_ok=True, parents=True)

    # Open/Create project
    program = None
    try:
        project = GhidraProject.openProject(project_location, project_name, True)
        if binary_path is not None:
            if project.getRootFolder().getFile(binary_path.name):
                program = project.openProgram("/", binary_path.name, False)
    except IOException:
        project = GhidraProject.createProject(project_location, project_name, False)

    if binary_path is not None and program is None:
        program = project.importProgram(binary_path)
        project.saveAs(program, "/", program.getName(), True)

    return project, program


def _setup_script(project, program):
    from pyhidra.script import PyGhidraScript
    from ghidra.app.script import GhidraState
    from ghidra.program.util import ProgramLocation
    from ghidra.util.task import TaskMonitor

    from java.io import PrintWriter
    from java.lang import System

    if project is not None:
        project = project.getProject()

    location = None
    if program is not None:
        # create a GhidraState and setup a HeadlessScript with it
        mem = program.getMemory().getLoadedAndInitializedAddressSet()
        if not mem.isEmpty():
            location = ProgramLocation(program, mem.getMinAddress())
    state = GhidraState(None, project, program, location, None, None)
    script = PyGhidraScript()
    script.set(state, TaskMonitor.DUMMY, PrintWriter(System.out))
    return script


@contextlib.contextmanager
def open_program(
        binary_path: Union[str, pathlib.Path],
        project_location: Union[str, Path] = None,
        project_name: str = None,
        analyze=True
) -> ContextManager["ghidra.program.flatapi.FlatProgramAPI"]:
    """
    Opens given binary path in Ghidra and returns FlatProgramAPI object.

    :param binary_path:
    :param project_location: Location of Ghidra project to open/create.
        (Defaults to same directory as binary file)
    :param project_name: Name of Ghidra project to open/create.
        (Defaults to name of binary file suffixed with "_ghidra")
    :param analyze: Whether to run analysis before returning.
    :return: A Ghidra FlatProgramAPI object.
    """

    from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher

    if not PyhidraLauncher.has_launched():
        HeadlessPyhidraLauncher().start()

    from ghidra.program.flatapi import FlatProgramAPI

    project, program = _setup_project(binary_path, project_location, project_name)

    try:
        flat_api = FlatProgramAPI(program)

        if analyze:
            from ghidra.program.util import GhidraProgramUtilities
            from ghidra.app.script import GhidraScriptUtil
            if GhidraProgramUtilities.shouldAskToAnalyze(program):
                GhidraScriptUtil.acquireBundleHostReference()
                try:
                    flat_api.analyzeAll(program)
                finally:
                    GhidraScriptUtil.releaseBundleHostReference()
        yield flat_api
    finally:
        project.save(program)
        project.close()


@contextlib.contextmanager
def _flat_api(
        binary_path: Union[str, Path],
        project_location: Union[str, Path] = None,
        project_name: str = None,
        verbose=False
):
    """
    Runs a given script on a given binary path.

    :param binary_path: Path to binary file.
    :param script_path: Path to script to run.
    :param project_location: Location of Ghidra project to open/create.
        (Defaults to same directory as binary file)
    :param project_name: Name of Ghidra project to open/create.
        (Defaults to name of binary file suffixed with "_ghidra")
    :param script_args: Command line arguments to pass to script.
    :param verbose: Enable verbose output during Ghidra initialization.
    """
    from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher

    if not PyhidraLauncher.has_launched():
        HeadlessPyhidraLauncher(verbose=verbose).start()

    project, program = None, None
    if binary_path or project_location:
        project, program = _setup_project(binary_path, project_location, project_name)

    try:
        yield _setup_script(project, program)
    finally:
        if project is not None:
            if program is not None:
                project.save(program)
            project.close()


# pylint: disable=too-many-arguments
def run_script(
    binary_path: Union[str, Path],
    script_path: Union[str, Path],
    project_location: Union[str, Path] = None,
    project_name: str = None,
    script_args: List[str] = None,
    verbose=False
):
    """
    Runs a given script on a given binary path.

    :param binary_path: Path to binary file, may be None
    :param script_path: Path to script to run.
    :param project_location: Location of Ghidra project to open/create.
        (Defaults to same directory as binary file if not None)
    :param project_name: Name of Ghidra project to open/create.
        (Defaults to name of binary file suffixed with "_ghidra" if not None)
    :param script_args: Command line arguments to pass to script.
    :param verbose: Enable verbose output during Ghidra initialization.
    """
    script_path = str(script_path)
    with _flat_api(binary_path, project_location, project_name, verbose) as script:
        script.run(script_path, script_args)
