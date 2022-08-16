
import pathlib
import textwrap
import importlib
import jpype
import sys
import pyhidra
from pyhidra.__main__ import _get_parser, PyhidraArgs
from pyhidra.script import PyGhidraScript

#pylint: disable=protected-access, missing-function-docstring

# hack fix so capsys works correctly
PyGhidraScript._print_wrapper = lambda self: print


def test_run_script(capsys, strings_exe):
    script_path = pathlib.Path(__file__).parent / "example_script.py"

    pyhidra.run_script(strings_exe, script_path, script_args=["my", "--commands"])
    captured = capsys.readouterr()

    expected = textwrap.dedent(f"""\
        {script_path} my --commands
        strings.exe - .ProgramDB
    """)

    assert captured.out == expected


def test_open_program(strings_exe):
    with pyhidra.open_program(strings_exe, analyze=False) as flat_api:
        assert flat_api.currentProgram.name == "strings.exe"
        assert flat_api.getCurrentProgram().listing
        assert flat_api.getCurrentProgram().changeable


def test_no_project(capsys):
    script_path = pathlib.Path(__file__).parent / "projectless_script.py"

    pyhidra.run_script(None, script_path)
    captured = capsys.readouterr()
    assert captured.out.rstrip() == "projectless_script executed successfully"


def test_no_program(capsys):
    script_path = pathlib.Path(__file__).parent / "programless_script.py"
    project_path = pathlib.Path(__file__).parent / "programless_ghidra"

    pyhidra.run_script(None, script_path, project_path, "programless")
    captured = capsys.readouterr()
    assert captured.out.rstrip() == "programless_script executed successfully"


def test_arg_parser(strings_exe):
    script_path = pathlib.Path(__file__).parent / "example_script.py"
    parser = _get_parser()
    strings_exe = str(strings_exe)
    args = [str(script_path), strings_exe]
    args1 = PyhidraArgs()
    args2 = PyhidraArgs()
    parser.parse_args(args, namespace=args1)
    args.reverse()
    parser.parse_args(args, namespace=args2)
    assert args1 == args2
    args.insert(0, "-v")
    args1 = parser.parse_args(args, namespace=PyhidraArgs())
    assert args1.verbose is True
    args = ["--project-name", "stub_name"] + args
    args1 = parser.parse_args(args, namespace=PyhidraArgs())
    assert args1.project_name == "stub_name"
    args = ["--project-path", str(script_path.parent)] + args
    args1 = parser.parse_args(args, namespace=PyhidraArgs())
    assert args1.project_path == script_path.parent

    # two scripts are ok
    parser.parse_args([str(script_path), str(script_path)], namespace=PyhidraArgs())

    try:
        # two binary files without a script is not
        parser.parse_args([strings_exe, strings_exe], namespace=PyhidraArgs())
        assert False
    except ValueError:
        pass


def test_import_ghidra_base_java_packages():

    def get_runtime_top_level_java_packages(launcher) -> set:
        from java.lang import Package

        packages = set()

        # Applicaiton needs to fully intialize to find all Ghidra packages
        if launcher.has_launched():

            for package in Package.getPackages():
                # capture base packages only
                packages.add(package.getName().split('.')[0])

        # Remove dc3 base package as it doesn't exist and won't conflict
        packages.remove('dc3')

        return packages

    def wrap_mod(mod):
        return mod + '_'

    launcher = pyhidra.start()

    # Test to ensure _PyhidraImportLoader is last loader
    assert isinstance(sys.meta_path[-1],pyhidra.launcher._PyhidraImportLoader)

    packages = get_runtime_top_level_java_packages(launcher)

    assert len(packages) > 0

    # Test full coverage for Java base packages (_JImportLoader or _PyhidraImportLoader)
    for mod in packages:
        # check spec using standard import machinery "import mod"
        spec = importlib.util.find_spec(mod)
        if not isinstance(spec.loader, jpype.imports._JImportLoader):
            # handle case with conflict. check spec with "import mod_"
            spec = importlib.util.find_spec(wrap_mod(mod))

        assert spec is not None
        assert isinstance(spec.loader, jpype.imports._JImportLoader) or isinstance(
            spec.loader, pyhidra.launcher._PyhidraImportLoader)

    # Test all Java base packages are available with '_'
    for mod in packages:
        spec_ = importlib.util.find_spec(wrap_mod(mod))
        assert spec_ is not None
        assert isinstance(spec_.loader, pyhidra.launcher._PyhidraImportLoader)

    # Test standard import
    import ghidra
    assert isinstance(ghidra.__loader__, jpype.imports._JImportLoader)

    # Test import with conflict    
    import pdb_
    assert isinstance(pdb_.__loader__, pyhidra.launcher._PyhidraImportLoader)

    # Test "from" import with conflict
    from pdb_ import PdbPlugin
    from pdb_.symbolserver import LocalSymbolStore

    # Test _Jpackage handles import that doesn't exist
    try:
        import pdb_.doesntexist
    except ImportError as e:
        pass


