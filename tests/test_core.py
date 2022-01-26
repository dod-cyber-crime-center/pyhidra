
import pathlib
import textwrap
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
