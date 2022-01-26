
import pathlib
import shutil

import pytest


@pytest.fixture
def strings_exe(tmpdir):
    """Creates and returns a copy of the strings.exe file in a temporary directory."""
    orig_path = pathlib.Path(__file__).parent / "strings.exe"
    new_path = tmpdir / "strings.exe"
    shutil.copy(orig_path, str(new_path))
    return new_path
