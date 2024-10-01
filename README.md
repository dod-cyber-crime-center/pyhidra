## NOTICE

Pyhidra has been integrated into Ghidra under the name "PyGhidra". Pyhidra will continue to support up to Ghidra 11.3/12.0 whichever comes first.

# pyhidra

Pyhidra is a Python library that provides direct access to the Ghidra API within a native CPython interpreter using [jpype](https://jpype.readthedocs.io/en/latest). As well, Pyhidra contains some conveniences for setting up analysis on a given sample and running a Ghidra script locally. It also contains a Ghidra plugin to allow the use of CPython from the
Ghidra user interface.

Pyhidra was initially developed for use with Dragodis and is designed to be installable without requiring Java or Ghidra. Due to this restriction, the Java plugin for Pyhidra is compiled and installed automatically during first use. The Java plugin is managed by Pyhidra and will automatically be rebuilt as necessary.

## Install

1. Download and install [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) to a desired location.

1. Set the `GHIDRA_INSTALL_DIR` environment variable to point to the directory where Ghidra is installed.

1. Install pyhidra.

```console
pip install pyhidra
```
### Enabling the Ghidra User Interface Plugin

1. Run `pyhidraw` from a terminal of your choice.
2. Open the Code Browser Tool.
3. From the `File` toolbar menu, select `Configure...`.
4. From the menu in the image below select `configure` under `Experimental`.
 ![](https://raw.githubusercontent.com/Defense-Cyber-Crime-Center/pyhidra/master/images/image-20220111154029764.png)
5. Check and enable Pyhidra as seen in the image below.
 ![](https://raw.githubusercontent.com/Defense-Cyber-Crime-Center/pyhidra/master/images/image-20220111154120531.png)

### Desktop Entry

If on linux, mac or windows, a desktop entry can be created to launch an instance of Ghidra with pyhidra attached.
When this script is run from a virtual environment (ie. venv), pyhidra will be started in this virtual environment
when launched.

```console
python -m pyhidra.install_desktop
```

On windows, this will install a shortcut file on the user's desktop. On linux, this will create an entry 
that can be found in the applications launcher. On mac this will create an entry that can be found in 
the Launchpad.


To remove, run the following:

```console
python -m pyhidra.uninstall_desktop
```

### Manual Plugin Installation

If pyhidra is planned to be used in a multiprocessing deployed server, the following must be run to allow the Ghidra plugins to be compiled and installed before use.

```console
python -m pyhidra.install_plugins
```


### Manual Plugin Uninstallation

If a plugin is misbehaving, the plugin can be manually uninstalled to allow recompilation on the next startup of pyhidra's launcher.

```console
python -m pyhidra.uninstall_plugin pyhidra
```


## Usage


### Raw Connection

To get just a raw connection to Ghidra use the `start()` function.
This will setup a Jpype connection and initialize Ghidra in headless mode,
which will allow you to directly import `ghidra` and `java`.

*NOTE: No projects or programs get setup in this mode.*

```python
import pyhidra
pyhidra.start()

import ghidra
from ghidra.app.util.headless import HeadlessAnalyzer
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.base.project import GhidraProject
from java.lang import String

# do things
```

### Customizing Java and Ghidra initialization

JVM configuration for the classpath and vmargs may be done through a `PyhidraLauncher`.

```python
from pyhidra.launcher import HeadlessPyhidraLauncher

launcher = HeadlessPyhidraLauncher()
launcher.add_classpaths("log4j-core-2.17.1.jar", "log4j-api-2.17.1.jar")
launcher.add_vmargs("-Dlog4j2.formatMsgNoLookups=true")
launcher.start()
```

### Registering an Entry Point

The `PyhidraLauncher` can also be configured through the use of a registered entry point on your own python project.
This is useful for installing your own Ghidra plugin which uses pyhidra and self-compiles.

First create an [entry_point](https://setuptools.pypa.io/en/latest/userguide/entry_point.html) for `pyhidra.setup`
pointing to a single argument function which accepts the launcher instance.

```python
# setup.py
from setuptools import setup

setup(
    # ...,
    entry_points={
        'pyhidra.setup': [
            'acme_plugin = acme.ghidra_plugin.install:setup',
        ]
    }
)
```


Then we create the target function.
This function will be called every time a user starts a pyhidra launcher.
In the same fashion, another entry point `pyhidra.pre_launch` may be registered and will be called after Ghidra and all
plugins have been loaded.

```python
# acme/ghidra_plugin/install.py
from pathlib import Path
import pyhidra

def setup(launcher):
    """
    Run by pyhidra launcher to install our plugin.
    """
    launcher.add_classpaths("log4j-core-2.17.1.jar", "log4j-api-2.17.1.jar")
    launcher.add_vmargs("-Dlog4j2.formatMsgNoLookups=true")

    # Install our plugin.
    source_path = Path(__file__).parent / "java" / "plugin"  # path to uncompiled .java code
    details = pyhidra.ExtensionDetails(
        name="acme_plugin",
        description="My Cool Plugin",
        author="acme",
        plugin_version="1.2",
    )
    launcher.install_plugin(source_path, details)  # install plugin (if not already)
```


### Analyze a File

To have pyhidra setup a binary file for you, use the `open_program()` function.
This will setup a Ghidra project and import the given binary file as a program for you.

Again, this will also allow you to import `ghidra` and `java` to perform more advanced processing.

```python
import pyhidra

with pyhidra.open_program("binary_file.exe") as flat_api:
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    print(listing.getCodeUnitAt(flat_api.toAddr(0x1234)))

    # We are also free to import ghidra while in this context to do more advanced things.
    from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
    decomp_api = FlatDecompilerAPI(flat_api)
    # ...
    decomp_api.dispose()
```

By default, pyhidra will run analysis for you. If you would like to do this yourself, set `analyze` to `False`.

```python
import pyhidra

with pyhidra.open_program("binary_file.exe", analyze=False) as flat_api:
    from ghidra.program.util import GhidraProgramUtilities

    program = flat_api.getCurrentProgram()
    if GhidraProgramUtilities.shouldAskToAnalyze(program):
        flat_api.analyzeAll(program)
```


The `open_program()` function can also accept optional arguments to control the project name and location that gets created.
(Helpful for opening up a sample in an already existing project.)

```python
import pyhidra

with pyhidra.open_program("binary_file.exe", project_name="EXAM_231", project_location=r"C:\exams\231") as flat_api:
    ...
```


### Run a Script

Pyhidra can also be used to run an existing Ghidra Python script directly in your native python interpreter
using the `run_script()` command.
However, while you can technically run an existing Ghidra script unmodified, you may
run into issues due to differences between Jython 2 and CPython 3.
Therefore, some modification to the script may be needed.

```python

import pyhidra

pyhidra.run_script(r"C:\input.exe", r"C:\some_ghidra_script.py")
```

This can also be done on the command line using `pyhidra`.

```console
> pyhidra C:\input.exe C:\some_ghidra_script.py <CLI ARGS PASSED TO SCRIPT>
```

### Ghidra User Interface

Ghidra **must** be started via `pyhidraw` and the plugin must be enabled for the user interface features to be present. Once these prerequisites are met the `pyhidra` menu item will be available in the `Window` toolbar menu and all Python scripts outside of the Ghidra installation will automatically be run with CPython. Any Python script found within the Ghidra installation will be run using Jython to prevent causing issues with any analyzers or Ghidra internals that use them. Below is a screenshot of the standard Python interpreter in Ghidra which is using CPython instead of Jython. It will appear when `pyhidra` is opened from the `Window` toolbar menu.

![](https://raw.githubusercontent.com/Defense-Cyber-Crime-Center/pyhidra/master/images/image-20220111152440065.png)

### Handling Package Name Conflicts

There may be some Python modules and Java packages with the same import path. When this occurs the Python module takes precedence.
While jpype has its own mechanism for handling this situation, pyhidra automatically makes the Java package accessible by allowing
it to be imported with an underscore appended to the package name.

```python
import pdb   # imports Python's pdb
import pdb_  # imports Ghidra's pdb
```
