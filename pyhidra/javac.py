import shutil
import tempfile
from pathlib import Path
from os import pathsep


COMPILER_OPTIONS = ["-target", "17", "-source", "17"]


def _to_jar_(jar_path: Path, root: Path):
    from java.io import ByteArrayOutputStream
    from java.util.jar import JarEntry, JarOutputStream

    out = ByteArrayOutputStream()
    with JarOutputStream(out) as jar:
        for p in root.glob("**/*.class"):
            p = p.resolve()
            jar.putNextEntry(JarEntry(str(p.relative_to(root).as_posix())))
            jar.write(p.read_bytes())
            jar.closeEntry()
    jar_path.write_bytes(out.toByteArray())


def java_compile(src_path: Path, jar_path: Path):
    """
    Compiles the provided Java source

    :param src_path: The path to the java file or the root directory of the java source files
    :param jar_path: The path to write the output jar to
    """

    from java.lang import System
    from java.nio.file import Path as JPath
    from javax.tools import StandardLocation, ToolProvider

    with tempfile.TemporaryDirectory() as out:
        outdir = Path(out).resolve()
        compiler = ToolProvider.getSystemJavaCompiler()
        fman = compiler.getStandardFileManager(None, None, None)
        cp = [JPath @ (Path(p)) for p in System.getProperty("java.class.path").split(pathsep)]
        fman.setLocationFromPaths(StandardLocation.CLASS_PATH, cp)
        if src_path.is_dir():
            fman.setLocationFromPaths(StandardLocation.SOURCE_PATH, [JPath @ (src_path.resolve())])
        fman.setLocationFromPaths(StandardLocation.CLASS_OUTPUT, [JPath @ (outdir)])
        sources = None
        if src_path.is_file():
            sources = fman.getJavaFileObjectsFromPaths([JPath @ (src_path)])
        else:
            glob = src_path.glob("**/*.java")
            sources = fman.getJavaFileObjectsFromPaths([JPath @ (p) for p in glob])

        task = compiler.getTask(None, fman, None, COMPILER_OPTIONS, None, sources)

        if not task.call():
            # errors printed to stderr
            return

        if jar_path.suffix == '.jar':
            jar_path.parent.mkdir(exist_ok=True, parents=True)
            _to_jar_(jar_path, outdir)
        else:
            shutil.copytree(outdir, jar_path, dirs_exist_ok=True)
