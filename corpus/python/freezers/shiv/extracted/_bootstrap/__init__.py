import compileall
import hashlib
import os
import runpy
import shutil
import site
import subprocess
import sys
import zipfile

from contextlib import contextmanager, suppress
from functools import partial
from importlib import import_module
from pathlib import Path

from .environment import Environment
from .filelock import FileLock
from .interpreter import execute_interpreter


def run(module):
    with suppress(KeyError):
        del os.environ[Environment.MODULE]

    with suppress(KeyError):
        del os.environ[Environment.ENTRY_POINT]

    with suppress(KeyError):
        del os.environ[Environment.CONSOLE_SCRIPT]

    sys.exit(module())


@contextmanager
def current_zipfile():
    if zipfile.is_zipfile(sys.argv[0]):
        with zipfile.ZipFile(sys.argv[0]) as fd:
            yield fd
    else:
        yield None


def import_string(import_name):
    import_name = str(import_name).replace(":", ".")

    try:
        import_module(import_name)

    except ImportError:
        if "." not in import_name:


            raise

    else:
        return sys.modules[import_name]


    module_name, obj_name = import_name.rsplit(".", 1)

    try:
        module = __import__(module_name, None, None, [obj_name])

    except ImportError:


        module = import_string(module_name)

    try:
        return getattr(module, obj_name)

    except AttributeError as e:
        raise ImportError(e)


def cache_path(archive, root_dir, build_id):

    if root_dir:

        if root_dir.startswith("$"):
            root_dir = os.environ.get(root_dir[1:], root_dir[1:])

        root_dir = Path(root_dir).expanduser()

    root = root_dir or Path("~/.shiv").expanduser()
    name = Path(archive.filename).resolve().name
    return root / f"{name}_{build_id}"


def extract_site_packages(archive, target_path, compile_pyc=False, compile_workers=0, force=False):
    parent = target_path.parent
    target_path_tmp = Path(parent, target_path.name + ".tmp")
    lock = Path(parent, f".{target_path.name}_lock")


    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)

    with FileLock(lock):


        if not target_path.exists() or force:


            for fileinfo in archive.infolist():

                if fileinfo.filename.startswith("site-packages"):
                    extracted = archive.extract(fileinfo.filename, target_path_tmp)


                    os.chmod(extracted, fileinfo.external_attr >> 16)

            if compile_pyc:
                compileall.compile_dir(target_path_tmp, quiet=2, workers=compile_workers)


            if target_path.exists():
                shutil.rmtree(str(target_path))


            shutil.move(str(target_path_tmp), str(target_path))


def get_first_sitedir_index():
    for index, part in enumerate(sys.path):
        if Path(part).stem in ("site-packages", "dist-packages"):
            return index


def extend_python_path(environ, additional_paths):


    python_path = environ["PYTHONPATH"].split(os.pathsep) if "PYTHONPATH" in environ else []
    python_path.extend(additional_paths)


    environ["PYTHONPATH"] = os.pathsep.join(sorted(set(python_path), key=python_path.index))


def ensure_no_modify(site_packages, hashes):

    for path in site_packages.rglob("**/*.py"):

        if hashlib.sha256(path.read_bytes()).hexdigest() != hashes.get(str(path.relative_to(site_packages))):
            raise RuntimeError(
                "A Python source file has been modified! File: {}. "
                "Try again with SHIV_FORCE_EXTRACT=1 to overwrite the modified source file(s).".format(str(path))
            )


def prepend_pythonpath(env):
    if env.prepend_pythonpath:
        sys.path.insert(0, env.prepend_pythonpath)


def bootstrap():


    with current_zipfile() as archive:


        env = Environment.from_json(archive.read("environment.json").decode())


        site_packages = cache_path(archive, env.root, env.build_id) / "site-packages"


        if not site_packages.exists() or env.force_extract:
            extract_site_packages(
                archive,
                site_packages.parent,
                env.compile_pyc,
                env.compile_workers,
                env.force_extract,
            )


    length = len(sys.path)


    index = get_first_sitedir_index() or length


    sys_path_before = sys.path.copy()


    site.addsitedir(site_packages)


    sys.path = sys.path[:index] + sys.path[length:] + sys.path[index:length]


    prepend_pythonpath(env)


    new_paths = [p for p in sys.path if p not in sys_path_before]


    if env.no_modify:
        ensure_no_modify(site_packages, env.hashes)


    if env.extend_pythonpath:
        extend_python_path(os.environ, new_paths)


    if env.preamble:


        preamble_bin = site_packages / "bin" / env.preamble

        if preamble_bin.suffix == ".py":
            runpy.run_path(
                str(preamble_bin),
                init_globals={"archive": sys.argv[0], "env": env, "site_packages": site_packages},
                run_name="__main__",
            )

        else:
            subprocess.run([preamble_bin])


    if not env.interpreter:


        if env.entry_point is not None and not env.script:
            run(import_string(env.entry_point))

        elif env.script is not None:
            run(partial(runpy.run_path, str(site_packages / "bin" / env.script), run_name="__main__"))


    execute_interpreter()


if __name__ == "__main__":
    bootstrap()
