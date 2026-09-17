

from __future__ import absolute_import

import collections
import os
import subprocess
import sys
from textwrap import dedent

from pex.common import Chroot, is_pyc_dir, is_pyc_file, open_zip, safe_mkdtemp, touch
from pex.exceptions import production_assert
from pex.tracer import TRACER
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Iterable, Iterator, List, Optional, Sequence, Set, Text, Tuple, Union

    from pex.interpreter import PythonInterpreter

_PACKAGE_COMPONENTS = __name__.split(".")


class EnclosingZip(collections.namedtuple("EnclosingZip", ["path", "entries"])):
    pass


class VendorRoot(collections.namedtuple("VendorRoot", ["path", "enclosing_zip"])):
    pass


def _root():
    # type: () -> VendorRoot

    path = os.path.dirname(os.path.abspath(__file__))
    for _ in _PACKAGE_COMPONENTS:
        path = os.path.dirname(path)

    if os.path.isdir(path):
        return VendorRoot(path, enclosing_zip=None)

    import zipfile

    enclosing_zip = path
    while not zipfile.is_zipfile(enclosing_zip):
        parent = os.path.dirname(enclosing_zip)
        production_assert(
            parent != enclosing_zip,
            "Expected to find enclosing PEX or .whl zip for vendor root: {root}",
            root=path,
        )
        enclosing_zip = parent

    with open_zip(enclosing_zip) as zf:
        return VendorRoot(
            path, enclosing_zip=EnclosingZip(path=enclosing_zip, entries=frozenset(zf.namelist()))
        )


class VendorSpec(
    collections.namedtuple(
        "VendorSpec", ["key", "requirement", "import_path", "rewrite", "constrain", "constraints"]
    )
):

    ROOT, _ENCLOSING_ZIP = _root()

    _VENDOR_DIR = "_vendored"

    @classmethod
    def vendor_root(cls):
        return os.path.join(cls.ROOT, *(_PACKAGE_COMPONENTS + [cls._VENDOR_DIR]))

    @classmethod
    def pinned(
        cls,
        key,
        version,
        import_path=None,
        rewrite=True,
        constraints=(),
    ):
        return cls(
            key=key,
            requirement="{}=={}".format(key, version),
            import_path=import_path or key,
            rewrite=rewrite,
            constrain=True,
            constraints=constraints,
        )

    @classmethod
    def git(
        cls,
        repo,
        commit,
        project_name,
        import_path=None,
        prep_command=None,
        rewrite=True,
        constraints=(),
    ):
        requirement = "{project_name} @ git+{repo}@{commit}".format(
            repo=repo, commit=commit, project_name=project_name
        )
        if not prep_command:
            return cls(
                key=project_name,
                requirement=requirement,
                import_path=import_path or project_name,
                rewrite=rewrite,
                constrain=False,
                constraints=constraints,
            )

        class PreparedGit(VendorSpec):
            def prepare(self):
                clone_dir = safe_mkdtemp()
                subprocess.check_call(["git", "clone", "--depth", "1", repo, clone_dir])
                subprocess.check_call(
                    ["git", "fetch", "--depth", "1", "origin", commit], cwd=clone_dir
                )
                subprocess.check_call(["git", "checkout", commit], cwd=clone_dir)
                if prep_command:
                    subprocess.check_call(prep_command, cwd=clone_dir)
                return clone_dir

        return PreparedGit(
            key=project_name,
            requirement=requirement,
            import_path=import_path or project_name,
            rewrite=rewrite,
            constrain=False,
            constraints=constraints,
        )

    @property
    def _subpath_components(self):
        # type: () -> List[str]
        return [self._VENDOR_DIR, self.import_path]

    @property
    def relpath(self):
        # type: () -> str
        return self._relpath()

    def _relpath(self, sep=os.sep):
        # type: (str) -> str
        return sep.join(_PACKAGE_COMPONENTS + self._subpath_components)

    @property
    def target_dir(self):
        return os.path.join(self.ROOT, self.relpath)

    @property
    def exists(self):
        # type: () -> bool
        if self._ENCLOSING_ZIP:
            prefix = self.ROOT[len(self._ENCLOSING_ZIP.path) + len(os.sep) :]
            target_dir = prefix + "/" + self._relpath("/") + "/"
            return target_dir in self._ENCLOSING_ZIP.entries
        return os.path.isdir(self.target_dir)

    def prepare(self):
        return self.requirement

    def create_packages(self):
        if not self.rewrite:


            pass

        for index, _ in enumerate(self._subpath_components):
            relpath = _PACKAGE_COMPONENTS + self._subpath_components[: index + 1] + ["__init__.py"]
            touch(os.path.join(self.ROOT, *relpath))


PIP_SPEC = VendorSpec.git(
    repo="https://github.com/pex-tool/pip",
    commit="8723d5ac400942896f69ed777da53f26f766510c",
    project_name="pip",
    rewrite=False,
)


def iter_vendor_specs(
    filter_requires_python=None,
    filter_exists=True,
):
    # type: (...) -> Iterator[VendorSpec]
    python_major_minor = None
    if filter_requires_python:
        python_major_minor = (
            filter_requires_python
            if isinstance(filter_requires_python, tuple)
            else filter_requires_python.version[:2]
        )

    yield VendorSpec.pinned("ansicolors", "1.1.8")
    yield VendorSpec.pinned("appdirs", "1.4.4")


    yield VendorSpec.git(
        repo="https://github.com/python-attrs/attrs",
        commit="947bfb542104209a587280701d8cb389c813459d",
        project_name="attrs",
    )


    if not python_major_minor or python_major_minor < (3, 6):

        yield VendorSpec.pinned(
            "packaging", "20.9", import_path="packaging_20_9", constraints=("pyparsing<3",)
        )
    if not python_major_minor or python_major_minor == (3, 6):


        yield VendorSpec.pinned(
            "packaging", "21.3", import_path="packaging_21_3", constraints=("pyparsing<3.0.8",)
        )
    if not python_major_minor or python_major_minor == (3, 7):

        yield VendorSpec.pinned("packaging", "24.0", import_path="packaging_24_0")
    if not python_major_minor or python_major_minor >= (3, 8):

        yield VendorSpec.pinned("packaging", "26.2", import_path="packaging_26_2")


    if not python_major_minor or python_major_minor < (3, 7):
        vendored_toml = VendorSpec.pinned("toml", "0.10.2")
        if not filter_exists or vendored_toml.exists:
            yield vendored_toml
    if not python_major_minor or (3, 7) <= python_major_minor < (3, 11):
        vendored_tomli = VendorSpec.pinned("tomli", "2.0.1")
        if not filter_exists or vendored_tomli.exists:
            yield vendored_tomli


    if not python_major_minor or python_major_minor < (3, 12):
        if not filter_exists or PIP_SPEC.exists:
            yield PIP_SPEC


    pex_tool_setuptools_commit = "3acb925dd708430aeaf197ea53ac8a752f7c1863"
    vendored_setuptools = VendorSpec.git(
        repo="https://github.com/pex-tool/setuptools",
        commit=pex_tool_setuptools_commit,
        project_name="setuptools",


        prep_command=[
            sys.executable,
            "-c",
            dedent(
                """\
                import configparser
                import subprocess
                import sys


                parser = configparser.ConfigParser()
                parser.read("setup.cfg")
                parser["egg_info"]["tag_build"] = "+{commit}"
                del parser["egg_info"]["tag_date"]
                with open("setup.cfg", "w") as fp:
                    parser.write(fp)

                subprocess.check_call([sys.executable, "bootstrap.py"])
                """
            ).format(commit=pex_tool_setuptools_commit),
        ],
    )
    if not python_major_minor or python_major_minor < (3, 12):
        if not filter_exists or vendored_setuptools.exists:
            yield vendored_setuptools


def vendor_runtime(
    chroot,
    dest_basedir,
    label,
    root_module_names,
):
    # type: (...) -> Set[str]
    vendor_module_names = {root_module_name: False for root_module_name in root_module_names}

    vendored_sources = set()
    for spec in iter_vendor_specs():
        for root, dirs, files in os.walk(spec.target_dir):
            if root == spec.target_dir:
                packages = [pkg_name for pkg_name in dirs if pkg_name in vendor_module_names]
                modules = [mod_name for mod_name in files if mod_name[:-3] in vendor_module_names]
                vendored_names = packages + [filename[:-3] for filename in modules]
                if not vendored_names:
                    dirs[:] = []
                    files[:] = []
                    continue

                pkg_path = ""
                for pkg in spec.relpath.split(os.sep):
                    pkg_path = os.path.join(pkg_path, pkg)
                    pkg_file = os.path.join(pkg_path, "__init__.py")
                    src = os.path.join(VendorSpec.ROOT, pkg_file)
                    if src in vendored_sources:
                        continue
                    dest = os.path.join(dest_basedir, pkg_file)
                    if os.path.exists(src):
                        chroot.copy(src, dest, label)
                    else:


                        chroot.touch(dest, label)
                    vendored_sources.add(src)

                for name in vendored_names:
                    vendor_module_names[name] = True
                    TRACER.log("Vendoring {} from {} @ {}".format(name, spec, spec.target_dir), V=3)

                dirs[:] = packages
                files[:] = modules


            dirs[:] = [d for d in dirs if not is_pyc_dir(d)]
            for filename in files:
                if is_pyc_file(filename):
                    continue
                src = os.path.join(root, filename)
                if src in vendored_sources:
                    continue
                dest = os.path.join(
                    dest_basedir, spec.relpath, os.path.relpath(src, spec.target_dir)
                )
                chroot.copy(src, dest, label)
                vendored_sources.add(src)

    if not all(vendor_module_names.values()):
        raise ValueError(
            "Failed to extract {module_names} from:\n\t{specs}".format(
                module_names=", ".join(
                    module for module, written in vendor_module_names.items() if not written
                ),
                specs="\n\t".join(
                    "{} @ {}".format(spec, spec.target_dir) for spec in iter_vendor_specs()
                ),
            )
        )

    return vendored_sources
