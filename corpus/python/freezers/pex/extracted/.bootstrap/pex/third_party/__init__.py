

from __future__ import absolute_import

import contextlib
import hashlib
import importlib
import os
import re
import shutil
import sys
import zipfile
from collections import OrderedDict, namedtuple

from pex.common import CopyMode, iter_copytree


from pex.typing import TYPE_CHECKING
from pex.util import CacheHelper

if TYPE_CHECKING:
    from typing import Container, Dict, Iterable, Iterator, List, Optional, Tuple

    from pex.cache.dirs import InstalledWheelDir
    from pex.interpreter import PythonInterpreter


def _tracer():
    from pex.tracer import TRACER

    return TRACER


class _Loader(namedtuple("_Loader", ["module_name", "vendor_module_name"])):


    def load_module(self, fullname):
        assert fullname in (
            self.module_name,
            self.vendor_module_name,
        ), "{} got an unexpected module {}".format(self, fullname)
        vendored_module = importlib.import_module(self.vendor_module_name)
        sys.modules[fullname] = vendored_module
        _tracer().log("{} imported via {}".format(fullname, self), V=9)
        return vendored_module


    if sys.version_info[:2] >= (3, 15):

        def create_module(self, spec):
            return self.load_module(spec.name)

        def exec_module(self, module):


            pass


    def unload(self):
        for mod in (self.module_name, self.vendor_module_name):
            if mod in sys.modules:
                sys.modules.pop(mod)
                _tracer().log("un-imported {}".format(mod), V=9)

                submod_prefix = mod + "."
                for submod in sorted(m for m in sys.modules.keys() if m.startswith(submod_prefix)):
                    sys.modules.pop(submod)
                    _tracer().log("un-imported {}".format(submod), V=9)


class _Importable(namedtuple("_Importable", ["module", "is_pkg", "path", "prefix"])):
    _exposed = False

    def expose(self):
        # type: () -> None
        self._exposed = True
        _tracer().log("Exposed {}".format(self), V=3)

    @property
    def exposed(self):
        # type: () -> bool
        return self._exposed

    def loader_for(self, fullname):
        # type: (str) -> Optional[_Loader]
        if fullname.startswith(self.prefix + "."):
            target = fullname[len(self.prefix + ".") :]
        else:
            if not self._exposed:
                return None
            target = fullname

        if target == self.module or self.is_pkg and target.startswith(self.module + "."):
            vendor_path = (
                os.path.join(*target.split("."))
                if not self.path or self.path == os.curdir
                else os.path.join(self.path, *target.split("."))
            )
            vendor_module_name = vendor_path.replace(os.sep, ".")
            return _Loader(fullname, vendor_module_name)

        return None


class _DirIterator(namedtuple("_DirIterator", ["rootdir"])):
    def iter_root_modules(self, relpath):
        for entry in self._iter_root(relpath):
            if os.path.isfile(entry):
                name, ext = os.path.splitext(os.path.basename(entry))
                if ext == ".py" and name != "__init__":
                    yield name

    def iter_root_packages(self, relpath):
        for entry in self._iter_root(relpath):
            if os.path.isfile(os.path.join(entry, "__init__.py")):
                yield os.path.basename(entry)

    def _iter_root(self, relpath):
        root = os.path.join(self.rootdir, relpath)
        if not os.path.isdir(root):


            return

        for entry in os.listdir(root):
            yield os.path.join(root, entry)


class _ZipIterator(namedtuple("_ZipIterator", ["zipfile_path", "prefix"])):
    @classmethod
    def containing(cls, root):
        prefix = ""
        path = root
        while path:


            if zipfile.is_zipfile(path):
                return cls(zipfile_path=path, prefix="{}/".format(prefix) if prefix else "")
            path_base = os.path.basename(path)
            prefix = "{}/{}".format(path_base, prefix) if prefix else path_base
            path = os.path.dirname(path)
        raise ValueError("Could not find the zip file housing {}".format(root))

    def iter_root_modules(self, relpath):
        for package in self._filter_names(relpath, r"(?P<module>[^/]+)\.py", "module"):
            if package != "__init__":
                yield package

    def iter_root_packages(self, relpath):
        for package in self._filter_names(relpath, r"(?P<package>[^/]+)/__init__\.py", "package"):
            yield package

    def _filter_names(self, relpath, pattern, group):


        relpath_pat = "" if not relpath else "{}/".format(relpath.replace(os.sep, "/"))
        pat = re.compile(r"^{}{}{}$".format(self.prefix, relpath_pat, pattern))
        with contextlib.closing(zipfile.ZipFile(self.zipfile_path)) as zf:
            for name in zf.namelist():
                match = pat.match(name)
                if match:
                    yield match.group(group)


class VendorImporter(object):

    @staticmethod
    def _vendored_path_items():
        # type: () -> Iterable[str]
        from pex import vendor

        return tuple(
            spec.relpath
            for spec in vendor.iter_vendor_specs(


                filter_requires_python=sys.version_info[:2]
            )
        )

    @staticmethod
    def _abs_root(root=None):
        # type: (Optional[str]) -> str
        from pex import vendor

        return os.path.abspath(root or vendor.VendorSpec.ROOT)

    @classmethod
    def _iter_importables(cls, root, path_items, prefix):
        module_iterator = (
            _DirIterator(root) if os.path.isdir(root) else _ZipIterator.containing(root)
        )
        for path_item in path_items:
            for module_name in module_iterator.iter_root_modules(path_item):
                yield _Importable(module=module_name, is_pkg=False, path=path_item, prefix=prefix)
            for package_name in module_iterator.iter_root_packages(path_item):
                yield _Importable(module=package_name, is_pkg=True, path=path_item, prefix=prefix)

    @classmethod
    def _iter_all_installed_vendor_importers(cls):
        for importer in sys.meta_path:
            if isinstance(importer, cls):
                yield importer

    @classmethod
    def iter_installed_vendor_importers(
        cls,
        prefix,
        root=None,
    ):
        # type: (...) -> Iterator[VendorImporter]
        root = cls._abs_root(root)
        for importer in cls._iter_all_installed_vendor_importers():

            if importer._importables and importer._importables[0].prefix == prefix:
                if importer._root == root:
                    yield importer

    @classmethod
    def install_vendored(
        cls,
        prefix,
        root=None,
        expose=None,
        expose_if_available=None,
    ):
        # type: (...) -> None
        root = cls._abs_root(root)
        installed = tuple(cls.iter_installed_vendor_importers(prefix, root=root))
        assert (
            len(installed) <= 1
        ), "Unexpected extra importers installed for vendored code:\n\t{}".format(
            "\n\t".join(map(str, installed))
        )
        if installed:
            vendor_importer = installed[0]
        else:


            vendor_importer = cls.install(
                uninstallable=True, prefix=prefix, path_items=cls._vendored_path_items(), root=root
            )


        exposed_paths = []
        if expose:
            for path in cls.expose(expose, root):
                sys.path.insert(0, path)
                exposed_paths.append(os.path.relpath(path, root))
        if expose_if_available:
            for path in cls.expose(expose_if_available, root, optional=True):
                sys.path.insert(0, path)
                exposed_paths.append(os.path.relpath(path, root))
        vendor_importer._expose(exposed_paths)

    @classmethod
    def expose(
        cls,
        dists,
        root=None,
        interpreter=None,
        optional=False,
    ):
        # type: (...) -> Iterator[str]
        from pex import vendor

        root = cls._abs_root(root)

        def iter_available():
            yield "pex", root
            for spec in vendor.iter_vendor_specs(filter_requires_python=interpreter):
                yield spec.key, spec.relpath

        path_by_key = OrderedDict(
            (key, relpath) for key, relpath in iter_available() if key in dists
        )

        if not optional:
            unexposed = set(dists) - set(path_by_key.keys())
            if unexposed:
                raise ValueError(
                    "The following vendored dists are not available to expose: {}".format(
                        ", ".join(sorted(unexposed))
                    )
                )

        exposed_paths = path_by_key.values()
        for exposed_path in exposed_paths:
            yield os.path.join(root, exposed_path)

    @classmethod
    def install(cls, uninstallable, prefix, path_items, root=None):
        root = cls._abs_root(root)
        importables = tuple(cls._iter_importables(root=root, path_items=path_items, prefix=prefix))
        vendor_importer = cls(root=root, importables=importables, uninstallable=uninstallable)
        sys.meta_path.insert(0, vendor_importer)
        _tracer().log("Installed {}".format(vendor_importer), V=3)
        return vendor_importer

    @classmethod
    def uninstall_all(cls):
        for vendor_importer in cls._iter_all_installed_vendor_importers():
            vendor_importer.uninstall()

    def __init__(
        self,
        root,
        importables,
        uninstallable=True,
    ):
        # type: (...) -> None
        self._root = root
        self._importables = importables
        self._uninstallable = uninstallable

        self._loaders = []

    @property
    def root(self):
        # type: () -> str
        return self._root

    @property
    def importables(self):
        # type: () -> Iterable[_Importable]
        return self._importables

    def uninstall(self):
        if not self._uninstallable:
            _tracer().log("Not uninstalling {}".format(self), V=9)
            return

        if self in sys.meta_path:
            sys.meta_path.remove(self)
            maybe_exposed = frozenset(
                os.path.join(self._root, importable.path) for importable in self._importables
            )
            sys.path[:] = [path_item for path_item in sys.path if path_item not in maybe_exposed]
            for loader in self._loaders:
                loader.unload()
            _tracer().log("Uninstalled {}".format(self), V=3)

    def find_spec(self, fullname, path, target=None):
        # Python 2.7 does not know about this API and does not use it.
        from importlib.util import spec_from_loader

        loader = self.find_module(fullname, path)
        if loader:
            return spec_from_loader(fullname, loader)
        return None


    def find_module(self, fullname, path=None):
        for importable in self._importables:
            loader = importable.loader_for(fullname)
            if loader is not None:
                self._loaders.append(loader)
                return loader
        return None

    def _expose(self, paths):
        for importable in self._importables:
            if importable.path in paths:
                importable.expose()

    def __repr__(self):
        return "{classname}(root={root!r}, importables={importables!r})".format(
            classname=self.__class__.__name__, root=self._root, importables=self._importables
        )


class IsolationResult(namedtuple("IsolatedPex", ["pex_hash", "chroot_path"])):


_ISOLATED = {}


def _isolate_pex_from_dir(
    pex_directory,
    isolate_to_dir,
    exclude_files,
):
    # type: (...) -> None
    from pex.common import is_pyc_dir, is_pyc_file, is_pyc_temporary_file, safe_copy

    for root, dirs, files in os.walk(pex_directory):
        relroot = os.path.relpath(root, pex_directory)
        for d in dirs:
            if is_pyc_dir(d):
                continue
            os.makedirs(os.path.join(isolate_to_dir, "pex", relroot, d))
        for f in files:
            if is_pyc_file(f):
                continue
            rel_f = os.path.join(relroot, f)
            if not is_pyc_temporary_file(rel_f) and rel_f not in exclude_files:
                safe_copy(
                    os.path.join(root, f),
                    os.path.join(isolate_to_dir, "pex", rel_f),
                )


def _isolate_pex_from_zip(
    pex_zip,
    pex_package_relpath,
    isolate_to_dir,
    exclude_files,
):
    # type: (...) -> None
    from pex.common import open_zip, safe_open

    with open_zip(pex_zip) as zf:
        for name in zf.namelist():
            if name.endswith("/") or not name.startswith(pex_package_relpath):
                continue
            rel_name = os.path.relpath(name, pex_package_relpath)
            if rel_name in exclude_files:
                continue
            with zf.open(name) as from_fp, safe_open(
                os.path.join(isolate_to_dir, rel_name), "wb"
            ) as to_fp:
                shutil.copyfileobj(from_fp, to_fp)


def isolated(interpreter=None):
    # type: (Optional[PythonInterpreter]) -> IsolationResult
    from pex.variables import ENV

    pex_root = ENV.PEX_ROOT
    isolation_result = _ISOLATED.get(pex_root)
    if isolation_result is None:
        from pex import layout, vendor
        from pex.atomic_directory import atomic_directory
        from pex.cache.dirs import CacheDir
        from pex.util import CacheHelper

        module = "pex"


        vendor_lockfiles = tuple(
            os.path.join(os.path.relpath(vendor_spec.relpath, module), "constraints.txt")
            for vendor_spec in vendor.iter_vendor_specs(filter_requires_python=interpreter)
        )

        pex_zip_paths = None
        pex_path = os.path.join(vendor.VendorSpec.ROOT, "pex")
        with _tracer().timed("Hashing pex"):
            if os.path.isdir(pex_path):
                pex_hash = CacheHelper.dir_hash(pex_path)
            else:


                zip_path = os.path.dirname(pex_path)
                if (
                    not zipfile.is_zipfile(zip_path)
                    and os.path.basename(zip_path) == layout.BOOTSTRAP_DIR
                ):
                    zip_path = os.path.dirname(zip_path)
                assert zipfile.is_zipfile(zip_path), (
                    "Expected the `pex` module to be available via an installed distribution "
                    "or else via a PEX. Loaded the `pex` module from {} and but the enclosing "
                    "PEX has an unexpected layout {}".format(pex_path, zip_path)
                )

                pex_package_relpath = (
                    ""
                    if os.path.basename(zip_path) == layout.BOOTSTRAP_DIR
                    else layout.BOOTSTRAP_DIR
                )
                pex_zip_paths = (zip_path, pex_package_relpath)
                pex_hash = CacheHelper.zip_hash(zip_path, relpath=pex_package_relpath)

        isolated_dir = CacheDir.ISOLATED.path(pex_hash, pex_root=pex_root)
        with _tracer().timed("Isolating pex"):
            with atomic_directory(isolated_dir) as chroot:
                if not chroot.is_finalized():
                    with _tracer().timed("Extracting pex to {}".format(isolated_dir)):
                        if pex_zip_paths:
                            pex_zip, pex_package_relpath = pex_zip_paths
                            _isolate_pex_from_zip(
                                pex_zip=pex_zip,
                                pex_package_relpath=pex_package_relpath,
                                isolate_to_dir=chroot.work_dir,
                                exclude_files=vendor_lockfiles,
                            )
                        else:
                            _isolate_pex_from_dir(
                                pex_directory=pex_path,
                                isolate_to_dir=chroot.work_dir,
                                exclude_files=vendor_lockfiles,
                            )

        isolation_result = IsolationResult(pex_hash=pex_hash, chroot_path=isolated_dir)
        _ISOLATED[pex_root] = isolation_result
    return isolation_result


def uninstall():
    VendorImporter.uninstall_all()


def import_prefix():
    return __name__


def install(root=None, expose=None, expose_if_available=None):
    VendorImporter.install_vendored(
        prefix=import_prefix(), root=root, expose=expose, expose_if_available=expose_if_available
    )


def exposed(root=None):
    # type: (Optional[str]) -> Iterator[str]
    for importer in VendorImporter.iter_installed_vendor_importers(
        prefix=import_prefix(), root=root
    ):
        for importable in importer.importables:
            if importable.exposed:
                yield os.path.join(importer.root, importable.path)


def expose(
    dists,
    interpreter=None,
):
    # type: (...) -> Iterator[str]
    for path in VendorImporter.expose(dists, root=isolated().chroot_path, interpreter=interpreter):
        yield path


def expose_installed_wheels(
    dists,
    interpreter=None,
):
    # type: (...) -> Iterator[InstalledWheelDir]

    from pex.atomic_directory import atomic_directory
    from pex.cache.dirs import InstalledWheelDir
    from pex.installed_wheel import InstalledWheel

    for path in expose(dists, interpreter=interpreter):


        installed_wheel = InstalledWheel.load(path)
        wheel_file_name = installed_wheel.wheel_file_name()
        install_hash = installed_wheel.fingerprint or CacheHelper.dir_hash(
            path, hasher=hashlib.sha256
        )
        installed_wheel_dir = InstalledWheelDir.create(
            wheel_name=wheel_file_name, install_hash=install_hash
        )
        with atomic_directory(installed_wheel_dir) as atomic_dir:
            if not atomic_dir.is_finalized():
                for _src, _dst in iter_copytree(path, atomic_dir.work_dir, copy_mode=CopyMode.LINK):
                    pass
        yield installed_wheel_dir


install(expose=["attrs"])
