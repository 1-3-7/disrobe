

from __future__ import absolute_import, print_function

import hashlib
import logging
import os
import shutil
import zipimport
from textwrap import dedent
from zipimport import ZipImportError

from pex import layout, pex_warnings
from pex.atomic_directory import atomic_directory
from pex.cache.dirs import BootstrapZipDir, PackedWheelDir
from pex.common import (
    Chroot,
    CopyMode,
    deterministic_walk,
    is_pyc_file,
    is_pyc_temporary_file,
    safe_copy,
    safe_delete,
    safe_mkdir,
    safe_mkdtemp,
    safe_open,
)
from pex.compatibility import safe_commonpath, to_bytes
from pex.compiler import Compiler
from pex.dist_metadata import Distribution, DistributionType, MetadataError
from pex.enum import Enum
from pex.executables import chmod_plus_x, create_sh_python_redirector_shebang
from pex.finders import get_entry_point_from_console_script, get_script_from_distributions
from pex.fs import safe_rename, safe_symlink
from pex.inherit_path import InheritPath
from pex.installed_wheel import InstalledWheel
from pex.interpreter import PythonInterpreter
from pex.layout import Layout
from pex.orderedset import OrderedSet
from pex.os import WINDOWS
from pex.pex import PEX
from pex.pex_info import PexInfo
from pex.sh_boot import create_sh_boot_script
from pex.targets import Targets
from pex.tracer import TRACER
from pex.typing import TYPE_CHECKING
from pex.util import CacheHelper

if TYPE_CHECKING:
    from typing import Dict, Iterable, Optional


# Python 2.7. This can occur in test scenarios; so we ensure the __file__ is resolved to an absolute


_ABS_PEX_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))


class InvalidZipAppError(Exception):
    pass


class Check(Enum["Check.Value"]):
    class Value(Enum.Value):
        def perform_check(
            self,
            layout,
            path,
        ):
            # type: (...) -> Optional[bool]

            if self is Check.NONE:
                return None

            if layout is not Layout.ZIPAPP:
                return None

            try:
                importer = zipimport.zipimporter(path)


                finder = "find_spec" if hasattr(importer, "find_spec") else "find_module"
                if getattr(importer, finder)("__main__") is not None:
                    return True
                reason = "Could not find the `__main__` module."
            except ZipImportError as e:


                reason = str(e)

            message = (
                dedent(
                    """\
                    The PEX zip at {path} is not a valid zipapp: {reason}
                    This is likely due to the zip requiring ZIP64 extensions due to size or the
                    number of file entries or both. You can work around this limitation in Python's
                    `zipimport` module by re-building the PEX with `--layout packed` or
                    `--layout loose`.
                    """
                )
                .format(path=path, reason=reason)
                .strip()
            )
            if self is Check.ERROR:
                raise InvalidZipAppError(message)

            pex_warnings.warn(message)
            return False

    NONE = Value("none")
    WARN = Value("warn")
    ERROR = Value("error")


Check.seal()


class PEXBuilder(object):

    class Error(Exception):
        pass

    class ImmutablePEX(Error):
        pass

    class InvalidDistribution(Error):
        pass

    class InvalidDependency(Error):
        pass

    class InvalidExecutableSpecification(Error):
        pass

    def __init__(
        self,
        path=None,
        interpreter=None,
        chroot=None,
        pex_info=None,
        preamble=None,
        copy_mode=CopyMode.LINK,
    ):
        # type: (...) -> None
        self._interpreter = interpreter or PythonInterpreter.get()
        self._chroot = chroot or Chroot(path or safe_mkdtemp())
        self._pex_info = pex_info or PexInfo.default()
        self._preamble = preamble or ""
        self._copy_mode = (
            CopyMode.LINK if ((copy_mode is CopyMode.SYMLINK) and WINDOWS) else copy_mode
        )

        self._shebang = self._interpreter.identity.hashbang()
        self._header = None
        self._logger = logging.getLogger(__name__)
        self._frozen = False
        self._distributions = {}

    def _ensure_unfrozen(self, name="Operation"):
        if self._frozen:
            raise self.ImmutablePEX("%s is not allowed on a frozen PEX!" % name)

    @property
    def interpreter(self):
        # type: () -> PythonInterpreter
        return self._interpreter

    def chroot(self):
        # type: () -> Chroot
        return self._chroot

    def path(self):
        # type: () -> str
        return self.chroot().path()

    @property
    def info(self):
        return self._pex_info

    @info.setter
    def info(self, value):
        if not isinstance(value, PexInfo):
            raise TypeError("PEXBuilder.info must be a PexInfo!")
        self._ensure_unfrozen("Changing PexInfo")
        self._pex_info = value

    def add_source(self, filename, env_filename):
        self._ensure_unfrozen("Adding source")
        self._copy_or_link(filename, env_filename, "source")

    def add_resource(self, filename, env_filename):
        pex_warnings.warn(
            "The `add_resource` method is deprecated. Resources should be added via the "
            "`add_source` method instead."
        )
        self._ensure_unfrozen("Adding a resource")
        self._copy_or_link(filename, env_filename, "resource")

    def add_requirement(self, req):
        self._ensure_unfrozen("Adding a requirement")
        self._pex_info.add_requirement(req)

    def set_executable(self, filename, env_filename=None):
        self._ensure_unfrozen("Setting the executable")
        if self._pex_info.script:
            raise self.InvalidExecutableSpecification(
                "Cannot set both entry point and script of PEX!"
            )
        if env_filename is None:
            env_filename = os.path.basename(filename)
        if self._chroot.get("executable"):
            raise self.InvalidExecutableSpecification(
                "Setting executable on a PEXBuilder that already has one!"
            )
        self._copy_or_link(filename, env_filename, "executable")
        entry_point = env_filename
        entry_point = entry_point.replace(os.path.sep, ".")
        self._pex_info.entry_point = entry_point.rpartition(".")[0]

    def set_script(self, script):

        distributions = OrderedSet(self._distributions.values())
        for pex in self._pex_info.pex_path:
            if os.path.exists(pex):
                distributions.update(PEX(pex, interpreter=self._interpreter).resolve())


        dist_entry_point = get_entry_point_from_console_script(script, distributions)
        if dist_entry_point:
            self.set_entry_point(str(dist_entry_point.entry_point))
            TRACER.log(
                "Set entrypoint to {console_script}".format(
                    console_script=dist_entry_point.render_description()
                )
            )
            return


        dist_script = get_script_from_distributions(script, distributions)
        if dist_script:
            if self._pex_info.entry_point:
                raise self.InvalidExecutableSpecification(
                    "Cannot set both entry point and script of PEX!"
                )
            self._pex_info.script = script
            TRACER.log("Set entrypoint to script {!r} in {!r}".format(script, dist_script.dist))
            return

        raise self.InvalidExecutableSpecification(
            "Could not find script {!r} in any distribution {} within PEX!".format(
                script, ", ".join(str(d) for d in distributions)
            )
        )

    def set_entry_point(self, entry_point):
        self._ensure_unfrozen("Setting an entry point")
        self._pex_info.entry_point = entry_point

    @property
    def shebang(self):
        # type: () -> str
        return self._shebang

    def set_shebang(self, shebang):
        self._shebang = "#!%s" % shebang if not shebang.startswith("#!") else shebang

    def set_header(self, header):
        # type: (str) -> None
        self._header = header

    def _add_dist(
        self,
        path,
        dist_name,
        fingerprint=None,
        is_wheel_file=False,
    ):
        target_dir = os.path.join(self._pex_info.internal_cache, dist_name)
        if self._copy_mode is CopyMode.SYMLINK or is_wheel_file:
            self._copy_or_link(
                path,
                target_dir,
                label=dist_name,
                compress=not is_wheel_file,
                copy_mode=CopyMode.LINK if is_wheel_file else None,
            )
        else:
            for root, _, files in deterministic_walk(path):
                for f in files:
                    if is_pyc_file(f):
                        continue
                    filename = os.path.join(root, f)
                    relpath = os.path.relpath(filename, path)
                    target = os.path.join(target_dir, relpath)
                    self._copy_or_link(filename, target, label=dist_name)
        if fingerprint:
            return fingerprint
        if not is_wheel_file:
            try:
                installed_wheel = InstalledWheel.load(path)
                if installed_wheel.fingerprint:
                    return installed_wheel.fingerprint
            except InstalledWheel.LoadError:
                pass
        return CacheHelper.hash(path) if is_wheel_file else CacheHelper.dir_hash(path)

    def add_distribution(
        self,
        dist,
        fingerprint=None,
    ):
        # type: (...) -> None
        if dist.location in self._distributions:
            TRACER.log(
                "Skipping adding {} - already added from {}".format(dist, dist.location), V=9
            )
            return
        self._ensure_unfrozen("Adding a distribution")
        dist_name = os.path.basename(dist.location)
        self._distributions[dist.location] = dist

        if dist.type not in (DistributionType.WHEEL, DistributionType.INSTALLED):
            raise self.InvalidDistribution(
                "Unsupported distribution type: {}, pex can only accept wheel files and dist "
                "dirs (installed wheels).".format(dist)
            )
        dist_hash = self._add_dist(
            dist.location,
            dist_name,
            fingerprint=fingerprint,
            is_wheel_file=dist.type is DistributionType.WHEEL,
        )


        self._pex_info.add_distribution(dist_name, dist_hash)

    def add_dist_location(
        self,
        dist,
        fingerprint=None,
    ):
        # type: (...) -> None
        self._ensure_unfrozen("Adding a distribution")
        try:
            distribution = Distribution.load(dist)
        except MetadataError as e:
            raise self.InvalidDistribution(str(e))
        self.add_distribution(distribution, fingerprint=fingerprint)
        self.add_requirement(distribution.as_requirement())

    @property
    def distributions(self):
        # type: () -> Iterable[Distribution]
        return self._distributions.values()

    def _precompile_source(self):
        vendored_dir = os.path.join(self._pex_info.bootstrap, "pex/vendor/_vendored")
        source_relpaths = [
            path
            for label in ("source", "executable", "main", "bootstrap")
            for path in self._chroot.filesets.get(label, ())
            if path.endswith(".py")


            and vendored_dir != safe_commonpath((vendored_dir, path))
        ]

        compiler = Compiler(self.interpreter)
        compiled_relpaths = compiler.compile(self._chroot.path(), source_relpaths)
        for compiled in compiled_relpaths:
            self._chroot.touch(compiled, label="bytecode")

    def _prepare_code(self):
        chroot_path = self._chroot.path()
        self._pex_info.code_hash = CacheHelper.pex_code_hash(
            chroot_path, exclude_dirs=(layout.BOOTSTRAP_DIR, layout.DEPS_DIR)
        )
        self._pex_info.pex_hash = hashlib.sha1(self._pex_info.dump().encode("utf-8")).hexdigest()
        self._chroot.write(self._pex_info.dump().encode("utf-8"), PexInfo.PATH, label="manifest")

        with open(os.path.join(_ABS_PEX_PACKAGE_DIR, "pex_boot.py")) as fp:
            pex_boot = fp.read()

        is_venv = self._pex_info.venv
        hermetic_boot = (is_venv and self._pex_info.venv_hermetic_scripts) or (
            not is_venv and self._pex_info.inherit_path is InheritPath.FALSE
        )

        pex_main = dedent(
            """
            result, should_exit, is_globals = boot(
                bootstrap_dir={bootstrap_dir!r},
                pex_root={pex_root!r},
                pex_hash={pex_hash!r},
                hermetic_boot={hermetic_boot!r},
                has_interpreter_constraints={has_interpreter_constraints!r},
                pex_path={pex_path!r},
                is_venv={is_venv!r},
                inject_python_args={inject_python_args!r},
            )
            if should_exit:
                sys.exit(0 if is_globals else result)
            elif is_globals:
                globals().update(result)
            """
        ).format(
            bootstrap_dir=self._pex_info.bootstrap,
            pex_root=self._pex_info.raw_pex_root,
            pex_hash=self._pex_info.pex_hash,
            hermetic_boot=hermetic_boot,
            has_interpreter_constraints=bool(self._pex_info.interpreter_constraints),
            pex_path=self._pex_info.pex_path,
            is_venv=is_venv,
            inject_python_args=self._pex_info.inject_python_args,
        )
        bootstrap = pex_boot + "\n" + pex_main

        self._chroot.write(
            data=to_bytes(self._shebang + "\n" + self._preamble + "\n" + bootstrap),
            dst="__main__.py",
            executable=True,
            label="main",
        )
        self._chroot.write(
            data=to_bytes(bootstrap),
            dst=os.path.join("__pex__", "__init__.py"),
            label="importhook",
        )

    def _copy_or_link(
        self,
        src,
        dst,
        label=None,
        compress=True,
        copy_mode=None,
    ):
        copy_mode = copy_mode or self._copy_mode
        if src is None:
            self._chroot.touch(dst, label)
        elif copy_mode is CopyMode.COPY:
            self._chroot.copy(src, dst, label, compress)
        elif copy_mode is CopyMode.SYMLINK:
            self._chroot.symlink(src, dst, label, compress)
        else:
            self._chroot.link(src, dst, label, compress)

    def _prepare_bootstrap(self):
        from . import vendor


        root_module_names = ["appdirs", "attr", "colors", "packaging", "pyparsing"]
        for vendor_spec in vendor.iter_vendor_specs():
            if vendor_spec.key == "setuptools":
                root_module_names.append("pkg_resources")

        prepared_sources = vendor.vendor_runtime(
            chroot=self._chroot,
            dest_basedir=self._pex_info.bootstrap,
            label="bootstrap",
            root_module_names=root_module_names,
        )

        bootstrap_digest = hashlib.sha1()
        bootstrap_packages = ["cache", "fs", "repl", "third_party", "venv", "windows"]
        if self._pex_info.includes_tools:
            bootstrap_packages.extend(["commands", "tools"])


        for root, dirs, files in deterministic_walk(_ABS_PEX_PACKAGE_DIR):
            if root == _ABS_PEX_PACKAGE_DIR:
                dirs[:] = bootstrap_packages

            for f in files:
                if is_pyc_file(f):
                    continue
                abs_src = os.path.join(root, f)


                if abs_src in prepared_sources:
                    continue
                with open(abs_src, "rb") as fp:
                    data = fp.read()
                self._chroot.write(
                    data,
                    dst=os.path.join(
                        self._pex_info.bootstrap,
                        "pex",
                        os.path.relpath(abs_src, _ABS_PEX_PACKAGE_DIR),
                    ),
                    label="bootstrap",
                )
                bootstrap_digest.update(data)

        self._pex_info.bootstrap_hash = bootstrap_digest.hexdigest()

    def freeze(self, bytecode_compile=True):
        self._ensure_unfrozen("Freezing the environment")
        self._prepare_bootstrap()
        self._prepare_code()
        if bytecode_compile:
            self._precompile_source()
        self._frozen = True

    def build(
        self,
        path,
        bytecode_compile=True,
        deterministic=False,
        layout=Layout.ZIPAPP,
        compress=True,
        check=Check.NONE,
    ):
        # type: (...) -> None
        if not self._frozen:
            self.freeze(bytecode_compile=bytecode_compile)


        tmp_pex = path + "~"
        if os.path.exists(tmp_pex):
            self._logger.warning("Previous binary unexpectedly exists, cleaning: {}".format(path))
            if os.path.isfile(tmp_pex):
                os.unlink(tmp_pex)
            else:
                shutil.rmtree(tmp_pex, True)

        if layout == Layout.LOOSE:
            shutil.copytree(
                self.path(),
                tmp_pex,
                ignore=None if bytecode_compile else lambda _, names: filter(is_pyc_file, names),
            )
        elif layout == Layout.PACKED:
            self._build_packedapp(
                dirname=tmp_pex,
                deterministic=deterministic,
                compress=compress,
                bytecode_compile=bytecode_compile,
            )
        else:
            self._build_zipapp(
                filename=tmp_pex,
                deterministic=deterministic,
                compress=compress,
                bytecode_compile=bytecode_compile,
            )
        if layout in (Layout.LOOSE, Layout.PACKED):
            pex_script = os.path.join(tmp_pex, "pex")
            if self._header:
                main_py = os.path.join(tmp_pex, "__main__.py")
                with open(pex_script, "w") as script_fp:
                    print(self._shebang, file=script_fp)
                    print(self._header, file=script_fp)
                    with open(main_py) as main_fp:
                        main_fp.readline()
                        shutil.copyfileobj(main_fp, script_fp)
                chmod_plus_x(pex_script)
                safe_rename(pex_script, main_py)
            safe_symlink("__main__.py", pex_script)

        if os.path.isdir(path):
            shutil.rmtree(path, True)
        elif os.path.isdir(tmp_pex):
            safe_delete(path)
        check.perform_check(layout, tmp_pex)
        safe_rename(tmp_pex, path)

    def set_sh_boot_script(
        self,
        pex_name,
        targets,
        python_shebang,
        layout=Layout.ZIPAPP,
    ):
        if not self._frozen:
            raise Exception("Generating a sh_boot script requires the pex to be frozen.")

        script = create_sh_boot_script(
            pex_name=pex_name,
            pex_info=self._pex_info,
            targets=targets,
            interpreter=self.interpreter,
            python_shebang=python_shebang,
            layout=layout,
        )
        if layout is Layout.ZIPAPP:
            self.set_shebang("/bin/sh")
            self.set_header(script)
        else:
            shebang, header = create_sh_python_redirector_shebang(script)
            self.set_shebang(shebang)
            self.set_header(header)

    def _build_packedapp(
        self,
        dirname,
        deterministic=False,
        compress=True,
        bytecode_compile=False,
    ):
        # type: (...) -> None

        pex_info = self._pex_info.copy()
        pex_info.update(PexInfo.from_env())


        for fileset in ("executable", "importhook", "main", "manifest", "resource", "source"):
            for f in self._chroot.filesets.get(fileset, ()):
                dest = os.path.join(dirname, f)
                safe_mkdir(os.path.dirname(dest))
                safe_copy(os.path.realpath(os.path.join(self._chroot.chroot, f)), dest)


        if pex_info.bootstrap_hash is None:
            raise AssertionError(
                "Expected bootstrap_hash to be populated for {}.".format(self._pex_info)
            )
        cached_bootstrap_zip_dir = BootstrapZipDir.create(
            pex_info.bootstrap_hash, compress=compress, pex_root=pex_info.pex_root
        )
        with TRACER.timed("Zipping PEX .bootstrap/ code."):
            with atomic_directory(cached_bootstrap_zip_dir) as atomic_bootstrap_zip_dir:
                if not atomic_bootstrap_zip_dir.is_finalized():
                    self._chroot.zip(
                        os.path.join(atomic_bootstrap_zip_dir.work_dir, pex_info.bootstrap),
                        deterministic=deterministic,
                        exclude_file=is_pyc_temporary_file if bytecode_compile else is_pyc_file,
                        strip_prefix=pex_info.bootstrap,
                        labels=("bootstrap",),
                        compress=compress,
                    )
        safe_copy(
            os.path.join(cached_bootstrap_zip_dir, pex_info.bootstrap),
            os.path.join(dirname, pex_info.bootstrap),
        )


        if pex_info.distributions:
            internal_cache = os.path.join(dirname, pex_info.internal_cache)
            os.mkdir(internal_cache)
            with TRACER.timed(
                "{action} {count} distributions.".format(
                    action="Copying" if pex_info.deps_are_wheel_files else "Zipping",
                    count=len(pex_info.distributions),
                )
            ):
                for location, fingerprint in pex_info.distributions.items():
                    dest = os.path.join(internal_cache, location)
                    if pex_info.deps_are_wheel_files:
                        for path in self._chroot.filesets[location]:
                            safe_copy(os.path.join(self._chroot.chroot, path), dest)
                    else:
                        cached_installed_wheel_zip_dir = PackedWheelDir.create(
                            fingerprint, compress, pex_root=pex_info.pex_root
                        )
                        with atomic_directory(cached_installed_wheel_zip_dir) as atomic_zip_dir:
                            if not atomic_zip_dir.is_finalized():
                                self._chroot.zip(
                                    os.path.join(atomic_zip_dir.work_dir, location),
                                    deterministic=deterministic,
                                    exclude_file=(
                                        is_pyc_temporary_file if bytecode_compile else is_pyc_file
                                    ),
                                    strip_prefix=os.path.join(pex_info.internal_cache, location),
                                    labels=(location,),
                                    compress=compress,
                                )
                        safe_copy(os.path.join(cached_installed_wheel_zip_dir, location), dest)

    def _build_zipapp(
        self,
        filename,
        deterministic=False,
        compress=True,
        bytecode_compile=False,
    ):
        # type: (...) -> None
        with safe_open(filename, "wb") as pexfile:
            assert os.path.getsize(pexfile.name) == 0
            pexfile.write(to_bytes("{}\n".format(self._shebang)))
            if self._header:
                pexfile.write(to_bytes(self._header))
        with TRACER.timed("Zipping PEX file."):
            self._chroot.zip(
                filename,
                mode="a",
                deterministic=deterministic,


                exclude_file=is_pyc_temporary_file if bytecode_compile else is_pyc_file,
                compress=compress,
            )
        chmod_plus_x(filename)
