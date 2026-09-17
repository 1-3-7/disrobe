

from __future__ import absolute_import

import json
import os
import re
import subprocess
import sys
import sysconfig
from collections import OrderedDict
from contextlib import contextmanager
from textwrap import dedent

from pex import third_party
from pex.cache.dirs import InterpreterDir
from pex.common import safe_mkdtemp, safe_rmtree
from pex.exceptions import production_assert
from pex.executor import Executor
from pex.interpreter_implementation import InterpreterImplementation
from pex.jobs import Job, Retain, SpawnedJob, execute_parallel
from pex.orderedset import OrderedSet
from pex.os import WINDOWS, is_exe
from pex.pep_425 import CompatibilityTags
from pex.pep_508 import MarkerEnvironment
from pex.platforms import Platform
from pex.pth import iter_pth_paths
from pex.pyenv import Pyenv
from pex.sysconfig import EXE_EXTENSION, SCRIPT_DIR, script_name
from pex.third_party.packaging import __version__ as packaging_version
from pex.third_party.packaging import tags
from pex.tracer import TRACER
from pex.typing import TYPE_CHECKING, cast, overload

if TYPE_CHECKING:
    from typing import (
        Any,
        AnyStr,
        Callable,
        Dict,
        Iterable,
        Iterator,
        List,
        Mapping,
        MutableMapping,
        Optional,
        Text,
        Tuple,
        Union,
    )

    PathFilter = Callable[[str], bool]

    InterpreterIdentificationJobError = Tuple[str, Union[Job.Error, Exception]]
    InterpreterOrJobError = Union["PythonInterpreter", InterpreterIdentificationJobError]


    InterpreterIdentificationError = Tuple[str, Text]
    InterpreterOrError = Union["PythonInterpreter", InterpreterIdentificationError]


class SitePackagesDir(object):
    def __init__(self, path):
        # type: (str) -> None
        self._path = os.path.realpath(path)

    @property
    def path(self):
        # type: () -> str
        return self._path

    def __repr__(self):
        # type: () -> str
        return "{class_name}({path})".format(class_name=self.__class__.__name__, path=self._path)

    def __eq__(self, other):
        # type: (Any) -> bool
        return type(self) is type(other) and self._path == other._path

    def __ne__(self, other):
        # type: (Any) -> bool
        return not self == other

    def __hash__(self):
        # type: () -> int
        return hash((type(self), self._path))


class Purelib(SitePackagesDir):
    pass


class Platlib(SitePackagesDir):
    pass


_PATH_MAPPINGS = {}


@contextmanager
def path_mapping(
    current_path,
    final_path,
):
    # type: (...) -> Iterator[None]

    _PATH_MAPPINGS[current_path] = final_path
    try:
        yield
    finally:
        _PATH_MAPPINGS.pop(current_path)


@contextmanager
def path_mappings(mappings):
    # type: (Mapping[str, str]) -> Iterator[None]

    _PATH_MAPPINGS.update(mappings)
    try:
        yield
    finally:
        for current_path in mappings:
            _PATH_MAPPINGS.pop(current_path)


def adjust_to_final_path(path):
    # type: (str) -> str
    for current_path, final_path in _PATH_MAPPINGS.items():
        if path.startswith(current_path):
            return final_path + path[len(current_path) :]
    return path


def _adjust_to_current_path(path):
    # type: (str) -> str
    for current_path, final_path in _PATH_MAPPINGS.items():
        if path.startswith(final_path):
            return current_path + path[len(final_path) :]
    return path


class PythonIdentity(object):
    class Error(Exception):
        pass

    class InvalidError(Error):
        pass

    class UnknownRequirement(Error):
        pass

    ABBR_TO_INTERPRETER_NAME = {
        "pp": "PyPy",
        "cp": "CPython",
    }

    @staticmethod
    def _normalize_macosx_deployment_target(value):
        # type: (Any) -> Optional[str]


        if value is None:
            return None
        return str(value)

    @staticmethod
    def _site_packages_dirs():
        # type: () -> Iterable[SitePackagesDir]


        site_packages = OrderedDict()
        try:
            from site import getsitepackages

            for path in getsitepackages():
                entry = SitePackagesDir(path)
                site_packages[entry.path] = entry
        except ImportError as e:


            TRACER.log("The site module does not define getsitepackages: {err}".format(err=e))


        try:
            import sysconfig

            get_default_scheme = getattr(sysconfig, "get_default_scheme", None)
            if get_default_scheme and sys.version_info[:2] >= (3, 11):
                scheme = get_default_scheme()

                purelib = Purelib(sysconfig.get_path("purelib", scheme))
                site_packages[purelib.path] = purelib

                platlib = Platlib(sysconfig.get_path("platlib", scheme))
                site_packages[platlib.path] = platlib

                return site_packages.values()
        except ImportError:
            pass


        try:
            from distutils.sysconfig import get_python_lib

            purelib = Purelib(get_python_lib(plat_specific=False))
            site_packages[purelib.path] = purelib

            platlib = Platlib(get_python_lib(plat_specific=True))
            site_packages[platlib.path] = platlib
        except ImportError:
            pass

        return site_packages.values()

    @staticmethod
    def _iter_extras_paths(site_packages):
        # type: (Iterable[SitePackagesDir]) -> Iterator[str]


        for entry in site_packages:
            dir_path = entry.path
            if not os.path.isdir(dir_path):
                continue
            for file in os.listdir(dir_path):
                if not file.endswith(".pth"):
                    continue
                pth_path = os.path.join(dir_path, file)
                TRACER.log("Found .pth file: {pth_file}".format(pth_file=pth_path), V=3)
                for extras_path in iter_pth_paths(pth_path):
                    yield extras_path

    @classmethod
    def get(cls, binary=None):
        # type: (Optional[str]) -> PythonIdentity


        if binary and binary != sys.executable and "__PYVENV_LAUNCHER__" not in os.environ:

            binary = sys.executable

        supported_tags = tuple(tags.sys_tags())
        preferred_tag = supported_tags[0]

        sys_config_vars = sysconfig.get_config_vars()

        configured_macosx_deployment_target = cls._normalize_macosx_deployment_target(
            sys_config_vars.get("MACOSX_DEPLOYMENT_TARGET")
        )

        pypy_version = cast(
            "Optional[Tuple[int, int, int]]",
            tuple(getattr(sys, "pypy_version_info", ())[:3]) or None,
        )
        if pypy_version is None:
            free_threaded = (
                sys.version_info[:2] >= (3, 13) and sys_config_vars.get("Py_GIL_DISABLED", 0) == 1
            )
        else:
            free_threaded = None


        pythonpath = os.environ.get("PYTHONPATH")
        internal_entries = frozenset(
            (pythonpath.split(os.pathsep) if pythonpath else []) + list(third_party.exposed())
        )
        sys_path = OrderedSet(
            entry for entry in sys.path if entry and entry not in internal_entries
        )

        site_packages = OrderedSet(
            site_packages_dir
            for site_packages_dir in cls._site_packages_dirs()


            if site_packages_dir.path != sys.prefix
        )

        extras_paths = OrderedSet(cls._iter_extras_paths(site_packages=site_packages))

        return cls(
            binary=binary or sys.executable,
            prefix=sys.prefix,
            base_prefix=(

                cast("Optional[str]", getattr(sys, "real_prefix", None))


                or cast(str, getattr(sys, "base_prefix", sys.prefix))
            ),
            sys_path=sys_path,
            site_packages=site_packages,
            extras_paths=extras_paths,
            paths=sysconfig.get_paths(),
            packaging_version=packaging_version,
            python_tag=preferred_tag.interpreter,
            abi_tag=preferred_tag.abi,
            platform_tag=preferred_tag.platform,
            version=cast("Tuple[int, int, int]", tuple(sys.version_info[:3])),
            pypy_version=pypy_version,
            supported_tags=supported_tags,
            env_markers=MarkerEnvironment.default(),
            configured_macosx_deployment_target=configured_macosx_deployment_target,
            free_threaded=free_threaded,
        )


    _FORMAT_VERSION = 1

    @classmethod
    def decode(cls, encoded):
        # type: (Text) -> PythonIdentity
        TRACER.log("creating PythonIdentity from encoded: {encoded}".format(encoded=encoded), V=9)
        values = json.loads(encoded)
        if len(values) != 20:
            raise cls.InvalidError(
                "Invalid interpreter identity: {encoded}".format(encoded=encoded)
            )
        try:
            format_version = int(values.pop("__format_version__", "0"))
        except ValueError as e:
            raise cls.InvalidError(
                "The PythonIdentity __format_version__ is invalid: {err}".format(err=e)
            )
        else:
            if format_version < cls._FORMAT_VERSION:
                raise cls.InvalidError(
                    "The PythonIdentity __format_version__ was {format_version}, but the current "
                    "version is {current_version}. Upgrading existing encoding: {encoded}".format(
                        format_version=format_version,
                        current_version=cls._FORMAT_VERSION,
                        encoded=encoded,
                    )
                )

        version = tuple(values.pop("version"))
        pypy_version = tuple(values.pop("pypy_version") or ()) or None

        supported_tags = values.pop("supported_tags")

        def iter_tags():
            for (interpreter, abi, platform) in supported_tags:
                yield tags.Tag(interpreter=interpreter, abi=abi, platform=platform)


        configured_macosx_deployment_target = cls._normalize_macosx_deployment_target(
            values.pop("configured_macosx_deployment_target")
        )

        env_markers = MarkerEnvironment(**values.pop("env_markers"))

        site_packages_paths = values.pop("site_packages")
        purelib = values.pop("purelib")
        platlib = values.pop("platlib")
        site_packages = []
        for path in site_packages_paths:
            if path == purelib:
                site_packages.append(Purelib(_adjust_to_current_path(path)))
            elif path == platlib:
                site_packages.append(Platlib(_adjust_to_current_path(path)))
            else:
                site_packages.append(SitePackagesDir(_adjust_to_current_path(path)))

        return cls(
            binary=_adjust_to_current_path(values.pop("binary")),
            prefix=_adjust_to_current_path(values.pop("prefix")),
            base_prefix=_adjust_to_current_path(values.pop("base_prefix")),
            sys_path=[_adjust_to_current_path(entry) for entry in values.pop("sys_path")],
            site_packages=site_packages,
            extras_paths=[
                _adjust_to_current_path(extras_path) for extras_path in values.pop("extras_paths")
            ],
            paths={
                name: _adjust_to_current_path(path) for name, path in values.pop("paths").items()
            },
            version=cast("Tuple[int, int, int]", version),
            pypy_version=cast("Optional[Tuple[int, int, int]]", pypy_version),
            supported_tags=iter_tags(),
            configured_macosx_deployment_target=configured_macosx_deployment_target,
            env_markers=env_markers,
            **values
        )

    @classmethod
    def _find_implementation(
        cls,
        python_tag,
        free_threaded,
        version,
    ):
        # type: (...) -> InterpreterImplementation.Value
        for implementation in InterpreterImplementation.values():
            if (
                implementation.applies(version)
                and python_tag.startswith(implementation.abbr)
                and (implementation.free_threaded == free_threaded)
            ):
                return implementation
        raise ValueError("Unknown interpreter: {}".format(python_tag))

    def __init__(
        self,
        binary,
        prefix,
        base_prefix,
        sys_path,
        site_packages,
        extras_paths,
        paths,
        packaging_version,
        python_tag,
        abi_tag,
        platform_tag,
        version,
        pypy_version,
        supported_tags,
        env_markers,
        configured_macosx_deployment_target,
        free_threaded,
    ):
        # type: (...) -> None

        self._implementation = self._find_implementation(python_tag, free_threaded, version)
        production_assert(
            not pypy_version or self._implementation is InterpreterImplementation.PYPY
        )
        self._pypy_version = pypy_version

        self._binary = binary
        self._prefix = prefix
        self._base_prefix = base_prefix
        self._sys_path = tuple(sys_path)
        self._site_packages = tuple(site_packages)
        self._extras_paths = tuple(extras_paths)
        self._paths = dict(paths)
        self._packaging_version = packaging_version
        self._python_tag = python_tag
        self._abi_tag = abi_tag
        self._platform_tag = platform_tag
        self._version = version
        self._supported_tags = CompatibilityTags(tags=supported_tags)
        self._env_markers = env_markers
        self._configured_macosx_deployment_target = configured_macosx_deployment_target
        self._free_threaded = free_threaded

    def encode(self):
        # type: () -> str
        site_packages = []
        purelib = None
        platlib = None
        for entry in self._site_packages:
            entry_path = adjust_to_final_path(entry.path)
            site_packages.append(entry_path)
            if isinstance(entry, Purelib):
                purelib = entry_path
            elif isinstance(entry, Platlib):
                platlib = entry_path

        values = dict(
            __format_version__=self._FORMAT_VERSION,
            binary=adjust_to_final_path(self._binary),
            prefix=adjust_to_final_path(self._prefix),
            base_prefix=adjust_to_final_path(self._base_prefix),
            sys_path=[adjust_to_final_path(entry) for entry in self._sys_path],
            site_packages=site_packages,


            purelib=purelib,
            platlib=platlib,
            extras_paths=[adjust_to_final_path(extras_path) for extras_path in self._extras_paths],
            paths={name: adjust_to_final_path(path) for name, path in self._paths.items()},
            packaging_version=self._packaging_version,
            python_tag=self._python_tag,
            abi_tag=self._abi_tag,
            platform_tag=self._platform_tag,
            version=self._version,
            pypy_version=self._pypy_version,
            supported_tags=[
                (tag.interpreter, tag.abi, tag.platform) for tag in self._supported_tags
            ],
            env_markers=self._env_markers.as_dict(),
            configured_macosx_deployment_target=self._configured_macosx_deployment_target,
            free_threaded=self._free_threaded,
        )
        return json.dumps(values, sort_keys=True, separators=(",", ":"))

    @property
    def binary(self):
        # type: () -> str
        return self._binary

    @property
    def is_venv(self):
        # type: () -> bool
        return self._prefix != self._base_prefix

    @property
    def prefix(self):
        # type: () -> str
        return self._prefix

    @property
    def base_prefix(self):
        # type: () -> str
        return self._base_prefix

    @property
    def sys_path(self):
        # type: () -> Tuple[str, ...]
        return self._sys_path

    @property
    def site_packages(self):
        # type: () -> Tuple[SitePackagesDir, ...]
        return self._site_packages

    @property
    def extras_paths(self):
        # type: () -> Tuple[str, ...]
        return self._extras_paths

    @property
    def paths(self):
        # type: () -> Mapping[str, str]
        return self._paths

    @property
    def python_tag(self):
        # type: () -> str
        return self._python_tag

    @property
    def abi_tag(self):
        # type: () -> str
        return self._abi_tag

    @property
    def platform_tag(self):
        # type: () -> str
        return self._platform_tag

    @property
    def version(self):
        # type: () -> Tuple[int, int, int]
        return self._version

    @property
    def pypy_version(self):
        # type: () -> Optional[Tuple[int, int, int]]
        return self._pypy_version

    @property
    def is_pypy(self):
        # type: () -> bool
        return self._implementation is InterpreterImplementation.PYPY

    @property
    def free_threaded(self):
        # type: () -> Optional[bool]
        return self._free_threaded

    @property
    def version_str(self):
        # type: () -> str
        return ".".join(map(str, self.version))

    @property
    def supported_tags(self):
        # type: () -> CompatibilityTags
        return self._supported_tags

    @property
    def env_markers(self):
        # type: () -> MarkerEnvironment
        return self._env_markers

    @property
    def configured_macosx_deployment_target(self):
        # type: () -> Optional[str]
        return self._configured_macosx_deployment_target

    @property
    def implementation(self):
        # type: () -> InterpreterImplementation.Value
        return self._implementation

    def iter_supported_platforms(self):
        # type: () -> Iterator[Platform]
        yield Platform(
            platform=self._platform_tag,
            impl=self.python_tag[:2],
            version=self.version_str,
            version_info=self.version,
            abi=self.abi_tag,
            supported_tags=self._supported_tags,
        )
        for index in range(len(self._supported_tags)):
            yield Platform.from_tags(self._supported_tags[index:])

    def binary_name(self, version_components=2):
        # type: (int) -> str
        return self._implementation.calculate_binary_name(
            version=self._version[:version_components] if version_components > 0 else None
        )

    def hashbang(self):
        # type: () -> str
        return "#!/usr/bin/env {}".format(
            self.binary_name(version_components=0 if self.is_pypy and self.version[0] == 2 else 2)
        )

    @property
    def python(self):
        # type: () -> str


        return "%d.%d" % (self.version[0:2])

    def __str__(self):
        # type: () -> str


        return "{implementation}-{major}.{minor}.{patch}".format(
            implementation=self._implementation,
            major=self._version[0],
            minor=self._version[1],
            patch=self._version[2],
        )

    def __repr__(self):
        # type: () -> str
        return (
            "{type}({binary!r}, {python_tag!r}, {abi_tag!r}, {platform_tag!r}, {version!r})".format(
                type=self.__class__.__name__,
                binary=self._binary,
                python_tag=self._python_tag,
                abi_tag=self._abi_tag,
                platform_tag=self._platform_tag,
                version=self._version,
            )
        )

    def _tup(self):
        # type: () -> Tuple[str, str, str, str, Tuple[int, int, int]]
        return self._binary, self._python_tag, self._abi_tag, self._platform_tag, self._version

    def __eq__(self, other):
        # type: (Any) -> bool
        if isinstance(other, PythonIdentity):
            return self._tup() == other._tup()
        return NotImplemented

    def __hash__(self):
        # type: () -> int
        return hash(self._tup())


class PyVenvCfg(object):

    class Error(ValueError):

    @classmethod
    def parse(cls, path):
        # type: (str) -> PyVenvCfg

        config = {}
        with open(path) as fp:
            for line in fp:
                raw_name, delimiter, raw_value = line.partition("=")
                if delimiter != "=":
                    continue
                config[raw_name.strip()] = raw_value.strip()
        if "home" not in config:
            raise cls.Error("No home config key in {pyvenv_cfg}.".format(pyvenv_cfg=path))
        return cls(path, **config)

    @classmethod
    def _get_pyvenv_cfg(cls, path):
        # type: (str) -> Optional[PyVenvCfg]

        pyvenv_cfg_path = os.path.join(path, "pyvenv.cfg")
        if os.path.isfile(pyvenv_cfg_path):
            try:
                return cls.parse(pyvenv_cfg_path)
            except cls.Error:
                pass
        return None

    @classmethod
    def find(cls, python_binary):
        # type: (str) -> Optional[PyVenvCfg]


        maybe_venv_bin_dir = os.path.dirname(python_binary)
        pyvenv_cfg = cls._get_pyvenv_cfg(maybe_venv_bin_dir)
        if not pyvenv_cfg:
            maybe_venv_dir = os.path.dirname(maybe_venv_bin_dir)
            pyvenv_cfg = cls._get_pyvenv_cfg(maybe_venv_dir)
        return pyvenv_cfg

    def __init__(
        self,
        path,
        **config
    ):
        # type: (...) -> None
        self._path = path
        self._config = config

    @property
    def path(self):
        # type: () -> str
        return self._path

    @property
    def home(self):
        # type: () -> str
        return self._config["home"]

    @overload
    def config(
        self,
        key,
        default=None,
    ):
        # type: (...) -> Optional[str]
        pass

    @overload
    def config(
        self,
        key,
        default,
    ):
        # type: (...) -> str
        pass

    def config(
        self,
        key,
        default=None,
    ):
        # type: (...) -> Optional[str]
        return self._config.get(key, default)

    @property
    def include_system_site_packages(self):
        # type: () -> Optional[bool]
        value = self.config("include-system-site-packages")
        return value.lower() == "true" if value else None


class PythonInterpreter(object):
    _REGEX = re.compile(
        r"""
        ^
        (?:
            python |
            pypy
        )
        (?:
            # Major version
            [2-9]
            (?:.
                # Minor version
                [0-9]+
                # Some distributions include a suffix on the interpreter name, similar to
                # PEP-3149. For example, Gentoo has /usr/bin/python3.6m to indicate it was
                # built with pymalloc
                [a-z]?
            )?
        )?
        {extension}
        $
        """.format(
            extension=re.escape(EXE_EXTENSION)
        ),


        flags=re.IGNORECASE | re.VERBOSE,
    )

    _PYTHON_INTERPRETER_BY_NORMALIZED_PATH = {}

    @classmethod
    @contextmanager
    def _cleared_memory_cache(cls):
        # type: () -> Iterator[None]


        _cache = cls._PYTHON_INTERPRETER_BY_NORMALIZED_PATH.copy()
        cls._PYTHON_INTERPRETER_BY_NORMALIZED_PATH = {}
        try:
            yield
        finally:
            cls._PYTHON_INTERPRETER_BY_NORMALIZED_PATH = _cache

    @classmethod
    def _resolve_pyvenv_canonical_python_binary(
        cls,
        maybe_venv_python_binary,
    ):
        # type: (...) -> Optional[str]
        maybe_venv_python_binary = os.path.abspath(maybe_venv_python_binary)
        if not os.path.islink(maybe_venv_python_binary):
            return None

        pyvenv_cfg = PyVenvCfg.find(maybe_venv_python_binary)
        if pyvenv_cfg is None:
            return None

        while os.path.islink(maybe_venv_python_binary):
            resolved = os.readlink(maybe_venv_python_binary)
            if not os.path.isabs(resolved):
                resolved = os.path.abspath(
                    os.path.join(os.path.dirname(maybe_venv_python_binary), resolved)
                )
            if os.path.dirname(resolved) == os.path.dirname(maybe_venv_python_binary):
                maybe_venv_python_binary = resolved
            else:


                break
        return maybe_venv_python_binary

    @classmethod
    def canonicalize_path(cls, path):
        # type: (str) -> str


        return cls._resolve_pyvenv_canonical_python_binary(
            maybe_venv_python_binary=path
        ) or os.path.realpath(path)

    class Error(Exception):
        pass

    class IdentificationError(Error):
        pass

    class InterpreterNotFound(Error):
        pass

    @staticmethod
    def latest_release_of_min_compatible_version(interps):
        # type: (Iterable[PythonInterpreter]) -> PythonInterpreter
        assert interps, "No interpreters passed to `PythonInterpreter.safe_min()`"
        return min(
            interps, key=lambda interp: (interp.version[0], interp.version[1], -interp.version[2])
        )

    @classmethod
    def get(cls):
        # type: () -> PythonInterpreter
        return cls.from_binary(sys.executable)

    @staticmethod
    def _paths(paths=None):
        # type: (Optional[Iterable[str]]) -> Iterable[str]

        return OrderedSet(paths if paths is not None else os.getenv("PATH", "").split(os.pathsep))

    @classmethod
    def iter(cls, paths=None):
        # type: (Optional[Iterable[str]]) -> Iterator[PythonInterpreter]
        return cls._filter(cls._find(cls._paths(paths=paths)))

    @classmethod
    def iter_candidates(cls, paths=None, path_filter=None):
        # type: (Optional[Iterable[str]], Optional[PathFilter]) -> Iterator[InterpreterOrError]
        failed_interpreters = OrderedDict()

        def iter_interpreters():
            # type: () -> Iterator[PythonInterpreter]
            for candidate in cls._find(
                cls._paths(paths=paths), path_filter=path_filter, error_handler=Retain[str]()
            ):
                if isinstance(candidate, cls):
                    yield candidate
                else:
                    python, exception = cast("InterpreterIdentificationJobError", candidate)
                    if isinstance(exception, Job.Error) and exception.stderr:


                        failed_interpreters[python] = exception.stderr.strip()
                    else:


                        failed_interpreters[python] = repr(exception)

        for interpreter in cls._filter(iter_interpreters()):
            yield interpreter

        for python, error in failed_interpreters.items():
            yield python, error

    @classmethod
    def all(cls, paths=None):
        # type: (Optional[Iterable[str]]) -> Iterable[PythonInterpreter]
        return list(cls.iter(paths=paths))

    @classmethod
    def _create_isolated_cmd(
        cls,
        binary,
        args=None,
        pythonpath=None,
        env=None,
        version=None,
    ):
        # type: (...) -> Tuple[Iterable[str], Mapping[str, str]]
        cmd = [binary]

        env = cls._sanitized_environment(env=env)
        pythonpath = list(pythonpath or ())
        if pythonpath:
            env["PYTHONPATH"] = os.pathsep.join(pythonpath)


            env.pop("PYTHONINSPECT", None)


            cmd.append("-s")


            if version and version >= (3, 11):
                cmd.append("-P")
        elif version and version[:2] >= (3, 4):
            cmd.append("-I")
        else:

            cmd.append("-s")


            cmd.append("-E")

        if args:
            cmd.extend(args)

        rendered_command = " ".join(cmd)
        if pythonpath:
            rendered_command = "PYTHONPATH={} {}".format(env["PYTHONPATH"], rendered_command)
        TRACER.log("Executing: {}".format(rendered_command), V=3)

        return cmd, env


    _PYENV = ()

    @classmethod
    def _pyenv(cls):
        # type: () -> Optional[Pyenv]
        if isinstance(cls._PYENV, tuple):
            cls._PYENV = Pyenv.find()
        return cls._PYENV

    @classmethod
    def _resolve_pyenv_shim(
        cls,
        binary,
        pyenv=None,
        cwd=None,
    ):
        # type: (...) -> Optional[str]

        pyenv = pyenv or cls._pyenv()
        if pyenv is not None:
            shim = pyenv.as_shim(binary)
            if shim is not None:
                python = shim.select_version(search_dir=cwd)
                if python is None:
                    TRACER.log("Detected inactive pyenv shim: {}.".format(shim), V=3)
                else:
                    TRACER.log("Detected pyenv shim activated to {}: {}.".format(python, shim), V=3)
                return python
        return binary

    @classmethod
    def _spawn_from_binary_external(
        cls,
        binary,
        ignore_cached=False,
    ):
        # type: (...) -> SpawnedJob[PythonInterpreter]

        def create_interpreter(
            stdout,
            check_binary=False,
        ):
            # type: (...) -> PythonInterpreter
            identity = stdout.decode("utf-8").strip()
            if not identity:
                raise cls.IdentificationError("Could not establish identity of {}.".format(binary))
            interpreter = cls(PythonIdentity.decode(identity))


            if check_binary and not os.path.exists(interpreter.binary):
                raise cls.InterpreterNotFound(
                    "Cached interpreter for {} reports a binary of {}, which could not be found".format(
                        binary, interpreter.binary
                    )
                )
            return interpreter

        cache_dir = InterpreterDir.create(binary)
        if ignore_cached:
            safe_rmtree(cache_dir)
        if os.path.isfile(cache_dir.interp_info_file):
            try:
                with open(cache_dir.interp_info_file, "rb") as fp:
                    return SpawnedJob.completed(create_interpreter(fp.read(), check_binary=True))
            except (IOError, OSError, cls.Error, PythonIdentity.Error):
                safe_rmtree(cache_dir)
                return cls._spawn_from_binary_external(binary)
        else:
            pythonpath = tuple(third_party.expose(["pex"]))
            cmd, env = cls._create_isolated_cmd(
                binary,
                args=[
                    "-c",
                    dedent(
                        """\
                        from __future__ import absolute_import

                        import os
                        import sys

                        from pex import interpreter
                        from pex.atomic_directory import atomic_directory
                        from pex.common import safe_open
                        from pex.interpreter import PythonIdentity


                        with interpreter.path_mappings({path_mappings!r}):
                            encoded_identity = PythonIdentity.get(binary={binary!r}).encode()
                            with atomic_directory({cache_dir!r}) as cache_dir:
                                if not cache_dir.is_finalized():
                                    with safe_open(
                                        os.path.join(cache_dir.work_dir, {info_file!r}), 'w'
                                    ) as fp:
                                        fp.write(encoded_identity)
                        """.format(
                            path_mappings=_PATH_MAPPINGS,
                            binary=binary,
                            cache_dir=cache_dir.path,
                            info_file=InterpreterDir.INTERP_INFO_FILE,
                        )
                    ),
                ],
                pythonpath=pythonpath,
            )


            cwd = safe_mkdtemp()
            process = Executor.open_process(
                cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd
            )
            job = Job(command=cmd, process=process, finalizer=lambda _: safe_rmtree(cwd))
            return SpawnedJob.file(
                job, output_file=cache_dir.interp_info_file, result_func=create_interpreter
            )

    @classmethod
    def _expand_path(cls, path):
        if os.path.isfile(path):
            return [path]
        elif os.path.isdir(path):
            return sorted(os.path.join(path, fn) for fn in os.listdir(path))
        return []

    @classmethod
    def from_env(
        cls,
        hashbang,
        paths=None,
    ):
        # type: (...) -> Optional[PythonInterpreter]

        def hashbang_matches(fn):
            basefile = os.path.basename(fn)
            return hashbang == basefile

        for interpreter in cls._identify_interpreters(
            filter=hashbang_matches, error_handler=None, paths=paths
        ):
            return interpreter

        if WINDOWS and hashbang.startswith("python"):

            env = os.environ.copy()
            env["PYLAUNCHER_DRYRUN"] = "1"

            args = ["py"]
            version_part = hashbang[len("python") :]
            if version_part:
                args.append("-{version}".format(version=version_part))

            with open(os.devnull, "wb") as fp:
                process = subprocess.Popen(args=args, env=env, stdout=subprocess.PIPE, stderr=fp)
                stdout, _ = process.communicate()
                if process.returncode == 0:

                    result = cast(str, stdout.decode("utf-8").strip())
                    return cls.from_binary(result)

        return None

    @classmethod
    def _spawn_from_binary(
        cls,
        binary,
        ignore_cached=False,
    ):
        # type: (...) -> SpawnedJob[PythonInterpreter]
        canonicalized_binary = cls.canonicalize_path(binary)
        if not os.path.exists(canonicalized_binary):
            raise cls.InterpreterNotFound(
                "The interpreter path {} does not exist.".format(canonicalized_binary)
            )


        cached_interpreter = cls._PYTHON_INTERPRETER_BY_NORMALIZED_PATH.get(canonicalized_binary)
        if cached_interpreter is not None and not ignore_cached:
            return SpawnedJob.completed(cached_interpreter)
        return cls._spawn_from_binary_external(canonicalized_binary, ignore_cached=ignore_cached)

    @classmethod
    def from_binary(
        cls,
        binary,
        pyenv=None,
        cwd=None,
        ignore_cached=False,
    ):
        # type: (...) -> PythonInterpreter
        python = cls._resolve_pyenv_shim(binary, pyenv=pyenv, cwd=cwd)
        if python is None:
            raise cls.IdentificationError("The pyenv shim at {} is not active.".format(binary))

        try:
            return cast(
                PythonInterpreter,
                cls._spawn_from_binary(python, ignore_cached=ignore_cached).await_result(),
            )
        except Job.Error as e:
            raise cls.IdentificationError("Failed to identify {}: {}".format(binary, e))

    @classmethod
    def matches_binary_name(cls, path):
        # type: (str) -> bool
        return cls._REGEX.match(os.path.basename(path)) is not None

    @overload
    @classmethod
    def _find(cls, paths):
        # type: (Iterable[str]) -> Iterator[PythonInterpreter]
        pass

    @overload
    @classmethod
    def _find(
        cls,
        paths,
        error_handler,
        path_filter=None,
    ):
        # type: (...) -> Iterator[InterpreterOrJobError]
        pass

    @classmethod
    def _find(
        cls,
        paths,
        error_handler=None,
        path_filter=None,
    ):
        # type: (...) -> Union[Iterator[PythonInterpreter], Iterator[InterpreterOrJobError]]
        return cls._identify_interpreters(
            filter=path_filter or cls.matches_binary_name, paths=paths, error_handler=error_handler
        )

    @overload
    @classmethod
    def _identify_interpreters(
        cls,
        filter,
        error_handler,
        paths=None,
    ):
        # type: (...) -> Iterator[PythonInterpreter]
        pass

    @overload
    @classmethod
    def _identify_interpreters(
        cls,
        filter,
        error_handler,
        paths=None,
    ):
        # type: (...) -> Iterator[InterpreterOrJobError]
        pass

    @classmethod
    def _identify_interpreters(
        cls,
        filter,
        error_handler=None,
        paths=None,
    ):
        # type: (...) -> Union[Iterator[PythonInterpreter], Iterator[InterpreterOrJobError]]
        def iter_candidates():
            # type: () -> Iterator[str]
            for path in cls._paths(paths=paths):
                for fn in cls._expand_path(path):
                    if filter(fn):
                        binary = cls._resolve_pyenv_shim(fn)
                        if binary:
                            yield binary

        results = execute_parallel(
            inputs=OrderedSet(iter_candidates()),
            spawn_func=cls._spawn_from_binary,
            error_handler=error_handler,
        )
        return cast("Union[Iterator[PythonInterpreter], Iterator[InterpreterOrJobError]]", results)

    @classmethod
    def _filter(cls, pythons):
        # type: (Iterable[PythonInterpreter]) -> Iterator[PythonInterpreter]
        MAJOR, MINOR, SUBMINOR = range(3)

        def version_filter(version):
            # type: (Tuple[int, int, int]) -> bool
            return (
                version[MAJOR] == 2
                and version[MINOR] >= 7
                or version[MAJOR] == 3
                and version[MINOR] >= 5
            )

        seen = set()
        for interp in pythons:
            version = interp.identity.version
            identity = version, interp.identity.abi_tag
            if identity not in seen and version_filter(version):
                seen.add(identity)
                yield interp

    @classmethod
    def _sanitized_environment(cls, env=None):
        # type: (Optional[Mapping[str, str]]) -> Dict[str, str]


        env_copy = dict(env or os.environ)
        env_copy.pop("MACOSX_DEPLOYMENT_TARGET", None)
        return env_copy

    def __init__(self, identity):
        # type: (PythonIdentity) -> None
        self._identity = identity
        self._binary = self.canonicalize_path(self.identity.binary)

        self._supported_platforms = None

        self._PYTHON_INTERPRETER_BY_NORMALIZED_PATH[self._binary] = self

    @property
    def binary(self):
        # type: () -> str
        return self._binary

    @property
    def is_venv(self):
        # type: () -> bool
        return self._identity.is_venv

    @property
    def prefix(self):
        # type: () -> str
        return self._identity.prefix

    @property
    def sys_path(self):
        # type: () -> Tuple[str, ...]
        return self._identity.sys_path

    @property
    def site_packages(self):
        # type: () -> Tuple[SitePackagesDir, ...]
        return self.identity.site_packages

    @property
    def extras_paths(self):
        # type: () -> Tuple[str, ...]
        return self.identity.extras_paths

    @property
    def hermetic_args(self):
        # type: () -> str
        return "-I" if self.version[:2] >= (3, 4) else "-sE"

    class BaseInterpreterResolutionError(Exception):

    def resolve_base_interpreter(self):
        # type: () -> PythonInterpreter
        if not self.is_venv:
            return self


        implementation = self._identity.implementation
        version = self._identity.version
        abi_tag = self._identity.abi_tag

        versions = version[:2], version[:1], None
        candidate_binaries = tuple(
            script_name(implementation.calculate_binary_name(version)) for version in versions
        )

        def iter_base_candidate_binary_paths(interpreter):
            # type: (PythonInterpreter) -> Iterator[str]
            bin_dir = (
                interpreter._identity.base_prefix
                if WINDOWS
                else os.path.join(interpreter._identity.base_prefix, SCRIPT_DIR)
            )
            for candidate_binary in candidate_binaries:
                candidate_binary_path = os.path.join(bin_dir, candidate_binary)
                if is_exe(candidate_binary_path):
                    yield candidate_binary_path

        resolution_path = []
        base_interpreter = self
        while base_interpreter.is_venv:
            resolved = None
            maybe_reinstalled_interpreters = []
            for candidate_path in iter_base_candidate_binary_paths(base_interpreter):
                resolved_interpreter = self.from_binary(candidate_path)
                if resolved_interpreter.abi_tag == abi_tag:
                    if resolved_interpreter.version == version:
                        resolved = resolved_interpreter
                        break
                    else:


                        maybe_reinstalled_interpreters.append(resolved_interpreter)
            if resolved is None:
                for maybe_reinstalled_interpreter in maybe_reinstalled_interpreters:
                    re_resolved_interpreter = self.from_binary(
                        maybe_reinstalled_interpreter.binary, ignore_cached=True
                    )
                    if re_resolved_interpreter.version == version:
                        resolved = re_resolved_interpreter
                        break
            if resolved is None:
                message = [
                    "Failed to resolve the base interpreter for the virtual environment at "
                    "{venv_dir}.".format(venv_dir=self._identity.prefix)
                ]
                if resolution_path:
                    message.append(
                        "Resolved through {path}".format(
                            path=" -> ".join(binary for binary in resolution_path)
                        )
                    )
                message.append(
                    "Search of base_prefix {} found no equivalent interpreter for {}".format(
                        base_interpreter._identity.base_prefix, base_interpreter._binary
                    )
                )
                raise self.BaseInterpreterResolutionError("\n".join(message))
            base_interpreter = resolved
            resolution_path.append(base_interpreter.binary)
        return base_interpreter

    @property
    def identity(self):
        # type: () -> PythonIdentity
        return self._identity

    @property
    def is_pypy(self):
        # type: () -> bool
        return self._identity.is_pypy

    @property
    def free_threaded(self):
        # type: () -> Optional[bool]
        return self._identity.free_threaded

    @property
    def python(self):
        return self._identity.python

    @property
    def abi_tag(self):
        # type: () -> str
        return self._identity.abi_tag

    @property
    def version(self):
        # type: () -> Tuple[int, int, int]
        return self._identity.version

    @property
    def version_string(self):
        # type: () -> str
        return str(self._identity)

    @property
    def platform(self):
        # type: () -> Platform
        return next(self._identity.iter_supported_platforms())

    @property
    def supported_platforms(self):
        if self._supported_platforms is None:
            self._supported_platforms = frozenset(self._identity.iter_supported_platforms())
        return self._supported_platforms

    def shebang(
        self,
        args=None,
        encoding_line="",
    ):
        # type: (...) -> Text
        return create_shebang(
            adjust_to_final_path(self._binary), python_args=args, encoding_line=encoding_line
        )

    def create_isolated_cmd(
        self,
        args=None,
        pythonpath=None,
        env=None,
    ):
        # type: (...) -> Tuple[Iterable[str], Mapping[str, str]]
        env_copy = dict(env or os.environ)

        if self._identity.configured_macosx_deployment_target:


            release = self._identity.configured_macosx_deployment_target
            version = release.split(".")
            if len(version) == 1:
                release = "{}.0".format(version[0])
            elif len(version) > 2:
                release = ".".join(version[:2])

            if release != self._identity.configured_macosx_deployment_target:
                osname, _, machine = sysconfig.get_platform().split("-")
                pep425_compatible_platform = "{osname}-{release}-{machine}".format(
                    osname=osname, release=release, machine=machine
                )


                TRACER.log(
                    "Correcting mis-configured MACOSX_DEPLOYMENT_TARGET of {} to {} corresponding "
                    "to a valid PEP-425 platform of {} for {}.".format(
                        self._identity.configured_macosx_deployment_target,
                        release,
                        pep425_compatible_platform,
                        self,
                    )
                )
                env_copy.update(_PYTHON_HOST_PLATFORM=pep425_compatible_platform)

        return self._create_isolated_cmd(
            self.binary,
            args=args,
            pythonpath=pythonpath,
            env=env_copy,
            version=self.version,
        )

    def execute(
        self,
        args=None,
        stdin_payload=None,
        pythonpath=None,
        env=None,
        **kwargs
    ):
        # type: (...) -> Tuple[Iterable[str], str, str]
        cmd, env = self.create_isolated_cmd(args=args, pythonpath=pythonpath, env=env)
        stdout, stderr = Executor.execute(cmd, stdin_payload=stdin_payload, env=env, **kwargs)
        return cmd, stdout, stderr

    def open_process(
        self,
        args=None,
        pythonpath=None,
        env=None,
        **kwargs
    ):
        # type: (...) -> Tuple[Iterable[str], subprocess.Popen]
        cmd, env = self.create_isolated_cmd(args=args, pythonpath=pythonpath, env=env)
        process = Executor.open_process(cmd, env=env, **kwargs)
        return cmd, process

    def __hash__(self):
        return hash(self._binary)

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self._binary == other._binary

    def __repr__(self):
        return "{type}({binary!r}, {identity!r})".format(
            type=self.__class__.__name__, binary=self._binary, identity=self._identity
        )


MAX_SHEBANG_LENGTH = 512 if sys.platform == "darwin" else 128


def create_shebang(
    python_exe,
    python_args=None,
    max_shebang_length=MAX_SHEBANG_LENGTH,
    encoding_line="",
):
    # type: (...) -> Text
    python = "{exe} {args}".format(exe=python_exe, args=python_args) if python_args else python_exe
    shebang = "#!{python}".format(python=python)


    if WINDOWS or len(shebang) + 1 <= max_shebang_length:
        return shebang


    return (
        dedent(
            """\
            #!/bin/sh
            {encoding_line}
            # N.B.: This python script executes via a /bin/sh re-exec as a hack to work around a
            # potential maximum shebang length of {max_shebang_length} bytes on this system which
            # the python interpreter `exec`ed below would violate.
            ''''exec {python} "$0" "$@"
            '''
            """
        )
        .format(
            encoding_line=encoding_line.rstrip(),
            max_shebang_length=max_shebang_length,
            python=python,
        )
        .strip()
    )
