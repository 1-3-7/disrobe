

from __future__ import absolute_import

import hashlib
import json
import os
import re
import sys
from contextlib import contextmanager
from textwrap import dedent

from pex import pex_root, pex_warnings
from pex.common import die
from pex.inherit_path import InheritPath
from pex.orderedset import OrderedSet
from pex.typing import TYPE_CHECKING, Generic, overload
from pex.venv.bin_path import BinPath

if TYPE_CHECKING:
    from typing import Any, Callable, Dict, Iterator, Mapping, Optional, Tuple, Type, TypeVar, Union

    _O = TypeVar("_O")
    _P = TypeVar("_P")


    from pex.cache.dirs import UnzipDir, VenvDir


    from pex.interpreter import PythonInterpreter


class NoValueError(Exception):


class DefaultedProperty(Generic["_O", "_P"]):

    def __init__(
        self,
        func,
        default,
    ):
        # type: (...) -> None
        self._func = func
        self._default = default
        self._validator = None

    @overload
    def __get__(
        self,
        instance,
        owner_class=None,
    ):
        # type: (...) -> DefaultedProperty[_O, _P]
        pass

    @overload
    def __get__(
        self,
        instance,
        owner_class=None,
    ):
        # type: (...) -> _P
        pass

    def __get__(
        self,
        instance,
        owner_class=None,
    ):
        # type: (...) -> Union[DefaultedProperty[_O, _P], _P]
        if instance is None:
            return self
        try:
            return self._validate(instance, self._func(instance))
        except NoValueError:
            return self._validate(
                instance, self._default() if callable(self._default) else self._default
            )

    def strip_default(self, instance):
        # type: (_O) -> Optional[_P]
        try:
            return self._validate(instance, self._func(instance))
        except NoValueError:
            return None

    def value_or(
        self,
        instance,
        fallback,
    ):
        # type: (...) -> _P
        try:
            value = self._func(instance)
        except NoValueError:
            value = fallback
        return self._validate(instance, value)

    def validator(self, func):
        # type: (Callable[[_O, _P], _P]) -> Callable[[_O, _P], _P]
        self._validator = func
        return func

    def _validate(self, instance, value):
        # type: (_O, _P) -> _P
        if self._validator is None:
            return value
        return self._validator(instance, value)


def defaulted_property(
    default,
    _type_hint=None,
):
    # type: (...) -> Callable[[Callable[[_O], _P]], DefaultedProperty[_O, _P]]

    def wrapped(func):
        # type: (Callable[[_O], _P]) -> DefaultedProperty[_O, _P]
        return DefaultedProperty(func, default)

    return wrapped


def _default_pex_root():
    # type: () -> str


    from pex.cache import root as cache_root

    return cache_root.path(expand_user=True)


class Variables(object):

    @classmethod
    def process_pydoc(cls, pydoc):
        # type: (Optional[str]) -> Tuple[str, str]
        if pydoc is None:
            return "Unknown", "Unknown"
        pydoc_lines = pydoc.splitlines()
        variable_type = pydoc_lines[0]
        variable_text = " ".join(filter(None, (line.strip() for line in pydoc_lines[2:])))
        return variable_type, variable_text

    @classmethod
    def iter_help(cls):
        # type: () -> Iterator[Tuple[str, str, str]]
        for variable_name, value in sorted(cls.__dict__.items()):
            if not variable_name.startswith("PEX_"):
                continue
            value = value._func if isinstance(value, DefaultedProperty) else value
            variable_type, variable_text = cls.process_pydoc(getattr(value, "__doc__"))
            yield variable_name, variable_type, variable_text

    @classmethod
    def from_rc(cls, rc=None):
        # type: (Optional[str]) -> Dict[str, str]
        ret_vars = {}
        rc_locations = [
            os.path.join(os.sep, "etc", "pexrc"),
            os.path.join("~", ".pexrc"),
            os.path.join(os.path.dirname(sys.argv[0]), ".pexrc"),
        ]
        if rc:
            rc_locations.append(rc)
        for filename in rc_locations:
            try:
                with open(os.path.expanduser(filename)) as fh:
                    rc_items = map(cls._get_kv, fh)
                    ret_vars.update(dict(filter(None, rc_items)))
            except IOError:
                continue
        return ret_vars

    @classmethod
    def _get_kv(cls, variable):
        kv = variable.strip().split("=")
        if len(list(filter(None, kv))) == 2:
            return kv

    @staticmethod
    def _maybe_get_bool_var(
        name,
        env,
    ):
        # type: (...) -> Optional[bool]
        value = env.get(name, None)
        if value is None:
            return None
        if value.lower() in ("0", "false"):
            return False
        if value.lower() in ("1", "true"):
            return True
        raise ValueError(
            "Invalid bool value for {name}, must be 0/1/false/true, got {value!r}".format(
                name=name, value=value
            )
        )

    def __init__(self, environ=None, rc=None):
        # type: (Optional[Mapping[str, str]], Optional[str]) -> None
        env = environ if environ is not None else os.environ
        if self._maybe_get_bool_var("PEX_DISABLE_VARIABLES", env) is True:
            self._environ = {
                key: value
                for key, value in env.items()
                if key == "PEX_DISABLE_VARIABLES" or not key.startswith("PEX_")
            }
        else:
            self._environ = dict(env)
            if not self.PEX_IGNORE_RCFILES:
                rc_values = self.from_rc(rc).copy()
                rc_values.update(self._environ)
                self._environ = rc_values

        if "PEX_ALWAYS_CACHE" in self._environ:
            pex_warnings.warn(
                "The `PEX_ALWAYS_CACHE` env var is deprecated. This env var is no longer read; all "
                "internally cached distributions in a PEX are always installed into the local Pex "
                "dependency cache."
            )
        if "PEX_FORCE_LOCAL" in self._environ:
            pex_warnings.warn(
                "The `PEX_FORCE_LOCAL` env var is deprecated. This env var is no longer read since "
                "user code is now always unzipped before execution."
            )
        if "PEX_UNZIP" in self._environ:
            pex_warnings.warn(
                "The `PEX_UNZIP` env var is deprecated. This env var is no longer read since "
                "unzipping PEX zip files before execution is now the default."
            )
        if "PEX_TEARDOWN_VERBOSE" in self._environ:
            pex_warnings.warn(
                "The `PEX_TEARDOWN_VERBOSE` env var is deprecated. This env var is no longer read "
                "since PEX teardown has been removed in favor of the natural teardown environment "
                "provided by the Python runtime."
            )

    def copy(self):
        # type: () -> Dict[str, str]
        return self._environ.copy()

    def _maybe_get_string(self, variable):
        # type: (str) -> Optional[str]
        return self._environ.get(variable)

    def _get_string(self, variable):
        # type: (str) -> str
        value = self._maybe_get_string(variable)
        if value is None:
            raise NoValueError(variable)
        return value

    def _maybe_get_bool(self, variable):
        # type: (str) -> Optional[bool]
        return self._maybe_get_bool_var(variable, self._environ)

    def _get_bool(self, variable):
        # type: (str) -> bool
        value = self._maybe_get_bool(variable)
        if value is None:
            raise NoValueError(variable)
        return value

    def _maybe_get_path(self, variable):
        # type: (str) -> Optional[str]
        value = self._maybe_get_string(variable)
        if value is None:
            return None
        return os.path.realpath(os.path.expanduser(value))

    def _get_path(self, variable):
        # type: (str) -> str
        value = self._maybe_get_path(variable)
        if value is None:
            raise NoValueError(variable)
        return value

    def _get_int(self, variable):
        # type: (str) -> int
        value = self._get_string(variable)
        try:
            return int(value)
        except ValueError:
            die(
                "Invalid value for %s, must be an integer, got %r"
                % (variable, self._environ[variable])
            )

    def _maybe_get_path_tuple(
        self,
        variable,
        empty_string_is_cwd=True,
    ):
        # type: (...) -> Optional[Tuple[str, ...]]
        value = self._maybe_get_string(variable)
        if value is None:
            return None
        if not value and not empty_string_is_cwd:
            return None
        return tuple(
            OrderedSet(os.path.normpath(os.path.expanduser(p)) for p in value.split(os.pathsep))
        )

    def strip(self):
        # type: () -> Variables
        stripped_environ = {
            k: v
            for k, v in self.copy().items()
            if k.startswith("__PEX_BUILD_") or not k.startswith(("PEX_", "__PEX_"))
        }
        return Variables(environ=stripped_environ)

    @contextmanager
    def patch(self, **kw):
        # type: (**Optional[str]) -> Iterator[Dict[str, str]]
        disable_env = self._maybe_get_bool_var("PEX_DISABLE_VARIABLES", kw)

        old_environ = self._environ
        self._environ = self._environ.copy()
        if disable_env:
            for k in list(self._environ):
                if k != "PEX_DISABLE_VARIABLES" and k.startswith("PEX_"):
                    self._environ.pop(k)
        for k, v in kw.items():
            if v is None:
                self._environ.pop(k, None)
            elif disable_env and k != "PEX_DISABLE_VARIABLES" and k.startswith("PEX_"):
                self._environ.pop(k, None)
            else:
                self._environ[k] = v

        yield self._environ
        self._environ = old_environ

    @defaulted_property(default=False)
    def PEX_DISABLE_VARIABLES(self):
        # type: () -> bool
        return self._get_bool("PEX_DISABLE_VARIABLES")

    @property
    def PEX(self):
        # type: () -> Optional[str]
        return self._maybe_get_path("PEX")

    @defaulted_property(default=False)
    def PEX_ALWAYS_CACHE(self):
        # type: () -> bool
        return self._get_bool("PEX_ALWAYS_CACHE")

    @defaulted_property(default=False)
    def PEX_COVERAGE(self):
        # type: () -> bool
        return self._get_bool("PEX_COVERAGE")

    @property
    def PEX_COVERAGE_FILENAME(self):
        # type: () -> Optional[str]
        return self._maybe_get_path("PEX_COVERAGE_FILENAME")

    @defaulted_property(default=False)
    def PEX_FORCE_LOCAL(self):
        # type: () -> bool
        return self._get_bool("PEX_FORCE_LOCAL")

    @defaulted_property(default=False)
    def PEX_UNZIP(self):
        # type: () -> bool
        return self._get_bool("PEX_UNZIP")

    @defaulted_property(default=False)
    def PEX_VENV(self):
        # type: () -> bool
        return self._get_bool("PEX_VENV")

    @defaulted_property(default=BinPath.FALSE)
    def PEX_VENV_BIN_PATH(self):
        # type: () -> BinPath.Value
        return BinPath.for_value(self._get_string("PEX_VENV_BIN_PATH"))

    @defaulted_property(default=False)
    def PEX_IGNORE_ERRORS(self):
        # type: () -> bool
        return self._get_bool("PEX_IGNORE_ERRORS")

    @defaulted_property(default=InheritPath.FALSE)
    def PEX_INHERIT_PATH(self):
        # type: () -> InheritPath.Value
        try:
            return InheritPath.for_value(self._get_string("PEX_INHERIT_PATH"))
        except ValueError as e:
            die("Invalid value for PEX_INHERIT_PATH: {}".format(e))

    @defaulted_property(default=False)
    def PEX_INTERPRETER(self):
        # type: () -> bool
        return self._get_bool("PEX_INTERPRETER")

    @defaulted_property(default=False)
    def PEX_INTERPRETER_HISTORY(self):
        # type: () -> bool
        return self._get_bool("PEX_INTERPRETER_HISTORY")

    @defaulted_property(default=os.path.join("~", ".python_history"))
    def PEX_INTERPRETER_HISTORY_FILE(self):
        # type: () -> str
        return self._get_string("PEX_INTERPRETER_HISTORY_FILE")

    @property
    def PEX_MODULE(self):
        # type: () -> Optional[str]
        return self._maybe_get_string("PEX_MODULE")

    @defaulted_property(default=False)
    def PEX_PROFILE(self):
        # type: () -> bool
        return self._get_bool("PEX_PROFILE")

    @property
    def PEX_PROFILE_FILENAME(self):
        # type: () -> Optional[str]
        return self._maybe_get_path("PEX_PROFILE_FILENAME")

    @defaulted_property(default="cumulative")
    def PEX_PROFILE_SORT(self):
        # type: () -> str
        return self._get_string("PEX_PROFILE_SORT")

    @property
    def PEX_PYTHON(self):
        # type: () -> Optional[str]
        return self._maybe_get_string("PEX_PYTHON")

    @property
    def PEX_PYTHON_PATH(self):
        # type: () -> Optional[Tuple[str, ...]]
        return self._maybe_get_path_tuple("PEX_PYTHON_PATH")

    @property
    def PEX_EXTRA_SYS_PATH(self):
        # type: () -> Tuple[str, ...]
        return self._maybe_get_path_tuple("PEX_EXTRA_SYS_PATH") or ()

    @defaulted_property(default=_default_pex_root, _type_hint=str)
    def PEX_ROOT(self):
        # type: () -> str
        return self._get_path("PEX_ROOT")

    @PEX_ROOT.validator
    def _ensure_writeable_pex_root(self, raw_pex_root):
        writeable_pex_root, is_fallback = pex_root.ensure_writeable(raw_pex_root)
        if is_fallback:
            self._environ["PEX_ROOT"] = writeable_pex_root
        return writeable_pex_root

    @property
    def PEX_PATH(self):
        # type: () -> Tuple[str, ...]
        return self._maybe_get_path_tuple("PEX_PATH", empty_string_is_cwd=False) or ()

    @property
    def PEX_SCRIPT(self):
        # type: () -> Optional[str]
        return self._maybe_get_string("PEX_SCRIPT")

    @defaulted_property(default=False)
    def PEX_TEARDOWN_VERBOSE(self):
        # type: () -> bool
        return self._get_bool("PEX_TEARDOWN_VERBOSE")

    @defaulted_property(default=0)
    def PEX_VERBOSE(self):
        # type: () -> int
        return self._get_int("PEX_VERBOSE")

    @defaulted_property(default=False)
    def PEX_IGNORE_RCFILES(self):
        # type: () -> bool
        return self._get_bool("PEX_IGNORE_RCFILES")

    @property
    def PEX_EMIT_WARNINGS(self):
        # type: () -> Optional[bool]
        return self._maybe_get_bool("PEX_EMIT_WARNINGS")

    @defaulted_property(default=False)
    def PEX_TOOLS(self):
        # type: () -> bool
        return self._get_bool("PEX_TOOLS")

    @defaulted_property(default=1)
    def PEX_MAX_INSTALL_JOBS(self):
        # type: () -> int
        install_jobs = self._get_int("PEX_MAX_INSTALL_JOBS")
        if install_jobs < -1:
            raise ValueError(
                "PEX_MAX_INSTALL_JOBS must be -1 or greater; given: {jobs}".format(
                    jobs=install_jobs
                )
            )
        return install_jobs

    def __repr__(self):
        return "{}({!r})".format(type(self).__name__, self._environ)


ENV = Variables()


def _expand_pex_root(pex_root):
    # type: (str) -> str
    fallback = os.path.realpath(os.path.expanduser(pex_root))
    return os.path.expanduser(Variables.PEX_ROOT.value_or(ENV, fallback=fallback))


def unzip_dir(
    pex_root,
    pex_hash,
    expand_pex_root=True,
):
    # type: (...) -> UnzipDir


    from pex.cache.dirs import UnzipDir

    pex_root = _expand_pex_root(pex_root) if expand_pex_root else pex_root
    return UnzipDir.create(pex_hash=pex_hash, pex_root=pex_root)


def venv_dir(
    pex_root,
    pex_hash,
    has_interpreter_constraints,
    pex_file=None,
    interpreter=None,
    pex_path=(),
    expand_pex_root=True,
):
    # type: (...) -> VenvDir


    from pex.cache.dirs import VenvDir


    pex_path_contents = {}
    venv_contents = {"pex_path": pex_path_contents}


    def add_pex_path_items(pexes):
        # type: (Tuple[str, ...]) -> None
        if not pexes:
            return
        from pex.pex_info import PexInfo

        for pex in pexes:
            pex_path_contents[pex] = PexInfo.from_pex(pex).distributions

    add_pex_path_items(pex_path)
    add_pex_path_items(ENV.PEX_PATH)


    venv_contents["PEX_PYTHON_PATH"] = ENV.PEX_PYTHON_PATH

    interpreter_path = None
    precise_pex_python = ENV.PEX_PYTHON and os.path.exists(ENV.PEX_PYTHON)
    if precise_pex_python:


        interpreter_path = ENV.PEX_PYTHON
    elif ENV.PEX_PYTHON:


        venv_contents["PEX_PYTHON"] = ENV.PEX_PYTHON
    elif not has_interpreter_constraints:


        interpreter_binary = interpreter.binary if interpreter else sys.executable
        if (
            not ENV.PEX_PYTHON_PATH
            or interpreter_binary.startswith(ENV.PEX_PYTHON_PATH)
            or os.path.realpath(interpreter_binary).startswith(
                tuple(os.path.realpath(p) for p in ENV.PEX_PYTHON_PATH)
            )
        ):
            interpreter_path = interpreter_binary
    if interpreter_path:
        venv_contents["interpreter"] = os.path.realpath(interpreter_path)

    venv_contents_hash = hashlib.sha1(
        json.dumps(venv_contents, sort_keys=True).encode("utf-8")
    ).hexdigest()
    pex_root = _expand_pex_root(pex_root) if expand_pex_root else pex_root
    venv_path = VenvDir.create(pex_hash, venv_contents_hash, pex_root=pex_root)

    def warn(message):
        # type: (str) -> None

        if not pex_file:
            return

        from pex.pex_info import PexInfo

        pex_warnings.configure_warnings(ENV, PexInfo.from_pex(pex_file))
        pex_warnings.warn(message)

    if (
        pex_file
        and ENV.PEX_PYTHON
        and not precise_pex_python
        and not re.match(r".*[^\d][\d]+\.[\d]+$", ENV.PEX_PYTHON)
    ):
        warn(
            dedent(
                """\
                Using a venv selected by PEX_PYTHON={pex_python} for {pex_file} at {venv_path}.

                If `{pex_python}` is upgraded or downgraded at some later date, this venv will still
                be used. To force re-creation of the venv using the upgraded or downgraded
                `{pex_python}` you will need to delete it at that point in time.

                To avoid this warning, either specify a Python binary with major and minor version
                in its name, like PEX_PYTHON=python{current_python_version} or else re-build the PEX
                with `--no-emit-warnings` or re-run the PEX with PEX_EMIT_WARNINGS=False.
                """.format(
                    pex_python=ENV.PEX_PYTHON,
                    pex_file=os.path.normpath(pex_file),
                    venv_path=venv_path,
                    current_python_version=".".join(map(str, sys.version_info[:2])),
                )
            )
        )
    if pex_file and not interpreter_path and ENV.PEX_PYTHON_PATH:
        warn(
            dedent(
                """\
                Using a venv restricted by PEX_PYTHON_PATH={ppp} for {pex_file} at {venv_path}.

                If the contents of `{ppp}` changes at some later date, this venv and the interpreter
                selected from `{ppp}` will still be used. To force re-creation of the venv using
                the new pythons available on `{ppp}` you will need to delete it at that point in
                time.

                To avoid this warning, re-build the PEX with `--no-emit-warnings` or re-run the PEX
                with PEX_EMIT_WARNINGS=False.
                """
            ).format(
                ppp=os.pathsep.join(ENV.PEX_PYTHON_PATH),
                pex_file=os.path.normpath(pex_file),
                venv_path=venv_path,
            )
        )

    return venv_path
