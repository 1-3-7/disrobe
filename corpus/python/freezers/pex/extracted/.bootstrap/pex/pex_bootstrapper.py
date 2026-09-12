

from __future__ import absolute_import

import hashlib
import os
import sys

from pex import interpreter, pex_warnings
from pex.atomic_directory import atomic_directory
from pex.cache import access as cache_access
from pex.cache.dirs import VenvDirs
from pex.common import CopyMode, die, pluralize
from pex.environment import ResolveError
from pex.fs import safe_symlink
from pex.inherit_path import InheritPath
from pex.interpreter import PythonInterpreter
from pex.interpreter_constraints import (
    InterpreterConstraints,
    UnsatisfiableInterpreterConstraintsError,
)
from pex.interpreter_selection_strategy import InterpreterSelectionStrategy
from pex.layout import Layout
from pex.orderedset import OrderedSet
from pex.os import WINDOWS, safe_execv
from pex.pex_info import PexInfo
from pex.sysconfig import SCRIPT_DIR, script_name
from pex.targets import LocalInterpreter
from pex.tracer import TRACER
from pex.typing import TYPE_CHECKING, cast
from pex.variables import ENV
from pex.venv import installer

if TYPE_CHECKING:
    from typing import (
        Any,
        Iterable,
        Iterator,
        List,
        NoReturn,
        Optional,
        Sequence,
        Set,
        Tuple,
        Union,
    )

    import attr

    from pex.interpreter import InterpreterIdentificationError, InterpreterOrError, PathFilter
    from pex.pex import PEX
else:
    from pex.third_party import attr


def normalize_path(path):
    # type: (Optional[Iterable[str]]) -> Optional[OrderedSet[str]]
    return OrderedSet(PythonInterpreter.canonicalize_path(p) for p in path) if path else None


@attr.s(frozen=True)
class InterpreterTest(object):
    entry_point = attr.ib()
    pex_info = attr.ib()

    @property
    def interpreter_constraints(self):
        # type: () -> InterpreterConstraints
        return self.pex_info.interpreter_constraints

    def test_resolve(self, interpreter):
        # type: (PythonInterpreter) -> Union[ResolveError, bool]
        with TRACER.timed(
            "Testing {python} can resolve PEX at {pex}".format(
                python=interpreter.binary, pex=self.entry_point
            )
        ):
            from pex.environment import PEXEnvironment

            pex_environment = PEXEnvironment.mount(
                self.entry_point,
                pex_info=self.pex_info,
                target=LocalInterpreter.create(interpreter),
            )
            try:
                pex_environment.resolve()
                return True
            except ResolveError as e:
                return e


def iter_compatible_interpreters(
    path=None,
    valid_basenames=None,
    interpreter_constraints=None,
    preferred_interpreter=None,
    interpreter_test=None,
):
    # type: (...) -> Iterator[PythonInterpreter]

    _valid_path = None
    if valid_basenames:
        _valid_basenames = frozenset(cast("Iterable[str]", valid_basenames))
        _valid_path = (
            lambda interpreter_path: os.path.basename(interpreter_path) in _valid_basenames
        )

    def _iter_interpreters():
        # type: () -> Iterator[InterpreterOrError]
        seen = set()

        normalized_paths = normalize_path(path)


        current_interpreter = preferred_interpreter or PythonInterpreter.get()
        if not _valid_path or _valid_path(current_interpreter.binary):
            if normalized_paths:
                candidate_paths = frozenset(
                    (current_interpreter.binary, os.path.dirname(current_interpreter.binary))
                )
                candidate_paths_in_path = candidate_paths.intersection(normalized_paths)
                if candidate_paths_in_path:


                    normalized_paths.discard(current_interpreter.binary)
                    seen.add(current_interpreter)
                    yield current_interpreter
            else:
                seen.add(current_interpreter)
                yield current_interpreter

        for interp in PythonInterpreter.iter_candidates(
            paths=normalized_paths, path_filter=_valid_path
        ):
            if interp not in seen:
                seen.add(interp)
                yield interp

    def _valid_interpreter(interp):
        # type: (PythonInterpreter) -> Union[ResolveError, bool]
        if not interpreter_constraints:
            return interpreter_test.test_resolve(interp) if interpreter_test else True

        if interp in interpreter_constraints:
            TRACER.log(
                "Constraints on interpreters: {}, Matching Interpreter: {}".format(
                    interpreter_constraints, interp.binary
                ),
                V=3,
            )
            return interpreter_test.test_resolve(interp) if interpreter_test else True

        return False

    candidates = []
    resolve_errors = []
    identification_failures = []
    found = False

    for interpreter_or_error in _iter_interpreters():
        if isinstance(interpreter_or_error, PythonInterpreter):
            interpreter = interpreter_or_error
            candidates.append(interpreter)
            valid_or_error = _valid_interpreter(interpreter)
            if isinstance(valid_or_error, ResolveError):
                resolve_errors.append(valid_or_error)
            elif valid_or_error:
                found = True
                yield interpreter
        else:
            identification_failures.append(interpreter_or_error)

    if not found and (resolve_errors or interpreter_constraints or valid_basenames):
        constraints = []
        if resolve_errors:
            constraints.extend(str(resolve_error) for resolve_error in resolve_errors)
        else:
            if interpreter_constraints:
                constraints.append(
                    "Version matches {}".format(" or ".join(map(str, interpreter_constraints)))
                )
            if valid_basenames:
                constraints.append("Basename is {}".format(" or ".join(valid_basenames)))
        raise UnsatisfiableInterpreterConstraintsError(
            constraints, candidates, identification_failures
        )


def _select_path_interpreter(
    path=None,
    valid_basenames=None,
    interpreter_constraints=None,
    preferred_interpreter=None,
    interpreter_test=None,
    interpreter_selection_strategy=InterpreterSelectionStrategy.OLDEST,
):
    # type: (...) -> Optional[PythonInterpreter]

    candidate_interpreters_iter = iter_compatible_interpreters(
        path=path,
        valid_basenames=valid_basenames,
        interpreter_constraints=interpreter_constraints,
        preferred_interpreter=preferred_interpreter,
        interpreter_test=interpreter_test,
    )
    current_interpreter = PythonInterpreter.get()
    preferred_interpreter = preferred_interpreter or current_interpreter
    candidate_interpreters = OrderedSet()
    for interpreter in candidate_interpreters_iter:
        if preferred_interpreter == interpreter:

            return preferred_interpreter
        else:
            candidate_interpreters.add(interpreter)
    if not candidate_interpreters:
        return None
    if current_interpreter in candidate_interpreters:


        return current_interpreter
    return interpreter_selection_strategy.select(candidate_interpreters)


def find_compatible_interpreter(
    interpreter_test=None,
    interpreter_selection_strategy=InterpreterSelectionStrategy.OLDEST,
):
    # type: (...) -> PythonInterpreter

    interpreter_constraints = interpreter_test.interpreter_constraints if interpreter_test else None

    def gather_constraints():
        # type: () -> Iterable[str]
        constraints = []
        if ENV.PEX_PYTHON:
            constraints.append("PEX_PYTHON={}".format(ENV.PEX_PYTHON))
        if ENV.PEX_PYTHON_PATH:
            constraints.append("PEX_PYTHON_PATH={}".format(ENV.PEX_PYTHON_PATH))
        if interpreter_constraints:
            constraints.append("Version matches {}".format(interpreter_constraints))
        return constraints

    preferred_interpreter = None
    if ENV.PEX_PYTHON and os.path.isabs(ENV.PEX_PYTHON):
        try:
            preferred_interpreter = PythonInterpreter.from_binary(ENV.PEX_PYTHON)
        except PythonInterpreter.Error as e:
            raise UnsatisfiableInterpreterConstraintsError(
                constraints=gather_constraints(),
                candidates=[],
                failures=[(ENV.PEX_PYTHON, str(e))],
                preamble=(
                    "The specified PEX_PYTHON={pex_python} could not be identified as a "
                    "valid Python interpreter.".format(pex_python=ENV.PEX_PYTHON)
                ),
            )

    current_interpreter = PythonInterpreter.get()
    with TRACER.timed("Selecting runtime interpreter", V=3):
        if ENV.PEX_PYTHON and not ENV.PEX_PYTHON_PATH:
            TRACER.log(
                "Using PEX_PYTHON={} constrained by {}".format(
                    ENV.PEX_PYTHON, interpreter_constraints
                ),
                V=3,
            )
            try:
                if os.path.isabs(ENV.PEX_PYTHON):
                    target = _select_path_interpreter(
                        path=(ENV.PEX_PYTHON,),
                        interpreter_constraints=interpreter_constraints,
                        preferred_interpreter=preferred_interpreter,
                        interpreter_test=interpreter_test,
                        interpreter_selection_strategy=interpreter_selection_strategy,
                    )
                else:
                    target = _select_path_interpreter(
                        valid_basenames=(os.path.basename(ENV.PEX_PYTHON),),
                        interpreter_constraints=interpreter_constraints,
                        interpreter_test=interpreter_test,
                        interpreter_selection_strategy=interpreter_selection_strategy,
                    )
            except UnsatisfiableInterpreterConstraintsError as e:
                raise e.with_preamble(
                    "Failed to find a compatible PEX_PYTHON={pex_python}.".format(
                        pex_python=ENV.PEX_PYTHON
                    )
                )
        else:
            TRACER.log(
                "Using {path} constrained by {constraints}".format(
                    path="PEX_PYTHON_PATH={}".format(ENV.PEX_PYTHON_PATH)
                    if ENV.PEX_PYTHON_PATH
                    else "$PATH",
                    constraints=interpreter_constraints,
                ),
                V=3,
            )
            try:
                target = _select_path_interpreter(
                    path=ENV.PEX_PYTHON_PATH,
                    interpreter_constraints=interpreter_constraints,
                    preferred_interpreter=preferred_interpreter,
                    interpreter_test=interpreter_test,
                    interpreter_selection_strategy=interpreter_selection_strategy,
                )
            except UnsatisfiableInterpreterConstraintsError as e:
                raise e.with_preamble(
                    "Failed to find compatible interpreter on path {path}.".format(
                        path=(
                            os.pathsep.join(ENV.PEX_PYTHON_PATH)
                            if ENV.PEX_PYTHON_PATH
                            else os.getenv("PATH", "(The PATH is empty!)")
                        )
                    )
                )

        if preferred_interpreter and target != preferred_interpreter:
            candidates = [preferred_interpreter, target] if target else [preferred_interpreter]
            raise UnsatisfiableInterpreterConstraintsError(
                constraints=gather_constraints(),
                candidates=candidates,
                failures=[],
                preamble=(
                    "The specified PEX_PYTHON={pex_python} did not meet other "
                    "constraints.".format(pex_python=ENV.PEX_PYTHON)
                ),
            )

        if target is None:


            raise UnsatisfiableInterpreterConstraintsError(
                constraints=gather_constraints(),
                candidates=[current_interpreter],
                failures=[],
                preamble="Could not find a compatible interpreter.",
            )

        return target


def maybe_reexec_pex(
    interpreter_test,
    interpreter_selection_strategy=InterpreterSelectionStrategy.OLDEST,
    python_args=(),
):
    # type: (...) -> Union[None, NoReturn]

    current_interpreter = PythonInterpreter.get()


    if "_PEX_EXEC_CHAIN" in os.environ:
        flag_or_chain = os.environ.pop("_PEX_EXEC_CHAIN")
        pex_exec_chain = [] if flag_or_chain == "1" else flag_or_chain.split(os.pathsep)
        pex_exec_chain.append(current_interpreter.binary)
        os.environ["_PEX_EXEC_CHAIN"] = os.pathsep.join(pex_exec_chain)

    current_interpreter_blessed_env_var = "_PEX_SHOULD_EXIT_BOOTSTRAP_REEXEC"
    if os.environ.pop(current_interpreter_blessed_env_var, None):

        return None

    try:
        target = find_compatible_interpreter(
            interpreter_test=interpreter_test,
            interpreter_selection_strategy=interpreter_selection_strategy,
        )
    except UnsatisfiableInterpreterConstraintsError as e:
        die(str(e))

    if interpreter_test.pex_info.inherit_path == InheritPath.FALSE:


        resolved = target.resolve_base_interpreter()
        if resolved != target:
            TRACER.log(
                "Resolved base interpreter of {} from virtual environment at {}".format(
                    resolved, target.prefix
                ),
                V=3,
            )
        target = resolved

    from . import pex

    pythonpath = pex.PEX.stash_pythonpath()
    if pythonpath is not None:
        TRACER.log("Stashed PYTHONPATH of {}".format(pythonpath), V=2)
    elif target == current_interpreter:
        TRACER.log(
            "Using the current interpreter {} since it matches constraints and "
            "PYTHONPATH is not set.".format(sys.executable)
        )
        return None

    target_binary = target.binary
    cmdline = [target_binary] + list(python_args) + sys.argv
    TRACER.log(
        "Re-executing: "
        "cmdline={cmdline!r}, "
        "sys.executable={python!r}, "
        "PEX_PYTHON={pex_python!r}, "
        "PEX_PYTHON_PATH={pex_python_path!r}, "
        "interpreter_constraints={interpreter_constraints!r}"
        "{pythonpath}".format(
            cmdline=" ".join(cmdline),
            python=sys.executable,
            pex_python=ENV.PEX_PYTHON,
            pex_python_path=ENV.PEX_PYTHON_PATH,
            interpreter_constraints=interpreter_test.interpreter_constraints,
            pythonpath=', (stashed) PYTHONPATH="{}"'.format(pythonpath)
            if pythonpath is not None
            else "",
        )
    )


    os.environ[current_interpreter_blessed_env_var] = "1"

    safe_execv(cmdline)


def _bootstrap(entry_point):
    # type: (str) -> PexInfo
    pex_info = PexInfo.from_pex(entry_point)
    pex_info.update(PexInfo.from_env())
    pex_warnings.configure_warnings(ENV, pex_info=pex_info)
    return pex_info


@attr.s(frozen=True)
class VenvPex(object):
    venv_dir = attr.ib()
    hermetic_script_args = attr.ib(default=None)
    pex = attr.ib(init=False)
    python = attr.ib(init=False)

    def bin_file(self, name):
        # type: (str) -> str
        return os.path.join(self.venv_dir, SCRIPT_DIR, script_name(name))

    def __attrs_post_init__(self):
        # type: () -> None
        object.__setattr__(self, "pex", os.path.join(self.venv_dir, "pex"))
        object.__setattr__(self, "python", self.bin_file("python"))

    def execute_args(
        self,
        python_args=(),
        additional_args=(),
    ):
        # type: (...) -> List[str]
        argv = [self.python]
        argv.extend(python_args)
        if self.hermetic_script_args:
            argv.append(self.hermetic_script_args)
        argv.append(self.pex)
        argv.extend(additional_args)
        return argv

    def execv(
        self,
        python_args=(),
        additional_args=(),
    ):
        # type: (...) -> NoReturn
        safe_execv(self.execute_args(python_args=python_args, additional_args=additional_args))


def ensure_venv(
    pex,
    collisions_ok=True,
    copy_mode=None,
    record_access=True,
):
    # type: (...) -> VenvPex
    pex_info = pex.pex_info()
    venv_dir = pex_info.runtime_venv_dir(pex_file=pex.path(), interpreter=pex.interpreter)
    if venv_dir is None:
        raise AssertionError(
            "Expected PEX-INFO for {} to have the components of a venv directory".format(pex.path())
        )
    if not pex_info.includes_tools:
        raise ValueError(
            "The PEX_VENV environment variable was set, but this PEX was not built with venv "
            "support (Re-build the PEX file with `pex --venv ...`)"
        )

    if not os.path.exists(venv_dir):
        with ENV.patch(PEX_ROOT=pex_info.pex_root):
            cache_access.read_write()
    with atomic_directory(venv_dir) as venv:
        if not venv.is_finalized():
            from pex.venv.virtualenv import Virtualenv

            with interpreter.path_mapping(venv.work_dir, venv_dir.path):
                virtualenv = Virtualenv.create_atomic(
                    venv_dir=venv,
                    interpreter=pex.interpreter,
                    copies=pex_info.venv_copies,
                    system_site_packages=pex_info.venv_system_site_packages,
                    prompt=os.path.basename(ENV.PEX) if ENV.PEX else None,
                )

                pex_path = os.path.abspath(pex.path())


                venv_hash = hashlib.sha1(venv_dir.encode("utf-8")).hexdigest()
                collisions = []
                for chars in range(8, len(venv_hash) + 1):
                    entropy = venv_hash[:chars]
                    venv_dirs = VenvDirs(venv_dir=venv_dir, short_hash=entropy)
                    with atomic_directory(venv_dirs.short_dir) as short_venv:
                        if short_venv.is_finalized():
                            collisions.append(venv_dirs.short_dir)
                            if entropy == venv_hash:
                                raise RuntimeError(
                                    "The venv for {pex} at {venv} has hash collisions with {count} "
                                    "other {venvs}!\n{collisions}".format(
                                        pex=pex_path,
                                        venv=venv_dir,
                                        count=len(collisions),
                                        venvs=pluralize(collisions, "venv"),
                                        collisions="\n".join(
                                            "{index}.) {venv_path}".format(
                                                index=index, venv_path=os.path.realpath(path)
                                            )
                                            for index, path in enumerate(collisions, start=1)
                                        ),
                                    )
                                )
                            continue

                        with interpreter.path_mapping(short_venv.work_dir, venv_dirs.short_dir):
                            safe_symlink(
                                os.path.relpath(venv_dirs, venv_dirs.short_dir),
                                os.path.join(short_venv.work_dir, venv_dirs.SHORT_SYMLINK_NAME),
                            )


                            copy_mode = copy_mode or (
                                CopyMode.SYMLINK
                                if (
                                    not WINDOWS
                                    and pex.layout != Layout.LOOSE
                                    and not pex_info.venv_site_packages_copies
                                )
                                else CopyMode.LINK
                            )

                            shebang = installer.populate_venv_from_pex(
                                virtualenv,
                                pex,
                                bin_path=pex_info.venv_bin_path,
                                shebang_python=os.path.join(
                                    venv_dirs.short_dir,
                                    "venv",
                                    SCRIPT_DIR,
                                    os.path.basename(virtualenv.interpreter.binary),
                                ),
                                collisions_ok=collisions_ok,
                                copy_mode=copy_mode,
                                hermetic_scripts=pex_info.venv_hermetic_scripts,
                            )


                            if len(shebang) > 128:
                                pex_warnings.warn(
                                    "The venv for {pex} at {venv} has script shebangs of "
                                    "{shebang!r} with {count} characters. On some systems this may "
                                    "be too long and cause problems running the venv scripts. You "
                                    "may be able adjust PEX_ROOT from {pex_root} to a shorter path "
                                    "as a work-around.".format(
                                        pex=pex_path,
                                        venv=venv_dir,
                                        shebang=shebang,
                                        count=len(shebang),
                                        pex_root=pex_info.pex_root,
                                    )
                                )

                            break
    if record_access:
        cache_access.record_access(venv_dir)
    return VenvPex(
        venv_dir,
        hermetic_script_args=(
            pex.interpreter.hermetic_args if pex_info.venv_hermetic_scripts else None
        ),
    )


def bootstrap_pex(
    entry_point,
    execute=True,
    venv_dir=None,
    python_args=(),
):
    # type: (...) -> Any

    pex_info = _bootstrap(entry_point)


    with ENV.patch(PEX_ROOT=pex_info.pex_root):
        cache_access.read_write()
        if not execute:
            for location in _activate_pex(entry_point, pex_info, venv_dir=venv_dir):
                from pex.third_party import VendorImporter

                VendorImporter.install(
                    uninstallable=False, prefix="__pex__", path_items=["."], root=location
                )

            from pex import bootstrap


            bootstrap.demote(disable_vendor_importer=False)
            return

        interpreter_test = InterpreterTest(entry_point=entry_point, pex_info=pex_info)
        if not (ENV.PEX_UNZIP or ENV.PEX_TOOLS) and pex_info.venv:
            try:
                target = find_compatible_interpreter(
                    interpreter_test=interpreter_test,
                    interpreter_selection_strategy=pex_info.interpreter_selection_strategy,
                )
            except UnsatisfiableInterpreterConstraintsError as e:
                die(str(e))
            venv_pex = _bootstrap_venv(entry_point, interpreter=target)
            venv_pex.execv(python_args=python_args, additional_args=sys.argv[1:])
        else:
            maybe_reexec_pex(
                interpreter_test=interpreter_test,
                interpreter_selection_strategy=pex_info.interpreter_selection_strategy,
                python_args=python_args,
            )
            from . import pex

            try:
                return pex.PEX(entry_point).execute(python_args=python_args)
            except pex.PEX.Error as e:
                return e


def _activate_pex(
    entry_point,
    pex_info,
    venv_dir=None,
):
    # type: (...) -> Iterator[str]

    if pex_info.venv:
        for location in _activate_venv_dir(entry_point, venv_dir=venv_dir):
            yield location
        return

    from . import pex

    yield entry_point
    for distribution in pex.PEX(entry_point).activate():
        yield distribution.location


def _activate_venv_dir(
    entry_point,
    venv_dir=None,
):
    # type: (...) -> Iterable[str]

    venv_python = None

    if venv_dir:
        python = os.path.join(venv_dir, SCRIPT_DIR, script_name("python"))
        if os.path.exists(python):
            venv_python = python

    if not venv_python:
        venv_python = _bootstrap_venv(entry_point).python

    from pex.venv.virtualenv import Virtualenv

    venv = Virtualenv.enclosing(venv_python)
    if not venv:
        die("Failed to load virtualenv for interpreter at {path}.".format(path=venv_python))

    site_packages_dir = venv.site_packages_dir
    sys.path.insert(0, site_packages_dir)
    import site

    site.addsitedir(site_packages_dir)
    yield site_packages_dir


def _bootstrap_venv(
    entry_point,
    interpreter=None,
):
    # type: (...) -> VenvPex

    from . import pex

    try:
        return ensure_venv(pex.PEX(entry_point, interpreter=interpreter))
    except ValueError as e:
        die(str(e))


def is_compressed(entry_point):
    # type: (str) -> bool
    return os.path.exists(entry_point) and not os.path.exists(
        os.path.join(entry_point, PexInfo.PATH)
    )


def bootstrap_pex_env(entry_point):
    # type: (str) -> None
    pex_info = _bootstrap(entry_point)

    from .environment import PEXEnvironment

    PEXEnvironment.mount(entry_point, pex_info).activate()

    from . import bootstrap

    bootstrap.demote()
