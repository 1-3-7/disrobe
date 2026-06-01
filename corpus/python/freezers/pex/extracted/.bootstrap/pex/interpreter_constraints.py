

from __future__ import absolute_import

import itertools

from pex import pex_warnings
from pex.common import pluralize
from pex.compatibility import indent
from pex.enum import Enum
from pex.interpreter import PythonInterpreter
from pex.interpreter_implementation import InterpreterImplementation
from pex.orderedset import OrderedSet
from pex.specifier_sets import UnsatisfiableSpecifierSet, as_range
from pex.third_party.packaging.specifiers import InvalidSpecifier, SpecifierSet
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterable, Iterator, List, Optional, Tuple

    import attr

    from pex.interpreter import InterpreterIdentificationError
else:
    from pex.third_party import attr


class UnsatisfiableError(ValueError):


def _iter_interpreter_implementations():
    # type: () -> Iterator[Tuple[InterpreterImplementation.Value, str]]
    for interpreter_implementation in InterpreterImplementation.values():
        yield interpreter_implementation, interpreter_implementation.value
        if interpreter_implementation.alias:
            yield interpreter_implementation, interpreter_implementation.alias


_INTERPRETER_IMPLEMENTATIONS = tuple(
    sorted(_iter_interpreter_implementations(), key=lambda tup: tup[1], reverse=True)
)


@attr.s(frozen=True)
class InterpreterConstraint(object):
    @classmethod
    def parse(
        cls,
        constraint,
        default_interpreter_implementation=None,
    ):
        # type: (...) -> InterpreterConstraint

        implementation = default_interpreter_implementation
        specifier = constraint

        for interpreter_implementation, value in _INTERPRETER_IMPLEMENTATIONS:
            if constraint.startswith(value):
                implementation = interpreter_implementation
                specifier = constraint[len(value) :]
                break

        try:
            return cls(specifier=SpecifierSet(specifier), implementation=implementation)
        except InvalidSpecifier as e:
            raise ValueError(
                "Unparseable interpreter constraint {constraint}: {err}".format(
                    constraint=constraint, err=e
                )
            )

    @classmethod
    def matches(
        cls,
        constraint,
        interpreter=None,
    ):
        return (interpreter or PythonInterpreter.get()) in cls.parse(constraint)

    @classmethod
    def exact_version(cls, interpreter=None):
        # type: (Optional[PythonInterpreter]) -> InterpreterConstraint
        python_identity = (interpreter or PythonInterpreter.get()).identity
        return cls.parse(
            "{implementation}=={version}".format(
                implementation=python_identity.implementation, version=python_identity.version_str
            )
        )

    specifier = attr.ib()
    implementation = attr.ib(default=None)

    @specifier.validator
    def _validate_specifier(
        self,
        _attribute,
        value,
    ):
        # type: (...) -> None
        if isinstance(as_range(value), UnsatisfiableSpecifierSet):
            raise UnsatisfiableError(
                "The interpreter constraint {constraint} is unsatisfiable.".format(constraint=self)
            )

    def iter_matching(self, paths=None):
        # type: (Optional[Iterable[str]]) -> Iterator[PythonInterpreter]
        for interp in PythonInterpreter.iter(paths=paths):
            if interp in self:
                yield interp

    @property
    def requires_python(self):
        # type: () -> SpecifierSet
        return self.specifier

    def __str__(self):
        # type: () -> str
        return "{implementation}{specifier}".format(
            implementation=self.implementation or "", specifier=self.specifier
        )

    def __contains__(self, interpreter):
        # type: (PythonInterpreter) -> bool
        python_identity = interpreter.identity
        if self.implementation and not self.implementation.includes(python_identity.implementation):
            return False
        return python_identity.version_str in self.specifier


@attr.s(frozen=True)
class InterpreterConstraints(object):
    @classmethod
    def parse(cls, *constraints):
        # type: (str) -> InterpreterConstraints

        interpreter_constraints = []
        unsatisfiable = []
        all_constraints = OrderedSet(constraints)
        for constraint in all_constraints:
            try:
                interpreter_constraints.append(InterpreterConstraint.parse(constraint))
            except UnsatisfiableError as e:
                unsatisfiable.append((constraint, e))

        if unsatisfiable:
            if len(unsatisfiable) == 1:
                _, err = unsatisfiable[0]
                if not interpreter_constraints:
                    raise err
                message = str(err)
            else:
                message = (
                    "Given interpreter constraints are unsatisfiable:\n{unsatisfiable}".format(
                        unsatisfiable="\n".join(constraint for constraint, _ in unsatisfiable)
                    )
                )

            if not interpreter_constraints:
                raise UnsatisfiableError(message)
            pex_warnings.warn(
                "Only {count} interpreter {constraints} {are} valid amongst: {all_constraints}.\n"
                "{message}\n"
                "Continuing using only {interpreter_constraints}".format(
                    count=len(interpreter_constraints),
                    constraints=pluralize(interpreter_constraints, "constraint"),
                    are="is" if len(interpreter_constraints) == 1 else "are",
                    all_constraints=" or ".join(all_constraints),
                    message=message,
                    interpreter_constraints=" or ".join(map(str, interpreter_constraints)),
                )
            )

        return cls(constraints=tuple(interpreter_constraints))

    constraints = attr.ib(default=())

    def merged(self, other):
        # type: (InterpreterConstraints) -> InterpreterConstraints
        constraints = OrderedSet(self.constraints)
        constraints.update(other.constraints)
        return InterpreterConstraints(constraints=tuple(constraints))

    def __str__(self):
        # type: () -> str
        return " or ".join(str(constraint) for constraint in self.constraints)

    def __contains__(self, interpreter):
        if not self.constraints:
            return True
        return any(interpreter in constraint for constraint in self.constraints)

    def __iter__(self):
        # type: () -> Iterator[InterpreterConstraint]
        return iter(self.constraints)

    def __bool__(self):
        # type: () -> bool
        return bool(self.constraints)


    __nonzero__ = __bool__

    def __len__(self):
        # type: () -> int
        return len(self.constraints)

    def __getitem__(self, item):
        # type: (int) -> InterpreterConstraint
        return self.constraints[item]


class UnsatisfiableInterpreterConstraintsError(Exception):

    def __init__(
        self,
        constraints,
        candidates,
        failures,
        preamble=None,
    ):
        # type: (...) -> None
        self.constraints = tuple(constraints)
        self.candidates = tuple(candidates)
        self.failures = tuple(failures)
        super(UnsatisfiableInterpreterConstraintsError, self).__init__(
            self.create_message(preamble=preamble)
        )

    def with_preamble(self, preamble):
        # type: (str) -> UnsatisfiableInterpreterConstraintsError
        return UnsatisfiableInterpreterConstraintsError(
            self.constraints, self.candidates, self.failures, preamble=preamble
        )

    def create_message(self, preamble=None):
        # type: (Optional[str]) -> str
        preamble = "{}\n\n".format(preamble) if preamble else ""

        failures_message = ""
        if self.failures:
            seen = set()
            broken_interpreters = []
            for python, error in self.failures:
                canonical_python = PythonInterpreter.canonicalize_path(python)
                if canonical_python not in seen:
                    broken_interpreters.append((canonical_python, error))
                    seen.add(canonical_python)

            failures_message = (
                "{}\n"
                "\n"
                "(See https://github.com/pex-tool/pex/issues/1027 for a list of known breaks and "
                "workarounds.)"
            ).format(
                "\n".join(
                    "{index}.) {binary}:\n{error}".format(index=i, binary=python, error=error)
                    for i, (python, error) in enumerate(broken_interpreters, start=1)
                )
            )

        if not self.candidates:
            if failures_message:
                return (
                    "{preamble}"
                    "Interpreters were found but they all appear to be broken:\n"
                    "{failures}"
                ).format(preamble=preamble, failures=failures_message)
            return "{}No interpreters could be found on the system.".format(preamble)

        binary_column_width = max(len(candidate.binary) for candidate in self.candidates)
        interpreters_format = "{{index}}.) {{binary: >{}}} {{requirement}}".format(
            binary_column_width
        )

        qualifier = ""
        if failures_message:
            failures_message = "Skipped the following broken interpreters:\n{}".format(
                failures_message
            )
            qualifier = "working "

        constraints_message = ""
        if self.constraints:
            constraints_message = (
                "No {qualifier}interpreter compatible with the requested constraints was found:\n"
                "\n{constraints}"
            ).format(
                qualifier=qualifier,
                constraints="\n\n".join(
                    indent(constraint, "  ") for constraint in self.constraints
                ),
            )

        problems = "\n\n".join(msg for msg in (failures_message, constraints_message) if msg)
        if problems:
            problems = "\n\n{}".format(problems)

        return (
            "{preamble}"
            "Examined the following {qualifier}interpreters:\n"
            "{interpreters}"
            "{problems}"
        ).format(
            preamble=preamble,
            qualifier=qualifier,
            interpreters="\n".join(
                interpreters_format.format(
                    index=i,
                    binary=candidate.binary,
                    requirement=InterpreterConstraint.exact_version(candidate),
                )
                for i, candidate in enumerate(self.candidates, start=1)
            ),
            problems=problems,
        )


class Lifecycle(Enum["Lifecycle.Value"]):
    class Value(Enum.Value):
        pass

    DEV = Value("dev")
    STABLE = Value("stable")
    EOL = Value("eol")


Lifecycle.seal()


DEFAULT_MAX_PATCH = 30


@attr.s(frozen=True)
class PythonVersion(object):
    lifecycle = attr.ib()
    major = attr.ib()
    minor = attr.ib()
    patch = attr.ib()

    def iter_compatible_versions(
        self,
        specifier_sets,
        max_patch=DEFAULT_MAX_PATCH,
    ):
        # type: (...) -> Iterator[Tuple[int, int, int]]
        last_patch = self.patch if self.lifecycle == Lifecycle.EOL else max_patch
        for patch in range(last_patch + 1):
            version = (self.major, self.minor, patch)
            version_string = ".".join(map(str, version))
            if not specifier_sets:
                yield version
            else:
                for specifier_set in specifier_sets:
                    if version_string in specifier_set:
                        yield version
                        break


COMPATIBLE_PYTHON_VERSIONS = (
    PythonVersion(Lifecycle.EOL, 2, 7, 18),

    PythonVersion(Lifecycle.EOL, 3, 5, 10),
    PythonVersion(Lifecycle.EOL, 3, 6, 15),
    PythonVersion(Lifecycle.EOL, 3, 7, 17),
    PythonVersion(Lifecycle.EOL, 3, 8, 20),
    PythonVersion(Lifecycle.EOL, 3, 9, 25),
    PythonVersion(Lifecycle.STABLE, 3, 10, 20),
    PythonVersion(Lifecycle.STABLE, 3, 11, 15),
    PythonVersion(Lifecycle.STABLE, 3, 12, 13),
    PythonVersion(Lifecycle.STABLE, 3, 13, 13),
    PythonVersion(Lifecycle.STABLE, 3, 14, 5),
    PythonVersion(Lifecycle.DEV, 3, 15, 0),
)


def iter_compatible_versions(
    requires_python,
    max_patch=DEFAULT_MAX_PATCH,
):
    # type: (...) -> Iterator[Tuple[int, int, int]]

    specifier_sets = OrderedSet(requires_python)
    return itertools.chain.from_iterable(
        python_version.iter_compatible_versions(specifier_sets, max_patch=max_patch)
        for python_version in COMPATIBLE_PYTHON_VERSIONS
    )
