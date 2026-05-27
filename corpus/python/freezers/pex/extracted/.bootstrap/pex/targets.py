

from __future__ import absolute_import

import os

from pex.dist_metadata import Constraint, Distribution
from pex.dist_metadata import requires_python as dist_requires_python
from pex.interpreter import PythonInterpreter
from pex.interpreter_implementation import InterpreterImplementation
from pex.interpreter_selection_strategy import InterpreterSelectionStrategy
from pex.orderedset import OrderedSet
from pex.pep_425 import CompatibilityTags, RankedTag
from pex.pep_508 import MarkerEnvironment
from pex.platforms import Platform
from pex.result import Error
from pex.third_party.packaging.specifiers import SpecifierSet
from pex.third_party.packaging.tags import Tag
from pex.typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from typing import Any, Iterable, Iterator, Optional, Tuple, Union

    import attr
else:
    from pex.third_party import attr


class RequiresPythonError(Exception):


@attr.s(frozen=True)
class WheelEvaluation(object):
    @classmethod
    def select_best_match(cls, evals):
        # type: (Iterable[WheelEvaluation]) -> Optional[WheelEvaluation]
        match = None
        for wheel_eval in evals:
            if not wheel_eval.applies:
                continue
            if match is None:
                match = wheel_eval
            elif wheel_eval.best_match and (
                wheel_eval.best_match.select_higher_rank(match.best_match) == wheel_eval.best_match
            ):
                match = wheel_eval
        return match

    wheel = attr.ib()
    tags = attr.ib()
    best_match = attr.ib()
    requires_python = attr.ib()
    applies = attr.ib()

    def __bool__(self):
        # type: () -> bool
        return self.applies


    __nonzero__ = __bool__


@attr.s(frozen=True, repr=False)
class Target(object):
    id = attr.ib()
    platform = attr.ib()
    marker_environment = attr.ib()
    implementation = attr.ib(init=False)

    def __attrs_post_init__(self):
        interpreter_implementation = None
        for interpreter_impl in InterpreterImplementation.values():
            if interpreter_impl.value == self.marker_environment.platform_python_implementation:
                interpreter_implementation = interpreter_impl
                break
        object.__setattr__(self, "implementation", interpreter_implementation)

    def binary_name(self, version_components=2):
        # type: (int) -> str
        interpreter_implementation = self.implementation or InterpreterImplementation.CPYTHON
        return interpreter_implementation.calculate_binary_name(
            version=(
                self.python_version[:version_components]
                if self.python_version and version_components > 0
                else None
            )
        )

    @property
    def python_version(self):
        # type: () -> Optional[Union[Tuple[int, int], Tuple[int, int, int]]]
        python_full_version = self.marker_environment.python_full_version
        if python_full_version:
            return cast("Tuple[int, int, int]", tuple(map(int, python_full_version.split(".")))[:3])
        python_version = self.marker_environment.python_version
        if python_version:
            return cast("Tuple[int, int]", tuple(map(int, python_version.split(".")))[:2])
        return None

    @property
    def platform_tag(self):
        # type: () -> Tag
        return self.supported_tags[0]

    @property
    def supported_tags(self):
        # type: () -> CompatibilityTags
        raise NotImplementedError()

    @property
    def is_foreign(self):
        # type: () -> bool
        return self.platform not in self.get_interpreter().supported_platforms

    @property
    def python_version_str(self):
        # type: () -> Optional[str]
        return self.marker_environment.python_full_version or self.marker_environment.python_version

    def get_interpreter(self):
        # type: () -> PythonInterpreter
        return PythonInterpreter.get()

    def requires_python_applies(
        self,
        requires_python,
        source,
    ):
        # type: (...) -> bool

        if not self.python_version_str:
            raise RequiresPythonError(
                "Encountered `Requires-Python: {requires_python}` when evaluating {source} "
                "for applicability but the Python version information needed to evaluate this "
                "requirement is not contained in the target being evaluated for: {target}".format(
                    requires_python=requires_python, source=source, target=self
                )
            )


        return self.python_version_str in requires_python

    def requirement_applies(
        self,
        requirement,
        extras=(),
    ):
        # type: (...) -> bool
        if requirement.marker is None:
            return True

        if not extras:

            extras = ("",)
        for extra in extras:
            environment = self.marker_environment.as_dict()
            environment["extra"] = extra
            if requirement.marker.evaluate(environment=environment):
                return True

        return False

    def wheel_applies(self, wheel):
        # type: (Union[str, Distribution]) -> WheelEvaluation

        wheel_tags = CompatibilityTags.from_wheel(wheel, platform_tag=self.platform_tag)
        ranked_tag = self.supported_tags.best_match(wheel_tags)
        requires_python = (
            wheel.metadata.requires_python
            if isinstance(wheel, Distribution)
            else dist_requires_python(wheel)
        )
        wheel_location = wheel.location if isinstance(wheel, Distribution) else wheel

        return WheelEvaluation(
            wheel=wheel_location,
            tags=tuple(wheel_tags),
            best_match=ranked_tag,
            requires_python=requires_python,
            applies=(
                ranked_tag is not None
                and (
                    not requires_python
                    or self.requires_python_applies(requires_python, source=wheel_location)
                )
            ),
        )

    def __str__(self):
        # type: () -> str
        return str(self.platform.tag)

    def render_description(self):
        # type: () -> str
        raise NotImplementedError()

    def __repr__(self):
        # type: () -> str
        return "{clazz}({self!r})".format(clazz=type(self).__name__, self=str(self))


@attr.s(frozen=True, repr=False)
class LocalInterpreter(Target):
    @classmethod
    def create(cls, interpreter=None):
        # type: (Optional[Union[str, PythonInterpreter]]) -> LocalInterpreter

        if not interpreter:
            python_interpreter = PythonInterpreter.get()
        elif isinstance(interpreter, PythonInterpreter):
            python_interpreter = interpreter
        else:
            python_interpreter = PythonInterpreter.from_binary(interpreter)

        return cls(
            id=python_interpreter.binary.replace(os.sep, ".").lstrip("."),
            platform=python_interpreter.platform,
            marker_environment=python_interpreter.identity.env_markers,
            interpreter=python_interpreter,
        )

    interpreter = attr.ib()

    def binary_name(self, version_components=2):
        # type: (int) -> str
        return self.interpreter.identity.binary_name(version_components=version_components)

    @property
    def python_version(self):
        # type: () -> Tuple[int, int, int]
        return self.interpreter.identity.version[:3]

    @property
    def is_foreign(self):
        # type: () -> bool
        return False

    @property
    def python_version_str(self):
        # type: () -> str
        return self.interpreter.identity.version_str

    def get_interpreter(self):
        # type: () -> PythonInterpreter
        return self.interpreter

    @property
    def supported_tags(self):
        return self.interpreter.identity.supported_tags

    def __str__(self):
        # type: () -> str
        return self.interpreter.binary

    def render_description(self):
        # type: () -> str
        return "{platform} interpreter at {path}".format(
            platform=self.interpreter.platform.tag, path=self.interpreter.binary
        )


@attr.s(frozen=True, repr=False)
class AbbreviatedPlatform(Target):
    @classmethod
    def create(cls, platform):
        # type: (Platform) -> AbbreviatedPlatform
        return cls(
            id=str(platform.tag),
            marker_environment=MarkerEnvironment.from_platform(platform),
            platform=platform,
        )

    @property
    def supported_tags(self):
        # type: () -> CompatibilityTags
        return self.platform.supported_tags

    def render_description(self):
        # type: () -> str
        return "abbreviated platform {platform}".format(platform=self.platform.tag)


def current():
    # type: () -> LocalInterpreter
    return LocalInterpreter.create()


@attr.s(frozen=True, repr=False)
class CompletePlatform(Target):
    @classmethod
    def from_interpreter(cls, interpreter):
        # type: (PythonInterpreter) -> CompletePlatform
        return cls.create(
            marker_environment=interpreter.identity.env_markers,
            supported_tags=interpreter.identity.supported_tags,
        )

    @classmethod
    def create(
        cls,
        marker_environment,
        supported_tags,
    ):
        # type: (...) -> CompletePlatform

        platform = Platform.from_tags(supported_tags)
        return cls(
            id=str(platform.tag),
            marker_environment=marker_environment,
            platform=platform,
            supported_tags=supported_tags,
        )

    _supported_tags = attr.ib()

    @property
    def supported_tags(self):
        # type: () -> CompatibilityTags
        return self._supported_tags

    def render_description(self):
        # type: () -> str
        return "complete platform {platform}".format(platform=self.platform.tag)


@attr.s(frozen=True)
class Targets(object):
    @classmethod
    def from_target(cls, target):
        # type: (Target) -> Targets
        if isinstance(target, AbbreviatedPlatform):
            return cls(platforms=(target.platform,))
        elif isinstance(target, CompletePlatform):
            return cls(complete_platforms=(target,))
        else:
            return cls(interpreters=(target.get_interpreter(),))

    interpreters = attr.ib(default=())
    interpreter_selection_strategy = attr.ib(
        default=InterpreterSelectionStrategy.OLDEST
    )
    complete_platforms = attr.ib(default=())
    platforms = attr.ib(default=())

    @property
    def is_empty(self):
        # type: () -> bool
        return not self.interpreters and not self.complete_platforms and not self.platforms

    @property
    def interpreter(self):
        # type: () -> Optional[PythonInterpreter]
        if not self.interpreters:
            return None
        return self.interpreter_selection_strategy.select(self.interpreters)

    def unique_targets(self, only_explicit=False):
        # type: (bool) -> OrderedSet[Target]

        def iter_targets():
            # type: () -> Iterator[Target]
            if (
                not only_explicit
                and not self.interpreters
                and not self.platforms
                and not self.complete_platforms
            ):


                yield current()
                return

            for interpreter in self.interpreters:

                yield LocalInterpreter.create(interpreter)

            for platform in self.platforms:
                if platform is None and not self.interpreters:


                    yield current()
                elif platform is not None:

                    yield AbbreviatedPlatform.create(platform)

            for complete_platform in self.complete_platforms:
                yield complete_platform

        return OrderedSet(iter_targets())

    def require_unique_target(self, purpose):
        # type: (str) -> Union[Target, Error]
        resolved_targets = self.unique_targets()
        if len(resolved_targets) != 1:
            return Error(
                "A single target is required for {purpose}.\n"
                "There were {count} targets selected:\n"
                "{targets}".format(
                    purpose=purpose,
                    count=len(resolved_targets),
                    targets="\n".join(
                        "{index}. {target}".format(index=index, target=target)
                        for index, target in enumerate(resolved_targets, start=1)
                    ),
                )
            )
        return cast(Target, next(iter(resolved_targets)))

    def require_at_most_one_target(self, purpose):
        # type: (str) -> Union[Optional[Target], Error]
        resolved_targets = self.unique_targets(only_explicit=True)
        if len(resolved_targets) > 1:
            return Error(
                "At most a single target is required for {purpose}.\n"
                "There were {count} targets selected:\n"
                "{targets}".format(
                    purpose=purpose,
                    count=len(resolved_targets),
                    targets="\n".join(
                        "{index}. {target}".format(index=index, target=target)
                        for index, target in enumerate(resolved_targets, start=1)
                    ),
                )
            )
        try:
            return cast(Target, next(iter(resolved_targets)))
        except StopIteration:
            return None

    def compatible_shebang(self):
        # type: () -> Optional[str]
        pythons = {
            (target.platform.impl, target.platform.version_info[:2])
            for target in self.unique_targets()
        }
        if len(pythons) == 1:
            impl, version = pythons.pop()
            return "#!/usr/bin/env {python}{version}".format(
                python="pypy" if impl == "pp" else "python", version=".".join(map(str, version))
            )
        return None
