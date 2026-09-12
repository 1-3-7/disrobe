

from __future__ import annotations

from typing import Iterator

from ._parser import parse_requirement as _parse_requirement
from ._tokenizer import ParserSyntaxError
from .markers import Marker, _normalize_extra_values
from .specifiers import SpecifierSet
from .utils import canonicalize_name

__all__ = [
    "InvalidRequirement",
    "Requirement",
]


def __dir__() -> list[str]:
    return __all__


class InvalidRequirement(ValueError):


class Requirement:


    def __init__(self, requirement_string: str) -> None:
        try:
            parsed = _parse_requirement(requirement_string)
        except ParserSyntaxError as e:
            raise InvalidRequirement(str(e)) from e

        self.name: str = parsed.name
        self.url: str | None = parsed.url or None
        self.extras: set[str] = set(parsed.extras or [])
        self.specifier: SpecifierSet = SpecifierSet(parsed.specifier)
        self.marker: Marker | None = None
        if parsed.marker is not None:
            self.marker = Marker.__new__(Marker)
            self.marker._markers = _normalize_extra_values(parsed.marker)

    def _iter_parts(self, name: str) -> Iterator[str]:
        yield name

        if self.extras:
            formatted_extras = ",".join(sorted(self.extras))
            yield f"[{formatted_extras}]"

        if self.specifier:
            yield str(self.specifier)

        if self.url:
            yield f" @ {self.url}"
            if self.marker:
                yield " "

        if self.marker:
            yield f"; {self.marker}"

    def __getstate__(self) -> str:


        return str(self)

    def __setstate__(self, state: object) -> None:
        if isinstance(state, str):

            try:
                tmp = Requirement(state)
            except InvalidRequirement as exc:
                raise TypeError(f"Cannot restore Requirement from {state!r}") from exc
            self.name = tmp.name
            self.url = tmp.url
            self.extras = tmp.extras
            self.specifier = tmp.specifier
            self.marker = tmp.marker
            return
        if isinstance(state, dict):

            self.__dict__.update(state)
            return
        raise TypeError(f"Cannot restore Requirement from {state!r}")

    def __str__(self) -> str:
        return "".join(self._iter_parts(self.name))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}({str(self)!r})>"

    def __hash__(self) -> int:
        return hash(tuple(self._iter_parts(canonicalize_name(self.name))))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Requirement):
            return NotImplemented

        return (
            canonicalize_name(self.name) == canonicalize_name(other.name)
            and self.extras == other.extras
            and self.specifier == other.specifier
            and self.url == other.url
            and self.marker == other.marker
        )
