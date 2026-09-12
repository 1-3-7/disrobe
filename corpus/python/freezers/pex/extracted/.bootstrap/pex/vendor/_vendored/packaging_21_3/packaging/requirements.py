

import re
import string
import urllib.parse
from typing import List, Optional as TOptional, Set

if "packaging" in __import__("os").environ.get("__PEX_UNVENDORED__", ""):
    from pyparsing import (
    Combine,
    Literal as L,
    Optional,
    ParseException,
    Regex,
    Word,
    ZeroOrMore,
    originalTextFor,
    stringEnd,
    stringStart,
)
else:
    from pex.third_party.pyparsing import (
    Combine,
    Literal as L,
    Optional,
    ParseException,
    Regex,
    Word,
    ZeroOrMore,
    originalTextFor,
    stringEnd,
    stringStart,
)


from .markers import MARKER_EXPR, Marker
from .specifiers import LegacySpecifier, Specifier, SpecifierSet


class InvalidRequirement(ValueError):


ALPHANUM = Word(string.ascii_letters + string.digits)

LBRACKET = L("[").suppress()
RBRACKET = L("]").suppress()
LPAREN = L("(").suppress()
RPAREN = L(")").suppress()
COMMA = L(",").suppress()
SEMICOLON = L(";").suppress()
AT = L("@").suppress()

PUNCTUATION = Word("-_.")
IDENTIFIER_END = ALPHANUM | (ZeroOrMore(PUNCTUATION) + ALPHANUM)
IDENTIFIER = Combine(ALPHANUM + ZeroOrMore(IDENTIFIER_END))

NAME = IDENTIFIER("name")
EXTRA = IDENTIFIER

URI = Regex(r"[^ ]+")("url")
URL = AT + URI

EXTRAS_LIST = EXTRA + ZeroOrMore(COMMA + EXTRA)
EXTRAS = (LBRACKET + Optional(EXTRAS_LIST) + RBRACKET)("extras")

VERSION_PEP440 = Regex(Specifier._regex_str, re.VERBOSE | re.IGNORECASE)
VERSION_LEGACY = Regex(LegacySpecifier._regex_str, re.VERBOSE | re.IGNORECASE)

VERSION_ONE = VERSION_PEP440 ^ VERSION_LEGACY
VERSION_MANY = Combine(
    VERSION_ONE + ZeroOrMore(COMMA + VERSION_ONE), joinString=",", adjacent=False
)("_raw_spec")
_VERSION_SPEC = Optional((LPAREN + VERSION_MANY + RPAREN) | VERSION_MANY)
_VERSION_SPEC.setParseAction(lambda s, l, t: t._raw_spec or "")

VERSION_SPEC = originalTextFor(_VERSION_SPEC)("specifier")
VERSION_SPEC.setParseAction(lambda s, l, t: t[1])

MARKER_EXPR = originalTextFor(MARKER_EXPR())("marker")
MARKER_EXPR.setParseAction(
    lambda s, l, t: Marker(s[t._original_start : t._original_end])
)
MARKER_SEPARATOR = SEMICOLON
MARKER = MARKER_SEPARATOR + MARKER_EXPR

VERSION_AND_MARKER = VERSION_SPEC + Optional(MARKER)
URL_AND_MARKER = URL + Optional(MARKER)

NAMED_REQUIREMENT = NAME + Optional(EXTRAS) + (URL_AND_MARKER | VERSION_AND_MARKER)

REQUIREMENT = stringStart + NAMED_REQUIREMENT + stringEnd


REQUIREMENT.parseString("x[]")


class Requirement:


    def __init__(self, requirement_string: str) -> None:
        try:
            req = REQUIREMENT.parseString(requirement_string)
        except ParseException as e:
            raise InvalidRequirement(
                f'Parse error at "{ requirement_string[e.loc : e.loc + 8]!r}": {e.msg}'
            )

        self.name: str = req.name
        if req.url:
            parsed_url = urllib.parse.urlparse(req.url)
            if parsed_url.scheme == "file":
                if urllib.parse.urlunparse(parsed_url) != req.url:
                    raise InvalidRequirement("Invalid URL given")
            elif not (parsed_url.scheme and parsed_url.netloc) or (
                not parsed_url.scheme and not parsed_url.netloc
            ):
                raise InvalidRequirement(f"Invalid URL: {req.url}")
            self.url: TOptional[str] = req.url
        else:
            self.url = None
        self.extras: Set[str] = set(req.extras.asList() if req.extras else [])
        self.specifier: SpecifierSet = SpecifierSet(req.specifier)
        self.marker: TOptional[Marker] = req.marker if req.marker else None

    def __str__(self) -> str:
        parts: List[str] = [self.name]

        if self.extras:
            formatted_extras = ",".join(sorted(self.extras))
            parts.append(f"[{formatted_extras}]")

        if self.specifier:
            parts.append(str(self.specifier))

        if self.url:
            parts.append(f"@ {self.url}")
            if self.marker:
                parts.append(" ")

        if self.marker:
            parts.append(f"; {self.marker}")

        return "".join(parts)

    def __repr__(self) -> str:
        return f"<Requirement('{self}')>"
