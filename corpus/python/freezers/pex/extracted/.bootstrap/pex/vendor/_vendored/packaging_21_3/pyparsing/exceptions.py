

import re
import sys
from typing import Optional

from .util import col, line, lineno, _collapse_string_to_ranges
from .unicode import pyparsing_unicode as ppu


class ExceptionWordUnicode(ppu.Latin1, ppu.LatinA, ppu.LatinB, ppu.Greek, ppu.Cyrillic):
    pass


_extract_alphanums = _collapse_string_to_ranges(ExceptionWordUnicode.alphanums)
_exception_word_extractor = re.compile("([" + _extract_alphanums + "]{1,16})|.")


class ParseBaseException(Exception):


    def __init__(
        self,
        pstr: str,
        loc: int = 0,
        msg: Optional[str] = None,
        elem=None,
    ):
        self.loc = loc
        if msg is None:
            self.msg = pstr
            self.pstr = ""
        else:
            self.msg = msg
            self.pstr = pstr
        self.parser_element = self.parserElement = elem
        self.args = (pstr, loc, msg)

    @staticmethod
    def explain_exception(exc, depth=16):
        import inspect
        from .core import ParserElement

        if depth is None:
            depth = sys.getrecursionlimit()
        ret = []
        if isinstance(exc, ParseBaseException):
            ret.append(exc.line)
            ret.append(" " * (exc.column - 1) + "^")
        ret.append("{}: {}".format(type(exc).__name__, exc))

        if depth > 0:
            callers = inspect.getinnerframes(exc.__traceback__, context=depth)
            seen = set()
            for i, ff in enumerate(callers[-depth:]):
                frm = ff[0]

                f_self = frm.f_locals.get("self", None)
                if isinstance(f_self, ParserElement):
                    if frm.f_code.co_name not in ("parseImpl", "_parseNoCache"):
                        continue
                    if id(f_self) in seen:
                        continue
                    seen.add(id(f_self))

                    self_type = type(f_self)
                    ret.append(
                        "{}.{} - {}".format(
                            self_type.__module__, self_type.__name__, f_self
                        )
                    )

                elif f_self is not None:
                    self_type = type(f_self)
                    ret.append("{}.{}".format(self_type.__module__, self_type.__name__))

                else:
                    code = frm.f_code
                    if code.co_name in ("wrapper", "<module>"):
                        continue

                    ret.append("{}".format(code.co_name))

                depth -= 1
                if not depth:
                    break

        return "\n".join(ret)

    @classmethod
    def _from_exception(cls, pe):
        return cls(pe.pstr, pe.loc, pe.msg, pe.parserElement)

    @property
    def line(self) -> str:
        return line(self.loc, self.pstr)

    @property
    def lineno(self) -> int:
        return lineno(self.loc, self.pstr)

    @property
    def col(self) -> int:
        return col(self.loc, self.pstr)

    @property
    def column(self) -> int:
        return col(self.loc, self.pstr)

    def __str__(self) -> str:
        if self.pstr:
            if self.loc >= len(self.pstr):
                foundstr = ", found end of text"
            else:

                found_match = _exception_word_extractor.match(self.pstr, self.loc)
                if found_match is not None:
                    found = found_match.group(0)
                else:
                    found = self.pstr[self.loc : self.loc + 1]
                foundstr = (", found %r" % found).replace(r"\\", "\\")
        else:
            foundstr = ""
        return "{}{}  (at char {}), (line:{}, col:{})".format(
            self.msg, foundstr, self.loc, self.lineno, self.column
        )

    def __repr__(self):
        return str(self)

    def mark_input_line(self, marker_string: str = None, *, markerString=">!<") -> str:
        markerString = marker_string if marker_string is not None else markerString
        line_str = self.line
        line_column = self.column - 1
        if markerString:
            line_str = "".join(
                (line_str[:line_column], markerString, line_str[line_column:])
            )
        return line_str.strip()

    def explain(self, depth=16) -> str:
        return self.explain_exception(self, depth)

    markInputline = mark_input_line


class ParseException(ParseBaseException):


class ParseFatalException(ParseBaseException):


class ParseSyntaxException(ParseFatalException):


class RecursiveGrammarException(Exception):

    def __init__(self, parseElementList):
        self.parseElementTrace = parseElementList

    def __str__(self) -> str:
        return "RecursiveGrammarException: {}".format(self.parseElementTrace)
