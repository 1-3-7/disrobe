

import os
from typing import (
    Optional as OptionalType,
    Iterable as IterableType,
    NamedTuple,
    Union,
    Callable,
    Any,
    Generator,
    Tuple,
    List,
    TextIO,
    Set,
    Dict as DictType,
    Sequence,
)
from abc import ABC, abstractmethod
from enum import Enum
import string
import copy
import warnings
import re
import sre_constants
import sys
from collections.abc import Iterable
import traceback
import types
from operator import itemgetter
from functools import wraps
from threading import RLock
from pathlib import Path

from .util import (
    _FifoCache,
    _UnboundedCache,
    __config_flags,
    _collapse_string_to_ranges,
    _escape_regex_range_chars,
    _bslash,
    _flatten,
    LRUMemo as _LRUMemo,
    UnboundedMemo as _UnboundedMemo,
)
from .exceptions import *
from .actions import *
from .results import ParseResults, _ParseResultsWithOffset
from .unicode import pyparsing_unicode

_MAX_INT = sys.maxsize
str_type: Tuple[type, ...] = (str, bytes)


class __compat__(__config_flags):

    _type_desc = "compatibility"

    collect_all_And_tokens = True

    _all_names = [__ for __ in locals() if not __.startswith("_")]
    _fixed_names = """
        collect_all_And_tokens
        """.split()


class __diag__(__config_flags):
    _type_desc = "diagnostic"

    warn_multiple_tokens_in_named_alternation = False
    warn_ungrouped_named_tokens_in_collection = False
    warn_name_set_on_empty_Forward = False
    warn_on_parse_using_empty_Forward = False
    warn_on_assignment_to_Forward = False
    warn_on_multiple_string_args_to_oneof = False
    warn_on_match_first_with_lshift_operator = False
    enable_debug_on_named_expressions = False

    _all_names = [__ for __ in locals() if not __.startswith("_")]
    _warning_names = [name for name in _all_names if name.startswith("warn")]
    _debug_names = [name for name in _all_names if name.startswith("enable_debug")]

    @classmethod
    def enable_all_warnings(cls) -> None:
        for name in cls._warning_names:
            cls.enable(name)


class Diagnostics(Enum):

    warn_multiple_tokens_in_named_alternation = 0
    warn_ungrouped_named_tokens_in_collection = 1
    warn_name_set_on_empty_Forward = 2
    warn_on_parse_using_empty_Forward = 3
    warn_on_assignment_to_Forward = 4
    warn_on_multiple_string_args_to_oneof = 5
    warn_on_match_first_with_lshift_operator = 6
    enable_debug_on_named_expressions = 7


def enable_diag(diag_enum: Diagnostics) -> None:
    __diag__.enable(diag_enum.name)


def disable_diag(diag_enum: Diagnostics) -> None:
    __diag__.disable(diag_enum.name)


def enable_all_warnings() -> None:
    __diag__.enable_all_warnings()


del __config_flags


def _should_enable_warnings(
    cmd_line_warn_options: IterableType[str], warn_env_var: OptionalType[str]
) -> bool:
    enable = bool(warn_env_var)
    for warn_opt in cmd_line_warn_options:
        w_action, w_message, w_category, w_module, w_line = (warn_opt + "::::").split(
            ":"
        )[:5]
        if not w_action.lower().startswith("i") and (
            not (w_message or w_category or w_module) or w_module == "pyparsing"
        ):
            enable = True
        elif w_action.lower().startswith("i") and w_module in ("pyparsing", ""):
            enable = False
    return enable


if _should_enable_warnings(
    sys.warnoptions, os.environ.get("PYPARSINGENABLEALLWARNINGS")
):
    enable_all_warnings()


_single_arg_builtins = {
    sum,
    len,
    sorted,
    reversed,
    list,
    tuple,
    set,
    any,
    all,
    min,
    max,
}

_generatorType = types.GeneratorType
ParseAction = Union[
    Callable[[], Any],
    Callable[[ParseResults], Any],
    Callable[[int, ParseResults], Any],
    Callable[[str, int, ParseResults], Any],
]
ParseCondition = Union[
    Callable[[], bool],
    Callable[[ParseResults], bool],
    Callable[[int, ParseResults], bool],
    Callable[[str, int, ParseResults], bool],
]
ParseFailAction = Callable[[str, int, "ParserElement", Exception], None]
DebugStartAction = Callable[[str, int, "ParserElement", bool], None]
DebugSuccessAction = Callable[
    [str, int, int, "ParserElement", ParseResults, bool], None
]
DebugExceptionAction = Callable[[str, int, "ParserElement", Exception, bool], None]


alphas = string.ascii_uppercase + string.ascii_lowercase
identchars = pyparsing_unicode.Latin1.identchars
identbodychars = pyparsing_unicode.Latin1.identbodychars
nums = "0123456789"
hexnums = nums + "ABCDEFabcdef"
alphanums = alphas + nums
printables = "".join([c for c in string.printable if c not in string.whitespace])

_trim_arity_call_line = None


def _trim_arity(func, maxargs=2):
    global _trim_arity_call_line

    if func in _single_arg_builtins:
        return lambda s, l, t: func(t)

    limit = 0
    found_arity = False

    def extract_tb(tb, limit=0):
        frames = traceback.extract_tb(tb, limit=limit)
        frame_summary = frames[-1]
        return [frame_summary[:2]]


    LINE_DIFF = 11


    _trim_arity_call_line = (
        _trim_arity_call_line or traceback.extract_stack(limit=2)[-1]
    )
    pa_call_line_synth = (
        _trim_arity_call_line[0],
        _trim_arity_call_line[1] + LINE_DIFF,
    )

    def wrapper(*args):
        nonlocal found_arity, limit
        while 1:
            try:
                ret = func(*args[limit:])
                found_arity = True
                return ret
            except TypeError as te:

                if found_arity:
                    raise
                else:
                    tb = te.__traceback__
                    trim_arity_type_error = (
                        extract_tb(tb, limit=2)[-1][:2] == pa_call_line_synth
                    )
                    del tb

                    if trim_arity_type_error:
                        if limit <= maxargs:
                            limit += 1
                            continue

                    raise


    func_name = getattr(func, "__name__", getattr(func, "__class__").__name__)
    wrapper.__name__ = func_name

    return wrapper


def condition_as_parse_action(
    fn: ParseCondition, message: str = None, fatal: bool = False
) -> ParseAction:
    msg = message if message is not None else "failed user-defined condition"
    exc_type = ParseFatalException if fatal else ParseException
    fn = _trim_arity(fn)

    @wraps(fn)
    def pa(s, l, t):
        if not bool(fn(s, l, t)):
            raise exc_type(s, l, msg)

    return pa


def _default_start_debug_action(
    instring: str, loc: int, expr: "ParserElement", cache_hit: bool = False
):
    cache_hit_str = "*" if cache_hit else ""
    print(
        (
            "{}Match {} at loc {}({},{})\n  {}\n  {}^".format(
                cache_hit_str,
                expr,
                loc,
                lineno(loc, instring),
                col(loc, instring),
                line(loc, instring),
                " " * (col(loc, instring) - 1),
            )
        )
    )


def _default_success_debug_action(
    instring: str,
    startloc: int,
    endloc: int,
    expr: "ParserElement",
    toks: ParseResults,
    cache_hit: bool = False,
):
    cache_hit_str = "*" if cache_hit else ""
    print("{}Matched {} -> {}".format(cache_hit_str, expr, toks.as_list()))


def _default_exception_debug_action(
    instring: str,
    loc: int,
    expr: "ParserElement",
    exc: Exception,
    cache_hit: bool = False,
):
    cache_hit_str = "*" if cache_hit else ""
    print(
        "{}Match {} failed, {} raised: {}".format(
            cache_hit_str, expr, type(exc).__name__, exc
        )
    )


def null_debug_action(*args):


class ParserElement(ABC):

    DEFAULT_WHITE_CHARS: str = " \n\t\r"
    verbose_stacktrace: bool = False
    _literalStringClass: OptionalType[type] = None

    @staticmethod
    def set_default_whitespace_chars(chars: str) -> None:
        ParserElement.DEFAULT_WHITE_CHARS = chars


        for expr in _builtin_exprs:
            if expr.copyDefaultWhiteChars:
                expr.whiteChars = set(chars)

    @staticmethod
    def inline_literals_using(cls: type) -> None:
        ParserElement._literalStringClass = cls

    class DebugActions(NamedTuple):
        debug_try: OptionalType[DebugStartAction]
        debug_match: OptionalType[DebugSuccessAction]
        debug_fail: OptionalType[DebugExceptionAction]

    def __init__(self, savelist: bool = False):
        self.parseAction: List[ParseAction] = list()
        self.failAction: OptionalType[ParseFailAction] = None
        self.customName = None
        self._defaultName = None
        self.resultsName = None
        self.saveAsList = savelist
        self.skipWhitespace = True
        self.whiteChars = set(ParserElement.DEFAULT_WHITE_CHARS)
        self.copyDefaultWhiteChars = True

        self.mayReturnEmpty = False
        self.keepTabs = False
        self.ignoreExprs: List["ParserElement"] = list()
        self.debug = False
        self.streamlined = False

        self.mayIndexError = True
        self.errmsg = ""

        self.modalResults = True

        self.debugActions = self.DebugActions(None, None, None)
        self.re = None

        self.callPreparse = True
        self.callDuringTry = False
        self.suppress_warnings_: List[Diagnostics] = []

    def suppress_warning(self, warning_type: Diagnostics) -> "ParserElement":
        self.suppress_warnings_.append(warning_type)
        return self

    def copy(self) -> "ParserElement":
        cpy = copy.copy(self)
        cpy.parseAction = self.parseAction[:]
        cpy.ignoreExprs = self.ignoreExprs[:]
        if self.copyDefaultWhiteChars:
            cpy.whiteChars = set(ParserElement.DEFAULT_WHITE_CHARS)
        return cpy

    def set_results_name(
        self, name: str, list_all_matches: bool = False, *, listAllMatches: bool = False
    ) -> "ParserElement":
        listAllMatches = listAllMatches or list_all_matches
        return self._setResultsName(name, listAllMatches)

    def _setResultsName(self, name, listAllMatches=False):
        if name is None:
            return self
        newself = self.copy()
        if name.endswith("*"):
            name = name[:-1]
            listAllMatches = True
        newself.resultsName = name
        newself.modalResults = not listAllMatches
        return newself

    def set_break(self, break_flag: bool = True) -> "ParserElement":
        if break_flag:
            _parseMethod = self._parse

            def breaker(instring, loc, doActions=True, callPreParse=True):
                import pdb


                pdb.set_trace()
                return _parseMethod(instring, loc, doActions, callPreParse)

            breaker._originalParseMethod = _parseMethod
            self._parse = breaker
        else:
            if hasattr(self._parse, "_originalParseMethod"):
                self._parse = self._parse._originalParseMethod
        return self

    def set_parse_action(self, *fns: ParseAction, **kwargs) -> "ParserElement":
        if list(fns) == [None]:
            self.parseAction = []
        else:
            if not all(callable(fn) for fn in fns):
                raise TypeError("parse actions must be callable")
            self.parseAction = [_trim_arity(fn) for fn in fns]
            self.callDuringTry = kwargs.get(
                "call_during_try", kwargs.get("callDuringTry", False)
            )
        return self

    def add_parse_action(self, *fns: ParseAction, **kwargs) -> "ParserElement":
        self.parseAction += [_trim_arity(fn) for fn in fns]
        self.callDuringTry = self.callDuringTry or kwargs.get(
            "call_during_try", kwargs.get("callDuringTry", False)
        )
        return self

    def add_condition(self, *fns: ParseCondition, **kwargs) -> "ParserElement":
        for fn in fns:
            self.parseAction.append(
                condition_as_parse_action(
                    fn, message=kwargs.get("message"), fatal=kwargs.get("fatal", False)
                )
            )

        self.callDuringTry = self.callDuringTry or kwargs.get(
            "call_during_try", kwargs.get("callDuringTry", False)
        )
        return self

    def set_fail_action(self, fn: ParseFailAction) -> "ParserElement":
        self.failAction = fn
        return self

    def _skipIgnorables(self, instring, loc):
        exprsFound = True
        while exprsFound:
            exprsFound = False
            for e in self.ignoreExprs:
                try:
                    while 1:
                        loc, dummy = e._parse(instring, loc)
                        exprsFound = True
                except ParseException:
                    pass
        return loc

    def preParse(self, instring, loc):
        if self.ignoreExprs:
            loc = self._skipIgnorables(instring, loc)

        if self.skipWhitespace:
            instrlen = len(instring)
            white_chars = self.whiteChars
            while loc < instrlen and instring[loc] in white_chars:
                loc += 1

        return loc

    def parseImpl(self, instring, loc, doActions=True):
        return loc, []

    def postParse(self, instring, loc, tokenlist):
        return tokenlist


    def _parseNoCache(
        self, instring, loc, doActions=True, callPreParse=True
    ) -> Tuple[int, ParseResults]:
        TRY, MATCH, FAIL = 0, 1, 2
        debugging = self.debug
        len_instring = len(instring)

        if debugging or self.failAction:

            try:
                if callPreParse and self.callPreparse:
                    pre_loc = self.preParse(instring, loc)
                else:
                    pre_loc = loc
                tokens_start = pre_loc
                if self.debugActions.debug_try:
                    self.debugActions.debug_try(instring, tokens_start, self, False)
                if self.mayIndexError or pre_loc >= len_instring:
                    try:
                        loc, tokens = self.parseImpl(instring, pre_loc, doActions)
                    except IndexError:
                        raise ParseException(instring, len_instring, self.errmsg, self)
                else:
                    loc, tokens = self.parseImpl(instring, pre_loc, doActions)
            except Exception as err:

                if self.debugActions.debug_fail:
                    self.debugActions.debug_fail(
                        instring, tokens_start, self, err, False
                    )
                if self.failAction:
                    self.failAction(instring, tokens_start, self, err)
                raise
        else:
            if callPreParse and self.callPreparse:
                pre_loc = self.preParse(instring, loc)
            else:
                pre_loc = loc
            tokens_start = pre_loc
            if self.mayIndexError or pre_loc >= len_instring:
                try:
                    loc, tokens = self.parseImpl(instring, pre_loc, doActions)
                except IndexError:
                    raise ParseException(instring, len_instring, self.errmsg, self)
            else:
                loc, tokens = self.parseImpl(instring, pre_loc, doActions)

        tokens = self.postParse(instring, loc, tokens)

        ret_tokens = ParseResults(
            tokens, self.resultsName, asList=self.saveAsList, modal=self.modalResults
        )
        if self.parseAction and (doActions or self.callDuringTry):
            if debugging:
                try:
                    for fn in self.parseAction:
                        try:
                            tokens = fn(instring, tokens_start, ret_tokens)
                        except IndexError as parse_action_exc:
                            exc = ParseException("exception raised in parse action")
                            raise exc from parse_action_exc

                        if tokens is not None and tokens is not ret_tokens:
                            ret_tokens = ParseResults(
                                tokens,
                                self.resultsName,
                                asList=self.saveAsList
                                and isinstance(tokens, (ParseResults, list)),
                                modal=self.modalResults,
                            )
                except Exception as err:

                    if self.debugActions.debug_fail:
                        self.debugActions.debug_fail(
                            instring, tokens_start, self, err, False
                        )
                    raise
            else:
                for fn in self.parseAction:
                    try:
                        tokens = fn(instring, tokens_start, ret_tokens)
                    except IndexError as parse_action_exc:
                        exc = ParseException("exception raised in parse action")
                        raise exc from parse_action_exc

                    if tokens is not None and tokens is not ret_tokens:
                        ret_tokens = ParseResults(
                            tokens,
                            self.resultsName,
                            asList=self.saveAsList
                            and isinstance(tokens, (ParseResults, list)),
                            modal=self.modalResults,
                        )
        if debugging:

            if self.debugActions.debug_match:
                self.debugActions.debug_match(
                    instring, tokens_start, loc, self, ret_tokens, False
                )

        return loc, ret_tokens

    def try_parse(self, instring: str, loc: int, raise_fatal: bool = False) -> int:
        try:
            return self._parse(instring, loc, doActions=False)[0]
        except ParseFatalException:
            if raise_fatal:
                raise
            raise ParseException(instring, loc, self.errmsg, self)

    def can_parse_next(self, instring: str, loc: int) -> bool:
        try:
            self.try_parse(instring, loc)
        except (ParseException, IndexError):
            return False
        else:
            return True


    recursion_lock = RLock()
    recursion_memos: DictType[
        Tuple[int, "Forward", bool], Tuple[int, Union[ParseResults, Exception]]
    ] = {}


    packrat_cache = (
        {}
    )
    packrat_cache_lock = RLock()
    packrat_cache_stats = [0, 0]


    def _parseCache(
        self, instring, loc, doActions=True, callPreParse=True
    ) -> Tuple[int, ParseResults]:
        HIT, MISS = 0, 1
        TRY, MATCH, FAIL = 0, 1, 2
        lookup = (self, instring, loc, callPreParse, doActions)
        with ParserElement.packrat_cache_lock:
            cache = ParserElement.packrat_cache
            value = cache.get(lookup)
            if value is cache.not_in_cache:
                ParserElement.packrat_cache_stats[MISS] += 1
                try:
                    value = self._parseNoCache(instring, loc, doActions, callPreParse)
                except ParseBaseException as pe:

                    cache.set(lookup, pe.__class__(*pe.args))
                    raise
                else:
                    cache.set(lookup, (value[0], value[1].copy(), loc))
                    return value
            else:
                ParserElement.packrat_cache_stats[HIT] += 1
                if self.debug and self.debugActions.debug_try:
                    try:
                        self.debugActions.debug_try(instring, loc, self, cache_hit=True)
                    except TypeError:
                        pass
                if isinstance(value, Exception):
                    if self.debug and self.debugActions.debug_fail:
                        try:
                            self.debugActions.debug_fail(
                                instring, loc, self, value, cache_hit=True
                            )
                        except TypeError:
                            pass
                    raise value

                loc_, result, endloc = value[0], value[1].copy(), value[2]
                if self.debug and self.debugActions.debug_match:
                    try:
                        self.debugActions.debug_match(
                            instring, loc_, endloc, self, result, cache_hit=True
                        )
                    except TypeError:
                        pass

                return loc_, result

    _parse = _parseNoCache

    @staticmethod
    def reset_cache() -> None:
        ParserElement.packrat_cache.clear()
        ParserElement.packrat_cache_stats[:] = [0] * len(
            ParserElement.packrat_cache_stats
        )
        ParserElement.recursion_memos.clear()

    _packratEnabled = False
    _left_recursion_enabled = False

    @staticmethod
    def disable_memoization() -> None:
        ParserElement.reset_cache()
        ParserElement._left_recursion_enabled = False
        ParserElement._packratEnabled = False
        ParserElement._parse = ParserElement._parseNoCache

    @staticmethod
    def enable_left_recursion(
        cache_size_limit: OptionalType[int] = None, *, force=False
    ) -> None:
        if force:
            ParserElement.disable_memoization()
        elif ParserElement._packratEnabled:
            raise RuntimeError("Packrat and Bounded Recursion are not compatible")
        if cache_size_limit is None:
            ParserElement.recursion_memos = _UnboundedMemo()
        elif cache_size_limit > 0:
            ParserElement.recursion_memos = _LRUMemo(capacity=cache_size_limit)
        else:
            raise NotImplementedError("Memo size of %s" % cache_size_limit)
        ParserElement._left_recursion_enabled = True

    @staticmethod
    def enable_packrat(cache_size_limit: int = 128, *, force: bool = False) -> None:
        if force:
            ParserElement.disable_memoization()
        elif ParserElement._left_recursion_enabled:
            raise RuntimeError("Packrat and Bounded Recursion are not compatible")
        if not ParserElement._packratEnabled:
            ParserElement._packratEnabled = True
            if cache_size_limit is None:
                ParserElement.packrat_cache = _UnboundedCache()
            else:
                ParserElement.packrat_cache = _FifoCache(cache_size_limit)
            ParserElement._parse = ParserElement._parseCache

    def parse_string(
        self, instring: str, parse_all: bool = False, *, parseAll: bool = False
    ) -> ParseResults:
        parseAll = parse_all or parseAll

        ParserElement.reset_cache()
        if not self.streamlined:
            self.streamline()
        for e in self.ignoreExprs:
            e.streamline()
        if not self.keepTabs:
            instring = instring.expandtabs()
        try:
            loc, tokens = self._parse(instring, 0)
            if parseAll:
                loc = self.preParse(instring, loc)
                se = Empty() + StringEnd()
                se._parse(instring, loc)
        except ParseBaseException as exc:
            if ParserElement.verbose_stacktrace:
                raise
            else:

                raise exc.with_traceback(None)
        else:
            return tokens

    def scan_string(
        self,
        instring: str,
        max_matches: int = _MAX_INT,
        overlap: bool = False,
        *,
        debug: bool = False,
        maxMatches: int = _MAX_INT,
    ) -> Generator[Tuple[ParseResults, int, int], None, None]:
        maxMatches = min(maxMatches, max_matches)
        if not self.streamlined:
            self.streamline()
        for e in self.ignoreExprs:
            e.streamline()

        if not self.keepTabs:
            instring = str(instring).expandtabs()
        instrlen = len(instring)
        loc = 0
        preparseFn = self.preParse
        parseFn = self._parse
        ParserElement.resetCache()
        matches = 0
        try:
            while loc <= instrlen and matches < maxMatches:
                try:
                    preloc = preparseFn(instring, loc)
                    nextLoc, tokens = parseFn(instring, preloc, callPreParse=False)
                except ParseException:
                    loc = preloc + 1
                else:
                    if nextLoc > loc:
                        matches += 1
                        if debug:
                            print(
                                {
                                    "tokens": tokens.asList(),
                                    "start": preloc,
                                    "end": nextLoc,
                                }
                            )
                        yield tokens, preloc, nextLoc
                        if overlap:
                            nextloc = preparseFn(instring, loc)
                            if nextloc > loc:
                                loc = nextLoc
                            else:
                                loc += 1
                        else:
                            loc = nextLoc
                    else:
                        loc = preloc + 1
        except ParseBaseException as exc:
            if ParserElement.verbose_stacktrace:
                raise
            else:

                raise exc.with_traceback(None)

    def transform_string(self, instring: str, *, debug: bool = False) -> str:
        out: List[str] = []
        lastE = 0


        self.keepTabs = True
        try:
            for t, s, e in self.scan_string(instring, debug=debug):
                out.append(instring[lastE:s])
                if t:
                    if isinstance(t, ParseResults):
                        out += t.as_list()
                    elif isinstance(t, Iterable) and not isinstance(t, str_type):
                        out.extend(t)
                    else:
                        out.append(t)
                lastE = e
            out.append(instring[lastE:])
            out = [o for o in out if o]
            return "".join([str(s) for s in _flatten(out)])
        except ParseBaseException as exc:
            if ParserElement.verbose_stacktrace:
                raise
            else:

                raise exc.with_traceback(None)

    def search_string(
        self,
        instring: str,
        max_matches: int = _MAX_INT,
        *,
        debug: bool = False,
        maxMatches: int = _MAX_INT,
    ) -> ParseResults:
        maxMatches = min(maxMatches, max_matches)
        try:
            return ParseResults(
                [t for t, s, e in self.scan_string(instring, maxMatches, debug=debug)]
            )
        except ParseBaseException as exc:
            if ParserElement.verbose_stacktrace:
                raise
            else:

                raise exc.with_traceback(None)

    def split(
        self,
        instring: str,
        maxsplit: int = _MAX_INT,
        include_separators: bool = False,
        *,
        includeSeparators=False,
    ) -> Generator[str, None, None]:
        includeSeparators = includeSeparators or include_separators
        last = 0
        for t, s, e in self.scan_string(instring, max_matches=maxsplit):
            yield instring[last:s]
            if includeSeparators:
                yield t[0]
            last = e
        yield instring[last:]

    def __add__(self, other):
        if other is Ellipsis:
            return _PendingSkip(self)

        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return And([self, other])

    def __radd__(self, other):
        if other is Ellipsis:
            return SkipTo(self)("_skipped*") + self

        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return other + self

    def __sub__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return self + And._ErrorStop() + other

    def __rsub__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return other - self

    def __mul__(self, other):
        if other is Ellipsis:
            other = (0, None)
        elif isinstance(other, tuple) and other[:1] == (Ellipsis,):
            other = ((0,) + other[1:] + (None,))[:2]

        if isinstance(other, int):
            minElements, optElements = other, 0
        elif isinstance(other, tuple):
            other = tuple(o if o is not Ellipsis else None for o in other)
            other = (other + (None, None))[:2]
            if other[0] is None:
                other = (0, other[1])
            if isinstance(other[0], int) and other[1] is None:
                if other[0] == 0:
                    return ZeroOrMore(self)
                if other[0] == 1:
                    return OneOrMore(self)
                else:
                    return self * other[0] + ZeroOrMore(self)
            elif isinstance(other[0], int) and isinstance(other[1], int):
                minElements, optElements = other
                optElements -= minElements
            else:
                raise TypeError(
                    "cannot multiply ParserElement and ({}) objects".format(
                        ",".join(type(item).__name__ for item in other)
                    )
                )
        else:
            raise TypeError(
                "cannot multiply ParserElement and {} objects".format(
                    type(other).__name__
                )
            )

        if minElements < 0:
            raise ValueError("cannot multiply ParserElement by negative value")
        if optElements < 0:
            raise ValueError(
                "second tuple value must be greater or equal to first tuple value"
            )
        if minElements == optElements == 0:
            return And([])

        if optElements:

            def makeOptionalList(n):
                if n > 1:
                    return Opt(self + makeOptionalList(n - 1))
                else:
                    return Opt(self)

            if minElements:
                if minElements == 1:
                    ret = self + makeOptionalList(optElements)
                else:
                    ret = And([self] * minElements) + makeOptionalList(optElements)
            else:
                ret = makeOptionalList(optElements)
        else:
            if minElements == 1:
                ret = self
            else:
                ret = And([self] * minElements)
        return ret

    def __rmul__(self, other):
        return self.__mul__(other)

    def __or__(self, other):
        if other is Ellipsis:
            return _PendingSkip(self, must_skip=True)

        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return MatchFirst([self, other])

    def __ror__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return other | self

    def __xor__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return Or([self, other])

    def __rxor__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return other ^ self

    def __and__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return Each([self, other])

    def __rand__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            raise TypeError(
                "Cannot combine element of type {} with ParserElement".format(
                    type(other).__name__
                )
            )
        return other & self

    def __invert__(self):
        return NotAny(self)


    __iter__ = None

    def __getitem__(self, key):


        try:
            if isinstance(key, str_type):
                key = (key,)
            iter(key)
        except TypeError:
            key = (key, key)

        if len(key) > 2:
            raise TypeError(
                "only 1 or 2 index arguments supported ({}{})".format(
                    key[:5], "... [{}]".format(len(key)) if len(key) > 5 else ""
                )
            )


        ret = self * tuple(key[:2])
        return ret

    def __call__(self, name: str = None):
        if name is not None:
            return self._setResultsName(name)
        else:
            return self.copy()

    def suppress(self) -> "ParserElement":
        return Suppress(self)

    def ignore_whitespace(self, recursive: bool = True) -> "ParserElement":
        self.skipWhitespace = True
        return self

    def leave_whitespace(self, recursive: bool = True) -> "ParserElement":
        self.skipWhitespace = False
        return self

    def set_whitespace_chars(
        self, chars: Union[Set[str], str], copy_defaults: bool = False
    ) -> "ParserElement":
        self.skipWhitespace = True
        self.whiteChars = set(chars)
        self.copyDefaultWhiteChars = copy_defaults
        return self

    def parse_with_tabs(self) -> "ParserElement":
        self.keepTabs = True
        return self

    def ignore(self, other: "ParserElement") -> "ParserElement":
        import typing

        if isinstance(other, str_type):
            other = Suppress(other)

        if isinstance(other, Suppress):
            if other not in self.ignoreExprs:
                self.ignoreExprs.append(other)
        else:
            self.ignoreExprs.append(Suppress(other.copy()))
        return self

    def set_debug_actions(
        self,
        start_action: DebugStartAction,
        success_action: DebugSuccessAction,
        exception_action: DebugExceptionAction,
    ) -> "ParserElement":
        self.debugActions = self.DebugActions(
            start_action or _default_start_debug_action,
            success_action or _default_success_debug_action,
            exception_action or _default_exception_debug_action,
        )
        self.debug = True
        return self

    def set_debug(self, flag: bool = True) -> "ParserElement":
        if flag:
            self.set_debug_actions(
                _default_start_debug_action,
                _default_success_debug_action,
                _default_exception_debug_action,
            )
        else:
            self.debug = False
        return self

    @property
    def default_name(self) -> str:
        if self._defaultName is None:
            self._defaultName = self._generateDefaultName()
        return self._defaultName

    @abstractmethod
    def _generateDefaultName(self):

    def set_name(self, name: str) -> "ParserElement":
        self.customName = name
        self.errmsg = "Expected " + self.name
        if __diag__.enable_debug_on_named_expressions:
            self.set_debug()
        return self

    @property
    def name(self) -> str:

        return self.customName if self.customName is not None else self.default_name

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return str(self)

    def streamline(self) -> "ParserElement":
        self.streamlined = True
        self._defaultName = None
        return self

    def recurse(self) -> Sequence["ParserElement"]:
        return []

    def _checkRecursion(self, parseElementList):
        subRecCheckList = parseElementList[:] + [self]
        for e in self.recurse():
            e._checkRecursion(subRecCheckList)

    def validate(self, validateTrace=None) -> None:
        self._checkRecursion([])

    def parse_file(
        self,
        file_or_filename: Union[str, Path, TextIO],
        encoding: str = "utf-8",
        parse_all: bool = False,
        *,
        parseAll: bool = False,
    ) -> ParseResults:
        parseAll = parseAll or parse_all
        try:
            file_contents = file_or_filename.read()
        except AttributeError:
            with open(file_or_filename, "r", encoding=encoding) as f:
                file_contents = f.read()
        try:
            return self.parse_string(file_contents, parseAll)
        except ParseBaseException as exc:
            if ParserElement.verbose_stacktrace:
                raise
            else:

                raise exc.with_traceback(None)

    def __eq__(self, other):
        if self is other:
            return True
        elif isinstance(other, str_type):
            return self.matches(other, parse_all=True)
        elif isinstance(other, ParserElement):
            return vars(self) == vars(other)
        return False

    def __hash__(self):
        return id(self)

    def matches(
        self, test_string: str, parse_all: bool = True, *, parseAll: bool = True
    ) -> bool:
        parseAll = parseAll and parse_all
        try:
            self.parse_string(str(test_string), parse_all=parseAll)
            return True
        except ParseBaseException:
            return False

    def run_tests(
        self,
        tests: Union[str, List[str]],
        parse_all: bool = True,
        comment: OptionalType[Union["ParserElement", str]] = "#",
        full_dump: bool = True,
        print_results: bool = True,
        failure_tests: bool = False,
        post_parse: Callable[[str, ParseResults], str] = None,
        file: OptionalType[TextIO] = None,
        with_line_numbers: bool = False,
        *,
        parseAll: bool = True,
        fullDump: bool = True,
        printResults: bool = True,
        failureTests: bool = False,
        postParse: Callable[[str, ParseResults], str] = None,
    ) -> Tuple[bool, List[Tuple[str, Union[ParseResults, Exception]]]]:
        from .testing import pyparsing_test

        parseAll = parseAll and parse_all
        fullDump = fullDump and full_dump
        printResults = printResults and print_results
        failureTests = failureTests or failure_tests
        postParse = postParse or post_parse
        if isinstance(tests, str_type):
            line_strip = type(tests).strip
            tests = [line_strip(test_line) for test_line in tests.rstrip().splitlines()]
        if isinstance(comment, str_type):
            comment = Literal(comment)
        if file is None:
            file = sys.stdout
        print_ = file.write

        result: Union[ParseResults, Exception]
        allResults = []
        comments = []
        success = True
        NL = Literal(r"\n").add_parse_action(replace_with("\n")).ignore(quoted_string)
        BOM = "\ufeff"
        for t in tests:
            if comment is not None and comment.matches(t, False) or comments and not t:
                comments.append(
                    pyparsing_test.with_line_numbers(t) if with_line_numbers else t
                )
                continue
            if not t:
                continue
            out = [
                "\n" + "\n".join(comments) if comments else "",
                pyparsing_test.with_line_numbers(t) if with_line_numbers else t,
            ]
            comments = []
            try:

                t = NL.transform_string(t.lstrip(BOM))
                result = self.parse_string(t, parse_all=parseAll)
            except ParseBaseException as pe:
                fatal = "(FATAL)" if isinstance(pe, ParseFatalException) else ""
                out.append(pe.explain())
                out.append("FAIL: " + str(pe))
                if ParserElement.verbose_stacktrace:
                    out.extend(traceback.format_tb(pe.__traceback__))
                success = success and failureTests
                result = pe
            except Exception as exc:
                out.append("FAIL-EXCEPTION: {}: {}".format(type(exc).__name__, exc))
                if ParserElement.verbose_stacktrace:
                    out.extend(traceback.format_tb(exc.__traceback__))
                success = success and failureTests
                result = exc
            else:
                success = success and not failureTests
                if postParse is not None:
                    try:
                        pp_value = postParse(t, result)
                        if pp_value is not None:
                            if isinstance(pp_value, ParseResults):
                                out.append(pp_value.dump())
                            else:
                                out.append(str(pp_value))
                        else:
                            out.append(result.dump())
                    except Exception as e:
                        out.append(result.dump(full=fullDump))
                        out.append(
                            "{} failed: {}: {}".format(
                                postParse.__name__, type(e).__name__, e
                            )
                        )
                else:
                    out.append(result.dump(full=fullDump))
            out.append("")

            if printResults:
                print_("\n".join(out))

            allResults.append((t, result))

        return success, allResults

    def create_diagram(
        self,
        output_html: Union[TextIO, Path, str],
        vertical: int = 3,
        show_results_names: bool = False,
        **kwargs,
    ) -> None:

        try:
            from .diagram import to_railroad, railroad_to_html
        except ImportError as ie:
            raise Exception(
                "must ``pip install pyparsing[diagrams]`` to generate parser railroad diagrams"
            ) from ie

        self.streamline()

        railroad = to_railroad(
            self,
            vertical=vertical,
            show_results_names=show_results_names,
            diagram_kwargs=kwargs,
        )
        if isinstance(output_html, (str, Path)):
            with open(output_html, "w", encoding="utf-8") as diag_file:
                diag_file.write(railroad_to_html(railroad))
        else:

            output_html.write(railroad_to_html(railroad))

    setDefaultWhitespaceChars = set_default_whitespace_chars
    inlineLiteralsUsing = inline_literals_using
    setResultsName = set_results_name
    setBreak = set_break
    setParseAction = set_parse_action
    addParseAction = add_parse_action
    addCondition = add_condition
    setFailAction = set_fail_action
    tryParse = try_parse
    canParseNext = can_parse_next
    resetCache = reset_cache
    enableLeftRecursion = enable_left_recursion
    enablePackrat = enable_packrat
    parseString = parse_string
    scanString = scan_string
    searchString = search_string
    transformString = transform_string
    setWhitespaceChars = set_whitespace_chars
    parseWithTabs = parse_with_tabs
    setDebugActions = set_debug_actions
    setDebug = set_debug
    defaultName = default_name
    setName = set_name
    parseFile = parse_file
    runTests = run_tests
    ignoreWhitespace = ignore_whitespace
    leaveWhitespace = leave_whitespace


class _PendingSkip(ParserElement):


    def __init__(self, expr: ParserElement, must_skip: bool = False):
        super().__init__()
        self.anchor = expr
        self.must_skip = must_skip

    def _generateDefaultName(self):
        return str(self.anchor + Empty()).replace("Empty", "...")

    def __add__(self, other):
        skipper = SkipTo(other).set_name("...")("_skipped*")
        if self.must_skip:

            def must_skip(t):
                if not t._skipped or t._skipped.as_list() == [""]:
                    del t[0]
                    t.pop("_skipped", None)

            def show_skip(t):
                if t._skipped.as_list()[-1:] == [""]:
                    t.pop("_skipped")
                    t["_skipped"] = "missing <" + repr(self.anchor) + ">"

            return (
                self.anchor + skipper().add_parse_action(must_skip)
                | skipper().add_parse_action(show_skip)
            ) + other

        return self.anchor + skipper + other

    def __repr__(self):
        return self.defaultName

    def parseImpl(self, *args):
        raise Exception(
            "use of `...` expression without following SkipTo target expression"
        )


class Token(ParserElement):

    def __init__(self):
        super().__init__(savelist=False)

    def _generateDefaultName(self):
        return type(self).__name__


class Empty(Token):

    def __init__(self):
        super().__init__()
        self.mayReturnEmpty = True
        self.mayIndexError = False


class NoMatch(Token):

    def __init__(self):
        super().__init__()
        self.mayReturnEmpty = True
        self.mayIndexError = False
        self.errmsg = "Unmatchable token"

    def parseImpl(self, instring, loc, doActions=True):
        raise ParseException(instring, loc, self.errmsg, self)


class Literal(Token):

    def __init__(self, match_string: str = "", *, matchString: str = ""):
        super().__init__()
        match_string = matchString or match_string
        self.match = match_string
        self.matchLen = len(match_string)
        try:
            self.firstMatchChar = match_string[0]
        except IndexError:
            raise ValueError("null string passed to Literal; use Empty() instead")
        self.errmsg = "Expected " + self.name
        self.mayReturnEmpty = False
        self.mayIndexError = False


        if self.matchLen == 1 and type(self) is Literal:
            self.__class__ = _SingleCharLiteral

    def _generateDefaultName(self):
        return repr(self.match)

    def parseImpl(self, instring, loc, doActions=True):
        if instring[loc] == self.firstMatchChar and instring.startswith(
            self.match, loc
        ):
            return loc + self.matchLen, self.match
        raise ParseException(instring, loc, self.errmsg, self)


class _SingleCharLiteral(Literal):
    def parseImpl(self, instring, loc, doActions=True):
        if instring[loc] == self.firstMatchChar:
            return loc + 1, self.match
        raise ParseException(instring, loc, self.errmsg, self)


ParserElement._literalStringClass = Literal


class Keyword(Token):

    DEFAULT_KEYWORD_CHARS = alphanums + "_$"

    def __init__(
        self,
        match_string: str = "",
        ident_chars: OptionalType[str] = None,
        caseless: bool = False,
        *,
        matchString: str = "",
        identChars: OptionalType[str] = None,
    ):
        super().__init__()
        identChars = identChars or ident_chars
        if identChars is None:
            identChars = Keyword.DEFAULT_KEYWORD_CHARS
        match_string = matchString or match_string
        self.match = match_string
        self.matchLen = len(match_string)
        try:
            self.firstMatchChar = match_string[0]
        except IndexError:
            raise ValueError("null string passed to Keyword; use Empty() instead")
        self.errmsg = "Expected {} {}".format(type(self).__name__, self.name)
        self.mayReturnEmpty = False
        self.mayIndexError = False
        self.caseless = caseless
        if caseless:
            self.caselessmatch = match_string.upper()
            identChars = identChars.upper()
        self.identChars = set(identChars)

    def _generateDefaultName(self):
        return repr(self.match)

    def parseImpl(self, instring, loc, doActions=True):
        errmsg = self.errmsg
        errloc = loc
        if self.caseless:
            if instring[loc : loc + self.matchLen].upper() == self.caselessmatch:
                if loc == 0 or instring[loc - 1].upper() not in self.identChars:
                    if (
                        loc >= len(instring) - self.matchLen
                        or instring[loc + self.matchLen].upper() not in self.identChars
                    ):
                        return loc + self.matchLen, self.match
                    else:

                        errmsg += ", was immediately followed by keyword character"
                        errloc = loc + self.matchLen
                else:

                    errmsg += ", keyword was immediately preceded by keyword character"
                    errloc = loc - 1


        else:
            if (
                instring[loc] == self.firstMatchChar
                and self.matchLen == 1
                or instring.startswith(self.match, loc)
            ):
                if loc == 0 or instring[loc - 1] not in self.identChars:
                    if (
                        loc >= len(instring) - self.matchLen
                        or instring[loc + self.matchLen] not in self.identChars
                    ):
                        return loc + self.matchLen, self.match
                    else:

                        errmsg += (
                            ", keyword was immediately followed by keyword character"
                        )
                        errloc = loc + self.matchLen
                else:

                    errmsg += ", keyword was immediately preceded by keyword character"
                    errloc = loc - 1


        raise ParseException(instring, errloc, errmsg, self)

    @staticmethod
    def set_default_keyword_chars(chars) -> None:
        Keyword.DEFAULT_KEYWORD_CHARS = chars

    setDefaultKeywordChars = set_default_keyword_chars


class CaselessLiteral(Literal):

    def __init__(self, match_string: str = "", *, matchString: str = ""):
        match_string = matchString or match_string
        super().__init__(match_string.upper())

        self.returnString = match_string
        self.errmsg = "Expected " + self.name

    def parseImpl(self, instring, loc, doActions=True):
        if instring[loc : loc + self.matchLen].upper() == self.match:
            return loc + self.matchLen, self.returnString
        raise ParseException(instring, loc, self.errmsg, self)


class CaselessKeyword(Keyword):

    def __init__(
        self,
        match_string: str = "",
        ident_chars: OptionalType[str] = None,
        *,
        matchString: str = "",
        identChars: OptionalType[str] = None,
    ):
        identChars = identChars or ident_chars
        match_string = matchString or match_string
        super().__init__(match_string, identChars, caseless=True)


class CloseMatch(Token):

    def __init__(
        self,
        match_string: str,
        max_mismatches: int = None,
        *,
        maxMismatches: int = 1,
        caseless=False,
    ):
        maxMismatches = max_mismatches if max_mismatches is not None else maxMismatches
        super().__init__()
        self.match_string = match_string
        self.maxMismatches = maxMismatches
        self.errmsg = "Expected {!r} (with up to {} mismatches)".format(
            self.match_string, self.maxMismatches
        )
        self.caseless = caseless
        self.mayIndexError = False
        self.mayReturnEmpty = False

    def _generateDefaultName(self):
        return "{}:{!r}".format(type(self).__name__, self.match_string)

    def parseImpl(self, instring, loc, doActions=True):
        start = loc
        instrlen = len(instring)
        maxloc = start + len(self.match_string)

        if maxloc <= instrlen:
            match_string = self.match_string
            match_stringloc = 0
            mismatches = []
            maxMismatches = self.maxMismatches

            for match_stringloc, s_m in enumerate(
                zip(instring[loc:maxloc], match_string)
            ):
                src, mat = s_m
                if self.caseless:
                    src, mat = src.lower(), mat.lower()

                if src != mat:
                    mismatches.append(match_stringloc)
                    if len(mismatches) > maxMismatches:
                        break
            else:
                loc = start + match_stringloc + 1
                results = ParseResults([instring[start:loc]])
                results["original"] = match_string
                results["mismatches"] = mismatches
                return loc, results

        raise ParseException(instring, loc, self.errmsg, self)


class Word(Token):

    def __init__(
        self,
        init_chars: str = "",
        body_chars: OptionalType[str] = None,
        min: int = 1,
        max: int = 0,
        exact: int = 0,
        as_keyword: bool = False,
        exclude_chars: OptionalType[str] = None,
        *,
        initChars: OptionalType[str] = None,
        bodyChars: OptionalType[str] = None,
        asKeyword: bool = False,
        excludeChars: OptionalType[str] = None,
    ):
        initChars = initChars or init_chars
        bodyChars = bodyChars or body_chars
        asKeyword = asKeyword or as_keyword
        excludeChars = excludeChars or exclude_chars
        super().__init__()
        if not initChars:
            raise ValueError(
                "invalid {}, initChars cannot be empty string".format(
                    type(self).__name__
                )
            )

        initChars = set(initChars)
        self.initChars = initChars
        if excludeChars:
            excludeChars = set(excludeChars)
            initChars -= excludeChars
            if bodyChars:
                bodyChars = set(bodyChars) - excludeChars
        self.initCharsOrig = "".join(sorted(initChars))

        if bodyChars:
            self.bodyCharsOrig = "".join(sorted(bodyChars))
            self.bodyChars = set(bodyChars)
        else:
            self.bodyCharsOrig = "".join(sorted(initChars))
            self.bodyChars = set(initChars)

        self.maxSpecified = max > 0

        if min < 1:
            raise ValueError(
                "cannot specify a minimum length < 1; use Opt(Word()) if zero-length word is permitted"
            )

        self.minLen = min

        if max > 0:
            self.maxLen = max
        else:
            self.maxLen = _MAX_INT

        if exact > 0:
            self.maxLen = exact
            self.minLen = exact

        self.errmsg = "Expected " + self.name
        self.mayIndexError = False
        self.asKeyword = asKeyword


        if " " not in self.initChars | self.bodyChars and (min == 1 and exact == 0):
            if self.bodyChars == self.initChars:
                if max == 0:
                    repeat = "+"
                elif max == 1:
                    repeat = ""
                else:
                    repeat = "{{{},{}}}".format(
                        self.minLen, "" if self.maxLen == _MAX_INT else self.maxLen
                    )
                self.reString = "[{}]{}".format(
                    _collapse_string_to_ranges(self.initChars),
                    repeat,
                )
            elif len(self.initChars) == 1:
                if max == 0:
                    repeat = "*"
                else:
                    repeat = "{{0,{}}}".format(max - 1)
                self.reString = "{}[{}]{}".format(
                    re.escape(self.initCharsOrig),
                    _collapse_string_to_ranges(self.bodyChars),
                    repeat,
                )
            else:
                if max == 0:
                    repeat = "*"
                elif max == 2:
                    repeat = ""
                else:
                    repeat = "{{0,{}}}".format(max - 1)
                self.reString = "[{}][{}]{}".format(
                    _collapse_string_to_ranges(self.initChars),
                    _collapse_string_to_ranges(self.bodyChars),
                    repeat,
                )
            if self.asKeyword:
                self.reString = r"\b" + self.reString + r"\b"

            try:
                self.re = re.compile(self.reString)
            except sre_constants.error:
                self.re = None
            else:
                self.re_match = self.re.match
                self.__class__ = _WordRegex

    def _generateDefaultName(self):
        def charsAsStr(s):
            max_repr_len = 16
            s = _collapse_string_to_ranges(s, re_escape=False)
            if len(s) > max_repr_len:
                return s[: max_repr_len - 3] + "..."
            else:
                return s

        if self.initChars != self.bodyChars:
            base = "W:({}, {})".format(
                charsAsStr(self.initChars), charsAsStr(self.bodyChars)
            )
        else:
            base = "W:({})".format(charsAsStr(self.initChars))


        if self.minLen > 1 or self.maxLen != _MAX_INT:
            if self.minLen == self.maxLen:
                if self.minLen == 1:
                    return base[2:]
                else:
                    return base + "{{{}}}".format(self.minLen)
            elif self.maxLen == _MAX_INT:
                return base + "{{{},...}}".format(self.minLen)
            else:
                return base + "{{{},{}}}".format(self.minLen, self.maxLen)
        return base

    def parseImpl(self, instring, loc, doActions=True):
        if instring[loc] not in self.initChars:
            raise ParseException(instring, loc, self.errmsg, self)

        start = loc
        loc += 1
        instrlen = len(instring)
        bodychars = self.bodyChars
        maxloc = start + self.maxLen
        maxloc = min(maxloc, instrlen)
        while loc < maxloc and instring[loc] in bodychars:
            loc += 1

        throwException = False
        if loc - start < self.minLen:
            throwException = True
        elif self.maxSpecified and loc < instrlen and instring[loc] in bodychars:
            throwException = True
        elif self.asKeyword:
            if (
                start > 0
                and instring[start - 1] in bodychars
                or loc < instrlen
                and instring[loc] in bodychars
            ):
                throwException = True

        if throwException:
            raise ParseException(instring, loc, self.errmsg, self)

        return loc, instring[start:loc]


class _WordRegex(Word):
    def parseImpl(self, instring, loc, doActions=True):
        result = self.re_match(instring, loc)
        if not result:
            raise ParseException(instring, loc, self.errmsg, self)

        loc = result.end()
        return loc, result.group()


class Char(_WordRegex):

    def __init__(
        self,
        charset: str,
        as_keyword: bool = False,
        exclude_chars: OptionalType[str] = None,
        *,
        asKeyword: bool = False,
        excludeChars: OptionalType[str] = None,
    ):
        asKeyword = asKeyword or as_keyword
        excludeChars = excludeChars or exclude_chars
        super().__init__(
            charset, exact=1, asKeyword=asKeyword, excludeChars=excludeChars
        )
        self.reString = "[{}]".format(_collapse_string_to_ranges(self.initChars))
        if asKeyword:
            self.reString = r"\b{}\b".format(self.reString)
        self.re = re.compile(self.reString)
        self.re_match = self.re.match


class Regex(Token):

    def __init__(
        self,
        pattern: Any,
        flags: Union[re.RegexFlag, int] = 0,
        as_group_list: bool = False,
        as_match: bool = False,
        *,
        asGroupList: bool = False,
        asMatch: bool = False,
    ):
        super().__init__()
        asGroupList = asGroupList or as_group_list
        asMatch = asMatch or as_match

        if isinstance(pattern, str_type):
            if not pattern:
                raise ValueError("null string passed to Regex; use Empty() instead")

            self.pattern = pattern
            self.flags = flags

            try:
                self.re = re.compile(self.pattern, self.flags)
                self.reString = self.pattern
            except sre_constants.error:
                raise ValueError(
                    "invalid pattern ({!r}) passed to Regex".format(pattern)
                )

        elif hasattr(pattern, "pattern") and hasattr(pattern, "match"):
            self.re = pattern
            self.pattern = self.reString = pattern.pattern
            self.flags = flags

        else:
            raise TypeError(
                "Regex may only be constructed with a string or a compiled RE object"
            )

        self.re_match = self.re.match

        self.errmsg = "Expected " + self.name
        self.mayIndexError = False
        self.mayReturnEmpty = self.re_match("") is not None
        self.asGroupList = asGroupList
        self.asMatch = asMatch
        if self.asGroupList:
            self.parseImpl = self.parseImplAsGroupList
        if self.asMatch:
            self.parseImpl = self.parseImplAsMatch

    def _generateDefaultName(self):
        return "Re:({})".format(repr(self.pattern).replace("\\\\", "\\"))

    def parseImpl(self, instring, loc, doActions=True):
        result = self.re_match(instring, loc)
        if not result:
            raise ParseException(instring, loc, self.errmsg, self)

        loc = result.end()
        ret = ParseResults(result.group())
        d = result.groupdict()
        if d:
            for k, v in d.items():
                ret[k] = v
        return loc, ret

    def parseImplAsGroupList(self, instring, loc, doActions=True):
        result = self.re_match(instring, loc)
        if not result:
            raise ParseException(instring, loc, self.errmsg, self)

        loc = result.end()
        ret = result.groups()
        return loc, ret

    def parseImplAsMatch(self, instring, loc, doActions=True):
        result = self.re_match(instring, loc)
        if not result:
            raise ParseException(instring, loc, self.errmsg, self)

        loc = result.end()
        ret = result
        return loc, ret

    def sub(self, repl: str) -> ParserElement:
        if self.asGroupList:
            raise TypeError("cannot use sub() with Regex(asGroupList=True)")

        if self.asMatch and callable(repl):
            raise TypeError("cannot use sub() with a callable with Regex(asMatch=True)")

        if self.asMatch:

            def pa(tokens):
                return tokens[0].expand(repl)

        else:

            def pa(tokens):
                return self.re.sub(repl, tokens[0])

        return self.add_parse_action(pa)


class QuotedString(Token):
    ws_map = ((r"\t", "\t"), (r"\n", "\n"), (r"\f", "\f"), (r"\r", "\r"))

    def __init__(
        self,
        quote_char: str = "",
        esc_char: OptionalType[str] = None,
        esc_quote: OptionalType[str] = None,
        multiline: bool = False,
        unquote_results: bool = True,
        end_quote_char: OptionalType[str] = None,
        convert_whitespace_escapes: bool = True,
        *,
        quoteChar: str = "",
        escChar: OptionalType[str] = None,
        escQuote: OptionalType[str] = None,
        unquoteResults: bool = True,
        endQuoteChar: OptionalType[str] = None,
        convertWhitespaceEscapes: bool = True,
    ):
        super().__init__()
        escChar = escChar or esc_char
        escQuote = escQuote or esc_quote
        unquoteResults = unquoteResults and unquote_results
        endQuoteChar = endQuoteChar or end_quote_char
        convertWhitespaceEscapes = (
            convertWhitespaceEscapes and convert_whitespace_escapes
        )
        quote_char = quoteChar or quote_char


        quote_char = quote_char.strip()
        if not quote_char:
            raise ValueError("quote_char cannot be the empty string")

        if endQuoteChar is None:
            endQuoteChar = quote_char
        else:
            endQuoteChar = endQuoteChar.strip()
            if not endQuoteChar:
                raise ValueError("endQuoteChar cannot be the empty string")

        self.quoteChar = quote_char
        self.quoteCharLen = len(quote_char)
        self.firstQuoteChar = quote_char[0]
        self.endQuoteChar = endQuoteChar
        self.endQuoteCharLen = len(endQuoteChar)
        self.escChar = escChar
        self.escQuote = escQuote
        self.unquoteResults = unquoteResults
        self.convertWhitespaceEscapes = convertWhitespaceEscapes

        sep = ""
        inner_pattern = ""

        if escQuote:
            inner_pattern += r"{}(?:{})".format(sep, re.escape(escQuote))
            sep = "|"

        if escChar:
            inner_pattern += r"{}(?:{}.)".format(sep, re.escape(escChar))
            sep = "|"
            self.escCharReplacePattern = re.escape(self.escChar) + "(.)"

        if len(self.endQuoteChar) > 1:
            inner_pattern += (
                "{}(?:".format(sep)
                + "|".join(
                    "(?:{}(?!{}))".format(
                        re.escape(self.endQuoteChar[:i]),
                        re.escape(self.endQuoteChar[i:]),
                    )
                    for i in range(len(self.endQuoteChar) - 1, 0, -1)
                )
                + ")"
            )
            sep = "|"

        if multiline:
            self.flags = re.MULTILINE | re.DOTALL
            inner_pattern += r"{}(?:[^{}{}])".format(
                sep,
                _escape_regex_range_chars(self.endQuoteChar[0]),
                (_escape_regex_range_chars(escChar) if escChar is not None else ""),
            )
        else:
            self.flags = 0
            inner_pattern += r"{}(?:[^{}\n\r{}])".format(
                sep,
                _escape_regex_range_chars(self.endQuoteChar[0]),
                (_escape_regex_range_chars(escChar) if escChar is not None else ""),
            )

        self.pattern = "".join(
            [
                re.escape(self.quoteChar),
                "(?:",
                inner_pattern,
                ")*",
                re.escape(self.endQuoteChar),
            ]
        )

        try:
            self.re = re.compile(self.pattern, self.flags)
            self.reString = self.pattern
            self.re_match = self.re.match
        except sre_constants.error:
            raise ValueError(
                "invalid pattern {!r} passed to Regex".format(self.pattern)
            )

        self.errmsg = "Expected " + self.name
        self.mayIndexError = False
        self.mayReturnEmpty = True

    def _generateDefaultName(self):
        if self.quoteChar == self.endQuoteChar and isinstance(self.quoteChar, str_type):
            return "string enclosed in {!r}".format(self.quoteChar)

        return "quoted string, starting with {} ending with {}".format(
            self.quoteChar, self.endQuoteChar
        )

    def parseImpl(self, instring, loc, doActions=True):
        result = (
            instring[loc] == self.firstQuoteChar
            and self.re_match(instring, loc)
            or None
        )
        if not result:
            raise ParseException(instring, loc, self.errmsg, self)

        loc = result.end()
        ret = result.group()

        if self.unquoteResults:


            ret = ret[self.quoteCharLen : -self.endQuoteCharLen]

            if isinstance(ret, str_type):

                if "\\" in ret and self.convertWhitespaceEscapes:
                    for wslit, wschar in self.ws_map:
                        ret = ret.replace(wslit, wschar)


                if self.escChar:
                    ret = re.sub(self.escCharReplacePattern, r"\g<1>", ret)


                if self.escQuote:
                    ret = ret.replace(self.escQuote, self.endQuoteChar)

        return loc, ret


class CharsNotIn(Token):

    def __init__(
        self,
        not_chars: str = "",
        min: int = 1,
        max: int = 0,
        exact: int = 0,
        *,
        notChars: str = "",
    ):
        super().__init__()
        self.skipWhitespace = False
        self.notChars = not_chars or notChars
        self.notCharsSet = set(self.notChars)

        if min < 1:
            raise ValueError(
                "cannot specify a minimum length < 1; use "
                "Opt(CharsNotIn()) if zero-length char group is permitted"
            )

        self.minLen = min

        if max > 0:
            self.maxLen = max
        else:
            self.maxLen = _MAX_INT

        if exact > 0:
            self.maxLen = exact
            self.minLen = exact

        self.errmsg = "Expected " + self.name
        self.mayReturnEmpty = self.minLen == 0
        self.mayIndexError = False

    def _generateDefaultName(self):
        not_chars_str = _collapse_string_to_ranges(self.notChars)
        if len(not_chars_str) > 16:
            return "!W:({}...)".format(self.notChars[: 16 - 3])
        else:
            return "!W:({})".format(self.notChars)

    def parseImpl(self, instring, loc, doActions=True):
        notchars = self.notCharsSet
        if instring[loc] in notchars:
            raise ParseException(instring, loc, self.errmsg, self)

        start = loc
        loc += 1
        maxlen = min(start + self.maxLen, len(instring))
        while loc < maxlen and instring[loc] not in notchars:
            loc += 1

        if loc - start < self.minLen:
            raise ParseException(instring, loc, self.errmsg, self)

        return loc, instring[start:loc]


class White(Token):

    whiteStrs = {
        " ": "<SP>",
        "\t": "<TAB>",
        "\n": "<LF>",
        "\r": "<CR>",
        "\f": "<FF>",
        "\u00A0": "<NBSP>",
        "\u1680": "<OGHAM_SPACE_MARK>",
        "\u180E": "<MONGOLIAN_VOWEL_SEPARATOR>",
        "\u2000": "<EN_QUAD>",
        "\u2001": "<EM_QUAD>",
        "\u2002": "<EN_SPACE>",
        "\u2003": "<EM_SPACE>",
        "\u2004": "<THREE-PER-EM_SPACE>",
        "\u2005": "<FOUR-PER-EM_SPACE>",
        "\u2006": "<SIX-PER-EM_SPACE>",
        "\u2007": "<FIGURE_SPACE>",
        "\u2008": "<PUNCTUATION_SPACE>",
        "\u2009": "<THIN_SPACE>",
        "\u200A": "<HAIR_SPACE>",
        "\u200B": "<ZERO_WIDTH_SPACE>",
        "\u202F": "<NNBSP>",
        "\u205F": "<MMSP>",
        "\u3000": "<IDEOGRAPHIC_SPACE>",
    }

    def __init__(self, ws: str = " \t\r\n", min: int = 1, max: int = 0, exact: int = 0):
        super().__init__()
        self.matchWhite = ws
        self.set_whitespace_chars(
            "".join(c for c in self.whiteStrs if c not in self.matchWhite),
            copy_defaults=True,
        )

        self.mayReturnEmpty = True
        self.errmsg = "Expected " + self.name

        self.minLen = min

        if max > 0:
            self.maxLen = max
        else:
            self.maxLen = _MAX_INT

        if exact > 0:
            self.maxLen = exact
            self.minLen = exact

    def _generateDefaultName(self):
        return "".join(White.whiteStrs[c] for c in self.matchWhite)

    def parseImpl(self, instring, loc, doActions=True):
        if instring[loc] not in self.matchWhite:
            raise ParseException(instring, loc, self.errmsg, self)
        start = loc
        loc += 1
        maxloc = start + self.maxLen
        maxloc = min(maxloc, len(instring))
        while loc < maxloc and instring[loc] in self.matchWhite:
            loc += 1

        if loc - start < self.minLen:
            raise ParseException(instring, loc, self.errmsg, self)

        return loc, instring[start:loc]


class PositionToken(Token):
    def __init__(self):
        super().__init__()
        self.mayReturnEmpty = True
        self.mayIndexError = False


class GoToColumn(PositionToken):

    def __init__(self, colno: int):
        super().__init__()
        self.col = colno

    def preParse(self, instring, loc):
        if col(loc, instring) != self.col:
            instrlen = len(instring)
            if self.ignoreExprs:
                loc = self._skipIgnorables(instring, loc)
            while (
                loc < instrlen
                and instring[loc].isspace()
                and col(loc, instring) != self.col
            ):
                loc += 1
        return loc

    def parseImpl(self, instring, loc, doActions=True):
        thiscol = col(loc, instring)
        if thiscol > self.col:
            raise ParseException(instring, loc, "Text not in expected column", self)
        newloc = loc + self.col - thiscol
        ret = instring[loc:newloc]
        return newloc, ret


class LineStart(PositionToken):

    def __init__(self):
        super().__init__()
        self.leave_whitespace()
        self.orig_whiteChars = set() | self.whiteChars
        self.whiteChars.discard("\n")
        self.skipper = Empty().set_whitespace_chars(self.whiteChars)
        self.errmsg = "Expected start of line"

    def preParse(self, instring, loc):
        if loc == 0:
            return loc
        else:
            ret = self.skipper.preParse(instring, loc)
            if "\n" in self.orig_whiteChars:
                while instring[ret : ret + 1] == "\n":
                    ret = self.skipper.preParse(instring, ret + 1)
            return ret

    def parseImpl(self, instring, loc, doActions=True):
        if col(loc, instring) == 1:
            return loc, []
        raise ParseException(instring, loc, self.errmsg, self)


class LineEnd(PositionToken):

    def __init__(self):
        super().__init__()
        self.whiteChars.discard("\n")
        self.set_whitespace_chars(self.whiteChars, copy_defaults=False)
        self.errmsg = "Expected end of line"

    def parseImpl(self, instring, loc, doActions=True):
        if loc < len(instring):
            if instring[loc] == "\n":
                return loc + 1, "\n"
            else:
                raise ParseException(instring, loc, self.errmsg, self)
        elif loc == len(instring):
            return loc + 1, []
        else:
            raise ParseException(instring, loc, self.errmsg, self)


class StringStart(PositionToken):

    def __init__(self):
        super().__init__()
        self.errmsg = "Expected start of text"

    def parseImpl(self, instring, loc, doActions=True):
        if loc != 0:

            if loc != self.preParse(instring, 0):
                raise ParseException(instring, loc, self.errmsg, self)
        return loc, []


class StringEnd(PositionToken):

    def __init__(self):
        super().__init__()
        self.errmsg = "Expected end of text"

    def parseImpl(self, instring, loc, doActions=True):
        if loc < len(instring):
            raise ParseException(instring, loc, self.errmsg, self)
        elif loc == len(instring):
            return loc + 1, []
        elif loc > len(instring):
            return loc, []
        else:
            raise ParseException(instring, loc, self.errmsg, self)


class WordStart(PositionToken):

    def __init__(self, word_chars: str = printables, *, wordChars: str = printables):
        wordChars = word_chars if wordChars == printables else wordChars
        super().__init__()
        self.wordChars = set(wordChars)
        self.errmsg = "Not at the start of a word"

    def parseImpl(self, instring, loc, doActions=True):
        if loc != 0:
            if (
                instring[loc - 1] in self.wordChars
                or instring[loc] not in self.wordChars
            ):
                raise ParseException(instring, loc, self.errmsg, self)
        return loc, []


class WordEnd(PositionToken):

    def __init__(self, word_chars: str = printables, *, wordChars: str = printables):
        wordChars = word_chars if wordChars == printables else wordChars
        super().__init__()
        self.wordChars = set(wordChars)
        self.skipWhitespace = False
        self.errmsg = "Not at the end of a word"

    def parseImpl(self, instring, loc, doActions=True):
        instrlen = len(instring)
        if instrlen > 0 and loc < instrlen:
            if (
                instring[loc] in self.wordChars
                or instring[loc - 1] not in self.wordChars
            ):
                raise ParseException(instring, loc, self.errmsg, self)
        return loc, []


class ParseExpression(ParserElement):

    def __init__(self, exprs: IterableType[ParserElement], savelist: bool = False):
        super().__init__(savelist)
        self.exprs: List[ParserElement]
        if isinstance(exprs, _generatorType):
            exprs = list(exprs)

        if isinstance(exprs, str_type):
            self.exprs = [self._literalStringClass(exprs)]
        elif isinstance(exprs, ParserElement):
            self.exprs = [exprs]
        elif isinstance(exprs, Iterable):
            exprs = list(exprs)

            if any(isinstance(expr, str_type) for expr in exprs):
                exprs = (
                    self._literalStringClass(e) if isinstance(e, str_type) else e
                    for e in exprs
                )
            self.exprs = list(exprs)
        else:
            try:
                self.exprs = list(exprs)
            except TypeError:
                self.exprs = [exprs]
        self.callPreparse = False

    def recurse(self) -> Sequence[ParserElement]:
        return self.exprs[:]

    def append(self, other) -> ParserElement:
        self.exprs.append(other)
        self._defaultName = None
        return self

    def leave_whitespace(self, recursive: bool = True) -> ParserElement:
        super().leave_whitespace(recursive)

        if recursive:
            self.exprs = [e.copy() for e in self.exprs]
            for e in self.exprs:
                e.leave_whitespace(recursive)
        return self

    def ignore_whitespace(self, recursive: bool = True) -> ParserElement:
        super().ignore_whitespace(recursive)
        if recursive:
            self.exprs = [e.copy() for e in self.exprs]
            for e in self.exprs:
                e.ignore_whitespace(recursive)
        return self

    def ignore(self, other) -> ParserElement:
        if isinstance(other, Suppress):
            if other not in self.ignoreExprs:
                super().ignore(other)
                for e in self.exprs:
                    e.ignore(self.ignoreExprs[-1])
        else:
            super().ignore(other)
            for e in self.exprs:
                e.ignore(self.ignoreExprs[-1])
        return self

    def _generateDefaultName(self):
        return "{}:({})".format(self.__class__.__name__, str(self.exprs))

    def streamline(self) -> ParserElement:
        if self.streamlined:
            return self

        super().streamline()

        for e in self.exprs:
            e.streamline()


        if len(self.exprs) == 2:
            other = self.exprs[0]
            if (
                isinstance(other, self.__class__)
                and not other.parseAction
                and other.resultsName is None
                and not other.debug
            ):
                self.exprs = other.exprs[:] + [self.exprs[1]]
                self._defaultName = None
                self.mayReturnEmpty |= other.mayReturnEmpty
                self.mayIndexError |= other.mayIndexError

            other = self.exprs[-1]
            if (
                isinstance(other, self.__class__)
                and not other.parseAction
                and other.resultsName is None
                and not other.debug
            ):
                self.exprs = self.exprs[:-1] + other.exprs[:]
                self._defaultName = None
                self.mayReturnEmpty |= other.mayReturnEmpty
                self.mayIndexError |= other.mayIndexError

        self.errmsg = "Expected " + str(self)

        return self

    def validate(self, validateTrace=None) -> None:
        tmp = (validateTrace if validateTrace is not None else [])[:] + [self]
        for e in self.exprs:
            e.validate(tmp)
        self._checkRecursion([])

    def copy(self) -> ParserElement:
        ret = super().copy()
        ret.exprs = [e.copy() for e in self.exprs]
        return ret

    def _setResultsName(self, name, listAllMatches=False):
        if (
            __diag__.warn_ungrouped_named_tokens_in_collection
            and Diagnostics.warn_ungrouped_named_tokens_in_collection
            not in self.suppress_warnings_
        ):
            for e in self.exprs:
                if (
                    isinstance(e, ParserElement)
                    and e.resultsName
                    and Diagnostics.warn_ungrouped_named_tokens_in_collection
                    not in e.suppress_warnings_
                ):
                    warnings.warn(
                        "{}: setting results name {!r} on {} expression "
                        "collides with {!r} on contained expression".format(
                            "warn_ungrouped_named_tokens_in_collection",
                            name,
                            type(self).__name__,
                            e.resultsName,
                        ),
                        stacklevel=3,
                    )

        return super()._setResultsName(name, listAllMatches)

    ignoreWhitespace = ignore_whitespace
    leaveWhitespace = leave_whitespace


class And(ParseExpression):

    class _ErrorStop(Empty):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.leave_whitespace()

        def _generateDefaultName(self):
            return "-"

    def __init__(self, exprs_arg: IterableType[ParserElement], savelist: bool = True):
        exprs: List[ParserElement] = list(exprs_arg)
        if exprs and Ellipsis in exprs:
            tmp = []
            for i, expr in enumerate(exprs):
                if expr is Ellipsis:
                    if i < len(exprs) - 1:
                        skipto_arg: ParserElement = (Empty() + exprs[i + 1]).exprs[-1]
                        tmp.append(SkipTo(skipto_arg)("_skipped*"))
                    else:
                        raise Exception(
                            "cannot construct And with sequence ending in ..."
                        )
                else:
                    tmp.append(expr)
            exprs[:] = tmp
        super().__init__(exprs, savelist)
        if self.exprs:
            self.mayReturnEmpty = all(e.mayReturnEmpty for e in self.exprs)
            if not isinstance(self.exprs[0], White):
                self.set_whitespace_chars(
                    self.exprs[0].whiteChars,
                    copy_defaults=self.exprs[0].copyDefaultWhiteChars,
                )
                self.skipWhitespace = self.exprs[0].skipWhitespace
            else:
                self.skipWhitespace = False
        else:
            self.mayReturnEmpty = True
        self.callPreparse = True

    def streamline(self) -> ParserElement:

        if self.exprs:
            if any(
                isinstance(e, ParseExpression)
                and e.exprs
                and isinstance(e.exprs[-1], _PendingSkip)
                for e in self.exprs[:-1]
            ):
                for i, e in enumerate(self.exprs[:-1]):
                    if e is None:
                        continue
                    if (
                        isinstance(e, ParseExpression)
                        and e.exprs
                        and isinstance(e.exprs[-1], _PendingSkip)
                    ):
                        e.exprs[-1] = e.exprs[-1] + self.exprs[i + 1]
                        self.exprs[i + 1] = None
                self.exprs = [e for e in self.exprs if e is not None]

        super().streamline()


        for prev, cur in zip(self.exprs, self.exprs[1:]):


            seen = set()
            while cur:
                if id(cur) in seen:
                    break
                seen.add(id(cur))
                if isinstance(cur, IndentedBlock):
                    prev.add_parse_action(
                        lambda s, l, t, cur_=cur: setattr(cur_, "parent_anchor", col(l, s))
                    )
                    break
                subs = cur.recurse()
                cur = next(iter(subs), None)

        self.mayReturnEmpty = all(e.mayReturnEmpty for e in self.exprs)
        return self

    def parseImpl(self, instring, loc, doActions=True):


        loc, resultlist = self.exprs[0]._parse(
            instring, loc, doActions, callPreParse=False
        )
        errorStop = False
        for e in self.exprs[1:]:

            if type(e) is And._ErrorStop:
                errorStop = True
                continue
            if errorStop:
                try:
                    loc, exprtokens = e._parse(instring, loc, doActions)
                except ParseSyntaxException:
                    raise
                except ParseBaseException as pe:
                    pe.__traceback__ = None
                    raise ParseSyntaxException._from_exception(pe)
                except IndexError:
                    raise ParseSyntaxException(
                        instring, len(instring), self.errmsg, self
                    )
            else:
                loc, exprtokens = e._parse(instring, loc, doActions)
            if exprtokens or exprtokens.haskeys():
                resultlist += exprtokens
        return loc, resultlist

    def __iadd__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        return self.append(other)

    def _checkRecursion(self, parseElementList):
        subRecCheckList = parseElementList[:] + [self]
        for e in self.exprs:
            e._checkRecursion(subRecCheckList)
            if not e.mayReturnEmpty:
                break

    def _generateDefaultName(self):
        inner = " ".join(str(e) for e in self.exprs)

        while len(inner) > 1 and inner[0 :: len(inner) - 1] == "{}":
            inner = inner[1:-1]
        return "{" + inner + "}"


class Or(ParseExpression):

    def __init__(self, exprs: IterableType[ParserElement], savelist: bool = False):
        super().__init__(exprs, savelist)
        if self.exprs:
            self.mayReturnEmpty = any(e.mayReturnEmpty for e in self.exprs)
            self.skipWhitespace = all(e.skipWhitespace for e in self.exprs)
        else:
            self.mayReturnEmpty = True

    def streamline(self) -> ParserElement:
        super().streamline()
        if self.exprs:
            self.mayReturnEmpty = any(e.mayReturnEmpty for e in self.exprs)
            self.saveAsList = any(e.saveAsList for e in self.exprs)
            self.skipWhitespace = all(
                e.skipWhitespace and not isinstance(e, White) for e in self.exprs
            )
        else:
            self.saveAsList = False
        return self

    def parseImpl(self, instring, loc, doActions=True):
        maxExcLoc = -1
        maxException = None
        matches = []
        fatals = []
        if all(e.callPreparse for e in self.exprs):
            loc = self.preParse(instring, loc)
        for e in self.exprs:
            try:
                loc2 = e.try_parse(instring, loc, raise_fatal=True)
            except ParseFatalException as pfe:
                pfe.__traceback__ = None
                pfe.parserElement = e
                fatals.append(pfe)
                maxException = None
                maxExcLoc = -1
            except ParseException as err:
                if not fatals:
                    err.__traceback__ = None
                    if err.loc > maxExcLoc:
                        maxException = err
                        maxExcLoc = err.loc
            except IndexError:
                if len(instring) > maxExcLoc:
                    maxException = ParseException(
                        instring, len(instring), e.errmsg, self
                    )
                    maxExcLoc = len(instring)
            else:

                matches.append((loc2, e))

        if matches:


            matches.sort(key=itemgetter(0), reverse=True)

            if not doActions:


                best_expr = matches[0][1]
                return best_expr._parse(instring, loc, doActions)

            longest = -1, None
            for loc1, expr1 in matches:
                if loc1 <= longest[0]:

                    return longest

                try:
                    loc2, toks = expr1._parse(instring, loc, doActions)
                except ParseException as err:
                    err.__traceback__ = None
                    if err.loc > maxExcLoc:
                        maxException = err
                        maxExcLoc = err.loc
                else:
                    if loc2 >= loc1:
                        return loc2, toks

                    elif loc2 > longest[0]:
                        longest = loc2, toks

            if longest != (-1, None):
                return longest

        if fatals:
            if len(fatals) > 1:
                fatals.sort(key=lambda e: -e.loc)
                if fatals[0].loc == fatals[1].loc:
                    fatals.sort(key=lambda e: (-e.loc, -len(str(e.parserElement))))
            max_fatal = fatals[0]
            raise max_fatal

        if maxException is not None:
            maxException.msg = self.errmsg
            raise maxException
        else:
            raise ParseException(
                instring, loc, "no defined alternatives to match", self
            )

    def __ixor__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        return self.append(other)

    def _generateDefaultName(self):
        return "{" + " ^ ".join(str(e) for e in self.exprs) + "}"

    def _setResultsName(self, name, listAllMatches=False):
        if (
            __diag__.warn_multiple_tokens_in_named_alternation
            and Diagnostics.warn_multiple_tokens_in_named_alternation
            not in self.suppress_warnings_
        ):
            if any(
                isinstance(e, And)
                and Diagnostics.warn_multiple_tokens_in_named_alternation
                not in e.suppress_warnings_
                for e in self.exprs
            ):
                warnings.warn(
                    "{}: setting results name {!r} on {} expression "
                    "will return a list of all parsed tokens in an And alternative, "
                    "in prior versions only the first token was returned; enclose "
                    "contained argument in Group".format(
                        "warn_multiple_tokens_in_named_alternation",
                        name,
                        type(self).__name__,
                    ),
                    stacklevel=3,
                )

        return super()._setResultsName(name, listAllMatches)


class MatchFirst(ParseExpression):

    def __init__(self, exprs: IterableType[ParserElement], savelist: bool = False):
        super().__init__(exprs, savelist)
        if self.exprs:
            self.mayReturnEmpty = any(e.mayReturnEmpty for e in self.exprs)
            self.skipWhitespace = all(e.skipWhitespace for e in self.exprs)
        else:
            self.mayReturnEmpty = True

    def streamline(self) -> ParserElement:
        if self.streamlined:
            return self

        super().streamline()
        if self.exprs:
            self.saveAsList = any(e.saveAsList for e in self.exprs)
            self.mayReturnEmpty = any(e.mayReturnEmpty for e in self.exprs)
            self.skipWhitespace = all(
                e.skipWhitespace and not isinstance(e, White) for e in self.exprs
            )
        else:
            self.saveAsList = False
            self.mayReturnEmpty = True
        return self

    def parseImpl(self, instring, loc, doActions=True):
        maxExcLoc = -1
        maxException = None

        for e in self.exprs:
            try:
                return e._parse(
                    instring,
                    loc,
                    doActions,
                )
            except ParseFatalException as pfe:
                pfe.__traceback__ = None
                pfe.parserElement = e
                raise
            except ParseException as err:
                if err.loc > maxExcLoc:
                    maxException = err
                    maxExcLoc = err.loc
            except IndexError:
                if len(instring) > maxExcLoc:
                    maxException = ParseException(
                        instring, len(instring), e.errmsg, self
                    )
                    maxExcLoc = len(instring)

        if maxException is not None:
            maxException.msg = self.errmsg
            raise maxException
        else:
            raise ParseException(
                instring, loc, "no defined alternatives to match", self
            )

    def __ior__(self, other):
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        return self.append(other)

    def _generateDefaultName(self):
        return "{" + " | ".join(str(e) for e in self.exprs) + "}"

    def _setResultsName(self, name, listAllMatches=False):
        if (
            __diag__.warn_multiple_tokens_in_named_alternation
            and Diagnostics.warn_multiple_tokens_in_named_alternation
            not in self.suppress_warnings_
        ):
            if any(
                isinstance(e, And)
                and Diagnostics.warn_multiple_tokens_in_named_alternation
                not in e.suppress_warnings_
                for e in self.exprs
            ):
                warnings.warn(
                    "{}: setting results name {!r} on {} expression "
                    "will return a list of all parsed tokens in an And alternative, "
                    "in prior versions only the first token was returned; enclose "
                    "contained argument in Group".format(
                        "warn_multiple_tokens_in_named_alternation",
                        name,
                        type(self).__name__,
                    ),
                    stacklevel=3,
                )

        return super()._setResultsName(name, listAllMatches)


class Each(ParseExpression):

    def __init__(self, exprs: IterableType[ParserElement], savelist: bool = True):
        super().__init__(exprs, savelist)
        if self.exprs:
            self.mayReturnEmpty = all(e.mayReturnEmpty for e in self.exprs)
        else:
            self.mayReturnEmpty = True
        self.skipWhitespace = True
        self.initExprGroups = True
        self.saveAsList = True

    def streamline(self) -> ParserElement:
        super().streamline()
        if self.exprs:
            self.mayReturnEmpty = all(e.mayReturnEmpty for e in self.exprs)
        else:
            self.mayReturnEmpty = True
        return self

    def parseImpl(self, instring, loc, doActions=True):
        if self.initExprGroups:
            self.opt1map = dict(
                (id(e.expr), e) for e in self.exprs if isinstance(e, Opt)
            )
            opt1 = [e.expr for e in self.exprs if isinstance(e, Opt)]
            opt2 = [
                e
                for e in self.exprs
                if e.mayReturnEmpty and not isinstance(e, (Opt, Regex, ZeroOrMore))
            ]
            self.optionals = opt1 + opt2
            self.multioptionals = [
                e.expr.set_results_name(e.resultsName, list_all_matches=True)
                for e in self.exprs
                if isinstance(e, _MultipleMatch)
            ]
            self.multirequired = [
                e.expr.set_results_name(e.resultsName, list_all_matches=True)
                for e in self.exprs
                if isinstance(e, OneOrMore)
            ]
            self.required = [
                e for e in self.exprs if not isinstance(e, (Opt, ZeroOrMore, OneOrMore))
            ]
            self.required += self.multirequired
            self.initExprGroups = False

        tmpLoc = loc
        tmpReqd = self.required[:]
        tmpOpt = self.optionals[:]
        multis = self.multioptionals[:]
        matchOrder = []

        keepMatching = True
        failed = []
        fatals = []
        while keepMatching:
            tmpExprs = tmpReqd + tmpOpt + multis
            failed.clear()
            fatals.clear()
            for e in tmpExprs:
                try:
                    tmpLoc = e.try_parse(instring, tmpLoc, raise_fatal=True)
                except ParseFatalException as pfe:
                    pfe.__traceback__ = None
                    pfe.parserElement = e
                    fatals.append(pfe)
                    failed.append(e)
                except ParseException:
                    failed.append(e)
                else:
                    matchOrder.append(self.opt1map.get(id(e), e))
                    if e in tmpReqd:
                        tmpReqd.remove(e)
                    elif e in tmpOpt:
                        tmpOpt.remove(e)
            if len(failed) == len(tmpExprs):
                keepMatching = False


        if fatals:
            if len(fatals) > 1:
                fatals.sort(key=lambda e: -e.loc)
                if fatals[0].loc == fatals[1].loc:
                    fatals.sort(key=lambda e: (-e.loc, -len(str(e.parserElement))))
            max_fatal = fatals[0]
            raise max_fatal

        if tmpReqd:
            missing = ", ".join([str(e) for e in tmpReqd])
            raise ParseException(
                instring,
                loc,
                "Missing one or more required elements ({})".format(missing),
            )


        matchOrder += [e for e in self.exprs if isinstance(e, Opt) and e.expr in tmpOpt]

        total_results = ParseResults([])
        for e in matchOrder:
            loc, results = e._parse(instring, loc, doActions)
            total_results += results

        return loc, total_results

    def _generateDefaultName(self):
        return "{" + " & ".join(str(e) for e in self.exprs) + "}"


class ParseElementEnhance(ParserElement):

    def __init__(self, expr: Union[ParserElement, str], savelist: bool = False):
        super().__init__(savelist)
        if isinstance(expr, str_type):
            if issubclass(self._literalStringClass, Token):
                expr = self._literalStringClass(expr)
            elif issubclass(type(self), self._literalStringClass):
                expr = Literal(expr)
            else:
                expr = self._literalStringClass(Literal(expr))
        self.expr = expr
        if expr is not None:
            self.mayIndexError = expr.mayIndexError
            self.mayReturnEmpty = expr.mayReturnEmpty
            self.set_whitespace_chars(
                expr.whiteChars, copy_defaults=expr.copyDefaultWhiteChars
            )
            self.skipWhitespace = expr.skipWhitespace
            self.saveAsList = expr.saveAsList
            self.callPreparse = expr.callPreparse
            self.ignoreExprs.extend(expr.ignoreExprs)

    def recurse(self) -> Sequence[ParserElement]:
        return [self.expr] if self.expr is not None else []

    def parseImpl(self, instring, loc, doActions=True):
        if self.expr is not None:
            return self.expr._parse(instring, loc, doActions, callPreParse=False)
        else:
            raise ParseException(instring, loc, "No expression defined", self)

    def leave_whitespace(self, recursive: bool = True) -> ParserElement:
        super().leave_whitespace(recursive)

        if recursive:
            self.expr = self.expr.copy()
            if self.expr is not None:
                self.expr.leave_whitespace(recursive)
        return self

    def ignore_whitespace(self, recursive: bool = True) -> ParserElement:
        super().ignore_whitespace(recursive)

        if recursive:
            self.expr = self.expr.copy()
            if self.expr is not None:
                self.expr.ignore_whitespace(recursive)
        return self

    def ignore(self, other) -> ParserElement:
        if isinstance(other, Suppress):
            if other not in self.ignoreExprs:
                super().ignore(other)
                if self.expr is not None:
                    self.expr.ignore(self.ignoreExprs[-1])
        else:
            super().ignore(other)
            if self.expr is not None:
                self.expr.ignore(self.ignoreExprs[-1])
        return self

    def streamline(self) -> ParserElement:
        super().streamline()
        if self.expr is not None:
            self.expr.streamline()
        return self

    def _checkRecursion(self, parseElementList):
        if self in parseElementList:
            raise RecursiveGrammarException(parseElementList + [self])
        subRecCheckList = parseElementList[:] + [self]
        if self.expr is not None:
            self.expr._checkRecursion(subRecCheckList)

    def validate(self, validateTrace=None) -> None:
        if validateTrace is None:
            validateTrace = []
        tmp = validateTrace[:] + [self]
        if self.expr is not None:
            self.expr.validate(tmp)
        self._checkRecursion([])

    def _generateDefaultName(self):
        return "{}:({})".format(self.__class__.__name__, str(self.expr))

    ignoreWhitespace = ignore_whitespace
    leaveWhitespace = leave_whitespace


class IndentedBlock(ParseElementEnhance):

    class _Indent(Empty):
        def __init__(self, ref_col: int):
            super().__init__()
            self.errmsg = "expected indent at column {}".format(ref_col)
            self.add_condition(lambda s, l, t: col(l, s) == ref_col)

    class _IndentGreater(Empty):
        def __init__(self, ref_col: int):
            super().__init__()
            self.errmsg = "expected indent at column greater than {}".format(ref_col)
            self.add_condition(lambda s, l, t: col(l, s) > ref_col)

    def __init__(
        self, expr: ParserElement, *, recursive: bool = False, grouped: bool = True
    ):
        super().__init__(expr, savelist=True)


        self._recursive = recursive
        self._grouped = grouped
        self.parent_anchor = 1

    def parseImpl(self, instring, loc, doActions=True):


        anchor_loc = Empty().preParse(instring, loc)


        self.expr.try_parse(instring, anchor_loc, doActions)

        indent_col = col(anchor_loc, instring)
        peer_detect_expr = self._Indent(indent_col)

        inner_expr = Empty() + peer_detect_expr + self.expr
        if self._recursive:
            sub_indent = self._IndentGreater(indent_col)
            nested_block = IndentedBlock(
                self.expr, recursive=self._recursive, grouped=self._grouped
            )
            nested_block.set_debug(self.debug)
            nested_block.parent_anchor = indent_col
            inner_expr += Opt(sub_indent + nested_block)

        inner_expr.set_name(f"inner {hex(id(inner_expr))[-4:].upper()}@{indent_col}")
        block = OneOrMore(inner_expr)

        trailing_undent = self._Indent(self.parent_anchor) | StringEnd()

        if self._grouped:
            wrapper = Group
        else:
            wrapper = lambda expr: expr
        return (wrapper(block) + Optional(trailing_undent)).parseImpl(
            instring, anchor_loc, doActions
        )


class AtStringStart(ParseElementEnhance):

    def __init__(self, expr: Union[ParserElement, str]):
        super().__init__(expr)
        self.callPreparse = False

    def parseImpl(self, instring, loc, doActions=True):
        if loc != 0:
            raise ParseException(instring, loc, "not found at string start")
        return super().parseImpl(instring, loc, doActions)


class AtLineStart(ParseElementEnhance):

    def __init__(self, expr: Union[ParserElement, str]):
        super().__init__(expr)
        self.callPreparse = False

    def parseImpl(self, instring, loc, doActions=True):
        if col(loc, instring) != 1:
            raise ParseException(instring, loc, "not found at line start")
        return super().parseImpl(instring, loc, doActions)


class FollowedBy(ParseElementEnhance):

    def __init__(self, expr: Union[ParserElement, str]):
        super().__init__(expr)
        self.mayReturnEmpty = True

    def parseImpl(self, instring, loc, doActions=True):


        _, ret = self.expr._parse(instring, loc, doActions=doActions)
        del ret[:]

        return loc, ret


class PrecededBy(ParseElementEnhance):

    def __init__(
        self, expr: Union[ParserElement, str], retreat: OptionalType[int] = None
    ):
        super().__init__(expr)
        self.expr = self.expr().leave_whitespace()
        self.mayReturnEmpty = True
        self.mayIndexError = False
        self.exact = False
        if isinstance(expr, str_type):
            retreat = len(expr)
            self.exact = True
        elif isinstance(expr, (Literal, Keyword)):
            retreat = expr.matchLen
            self.exact = True
        elif isinstance(expr, (Word, CharsNotIn)) and expr.maxLen != _MAX_INT:
            retreat = expr.maxLen
            self.exact = True
        elif isinstance(expr, PositionToken):
            retreat = 0
            self.exact = True
        self.retreat = retreat
        self.errmsg = "not preceded by " + str(expr)
        self.skipWhitespace = False
        self.parseAction.append(lambda s, l, t: t.__delitem__(slice(None, None)))

    def parseImpl(self, instring, loc=0, doActions=True):
        if self.exact:
            if loc < self.retreat:
                raise ParseException(instring, loc, self.errmsg)
            start = loc - self.retreat
            _, ret = self.expr._parse(instring, start)
        else:

            test_expr = self.expr + StringEnd()
            instring_slice = instring[max(0, loc - self.retreat) : loc]
            last_expr = ParseException(instring, loc, self.errmsg)
            for offset in range(1, min(loc, self.retreat + 1) + 1):
                try:

                    _, ret = test_expr._parse(
                        instring_slice, len(instring_slice) - offset
                    )
                except ParseBaseException as pbe:
                    last_expr = pbe
                else:
                    break
            else:
                raise last_expr
        return loc, ret


class Located(ParseElementEnhance):

    def parseImpl(self, instring, loc, doActions=True):
        start = loc
        loc, tokens = self.expr._parse(instring, start, doActions, callPreParse=False)
        ret_tokens = ParseResults([start, tokens, loc])
        ret_tokens["locn_start"] = start
        ret_tokens["value"] = tokens
        ret_tokens["locn_end"] = loc
        if self.resultsName:

            return loc, [ret_tokens]
        else:
            return loc, ret_tokens


class NotAny(ParseElementEnhance):

    def __init__(self, expr: Union[ParserElement, str]):
        super().__init__(expr)


        self.skipWhitespace = False

        self.mayReturnEmpty = True
        self.errmsg = "Found unwanted token, " + str(self.expr)

    def parseImpl(self, instring, loc, doActions=True):
        if self.expr.can_parse_next(instring, loc):
            raise ParseException(instring, loc, self.errmsg, self)
        return loc, []

    def _generateDefaultName(self):
        return "~{" + str(self.expr) + "}"


class _MultipleMatch(ParseElementEnhance):
    def __init__(
        self,
        expr: ParserElement,
        stop_on: OptionalType[Union[ParserElement, str]] = None,
        *,
        stopOn: OptionalType[Union[ParserElement, str]] = None,
    ):
        super().__init__(expr)
        stopOn = stopOn or stop_on
        self.saveAsList = True
        ender = stopOn
        if isinstance(ender, str_type):
            ender = self._literalStringClass(ender)
        self.stopOn(ender)

    def stopOn(self, ender) -> ParserElement:
        if isinstance(ender, str_type):
            ender = self._literalStringClass(ender)
        self.not_ender = ~ender if ender is not None else None
        return self

    def parseImpl(self, instring, loc, doActions=True):
        self_expr_parse = self.expr._parse
        self_skip_ignorables = self._skipIgnorables
        check_ender = self.not_ender is not None
        if check_ender:
            try_not_ender = self.not_ender.tryParse


        if check_ender:
            try_not_ender(instring, loc)
        loc, tokens = self_expr_parse(instring, loc, doActions)
        try:
            hasIgnoreExprs = not not self.ignoreExprs
            while 1:
                if check_ender:
                    try_not_ender(instring, loc)
                if hasIgnoreExprs:
                    preloc = self_skip_ignorables(instring, loc)
                else:
                    preloc = loc
                loc, tmptokens = self_expr_parse(instring, preloc, doActions)
                if tmptokens or tmptokens.haskeys():
                    tokens += tmptokens
        except (ParseException, IndexError):
            pass

        return loc, tokens

    def _setResultsName(self, name, listAllMatches=False):
        if (
            __diag__.warn_ungrouped_named_tokens_in_collection
            and Diagnostics.warn_ungrouped_named_tokens_in_collection
            not in self.suppress_warnings_
        ):
            for e in [self.expr] + self.expr.recurse():
                if (
                    isinstance(e, ParserElement)
                    and e.resultsName
                    and Diagnostics.warn_ungrouped_named_tokens_in_collection
                    not in e.suppress_warnings_
                ):
                    warnings.warn(
                        "{}: setting results name {!r} on {} expression "
                        "collides with {!r} on contained expression".format(
                            "warn_ungrouped_named_tokens_in_collection",
                            name,
                            type(self).__name__,
                            e.resultsName,
                        ),
                        stacklevel=3,
                    )

        return super()._setResultsName(name, listAllMatches)


class OneOrMore(_MultipleMatch):

    def _generateDefaultName(self):
        return "{" + str(self.expr) + "}..."


class ZeroOrMore(_MultipleMatch):

    def __init__(
        self,
        expr: ParserElement,
        stop_on: OptionalType[Union[ParserElement, str]] = None,
        *,
        stopOn: OptionalType[Union[ParserElement, str]] = None,
    ):
        super().__init__(expr, stopOn=stopOn or stop_on)
        self.mayReturnEmpty = True

    def parseImpl(self, instring, loc, doActions=True):
        try:
            return super().parseImpl(instring, loc, doActions)
        except (ParseException, IndexError):
            return loc, ParseResults([], name=self.resultsName)

    def _generateDefaultName(self):
        return "[" + str(self.expr) + "]..."


class _NullToken:
    def __bool__(self):
        return False

    def __str__(self):
        return ""


class Opt(ParseElementEnhance):

    __optionalNotMatched = _NullToken()

    def __init__(
        self, expr: Union[ParserElement, str], default: Any = __optionalNotMatched
    ):
        super().__init__(expr, savelist=False)
        self.saveAsList = self.expr.saveAsList
        self.defaultValue = default
        self.mayReturnEmpty = True

    def parseImpl(self, instring, loc, doActions=True):
        self_expr = self.expr
        try:
            loc, tokens = self_expr._parse(instring, loc, doActions, callPreParse=False)
        except (ParseException, IndexError):
            default_value = self.defaultValue
            if default_value is not self.__optionalNotMatched:
                if self_expr.resultsName:
                    tokens = ParseResults([default_value])
                    tokens[self_expr.resultsName] = default_value
                else:
                    tokens = [default_value]
            else:
                tokens = []
        return loc, tokens

    def _generateDefaultName(self):
        inner = str(self.expr)

        while len(inner) > 1 and inner[0 :: len(inner) - 1] == "{}":
            inner = inner[1:-1]
        return "[" + inner + "]"


Optional = Opt


class SkipTo(ParseElementEnhance):

    def __init__(
        self,
        other: Union[ParserElement, str],
        include: bool = False,
        ignore: bool = None,
        fail_on: OptionalType[Union[ParserElement, str]] = None,
        *,
        failOn: Union[ParserElement, str] = None,
    ):
        super().__init__(other)
        failOn = failOn or fail_on
        self.ignoreExpr = ignore
        self.mayReturnEmpty = True
        self.mayIndexError = False
        self.includeMatch = include
        self.saveAsList = False
        if isinstance(failOn, str_type):
            self.failOn = self._literalStringClass(failOn)
        else:
            self.failOn = failOn
        self.errmsg = "No match found for " + str(self.expr)

    def parseImpl(self, instring, loc, doActions=True):
        startloc = loc
        instrlen = len(instring)
        self_expr_parse = self.expr._parse
        self_failOn_canParseNext = (
            self.failOn.canParseNext if self.failOn is not None else None
        )
        self_ignoreExpr_tryParse = (
            self.ignoreExpr.tryParse if self.ignoreExpr is not None else None
        )

        tmploc = loc
        while tmploc <= instrlen:
            if self_failOn_canParseNext is not None:

                if self_failOn_canParseNext(instring, tmploc):
                    break

            if self_ignoreExpr_tryParse is not None:

                while 1:
                    try:
                        tmploc = self_ignoreExpr_tryParse(instring, tmploc)
                    except ParseBaseException:
                        break

            try:
                self_expr_parse(instring, tmploc, doActions=False, callPreParse=False)
            except (ParseException, IndexError):

                tmploc += 1
            else:

                break

        else:

            raise ParseException(instring, loc, self.errmsg, self)


        loc = tmploc
        skiptext = instring[startloc:loc]
        skipresult = ParseResults(skiptext)

        if self.includeMatch:
            loc, mat = self_expr_parse(instring, loc, doActions, callPreParse=False)
            skipresult += mat

        return loc, skipresult


class Forward(ParseElementEnhance):

    def __init__(self, other: OptionalType[Union[ParserElement, str]] = None):
        self.caller_frame = traceback.extract_stack(limit=2)[0]
        super().__init__(other, savelist=False)
        self.lshift_line = None

    def __lshift__(self, other):
        if hasattr(self, "caller_frame"):
            del self.caller_frame
        if isinstance(other, str_type):
            other = self._literalStringClass(other)
        self.expr = other
        self.mayIndexError = self.expr.mayIndexError
        self.mayReturnEmpty = self.expr.mayReturnEmpty
        self.set_whitespace_chars(
            self.expr.whiteChars, copy_defaults=self.expr.copyDefaultWhiteChars
        )
        self.skipWhitespace = self.expr.skipWhitespace
        self.saveAsList = self.expr.saveAsList
        self.ignoreExprs.extend(self.expr.ignoreExprs)
        self.lshift_line = traceback.extract_stack(limit=2)[-2]
        return self

    def __ilshift__(self, other):
        return self << other

    def __or__(self, other):
        caller_line = traceback.extract_stack(limit=2)[-2]
        if (
            __diag__.warn_on_match_first_with_lshift_operator
            and caller_line == self.lshift_line
            and Diagnostics.warn_on_match_first_with_lshift_operator
            not in self.suppress_warnings_
        ):
            warnings.warn(
                "using '<<' operator with '|' is probably an error, use '<<='",
                stacklevel=2,
            )
        ret = super().__or__(other)
        return ret

    def __del__(self):

        if (
            self.expr is None
            and __diag__.warn_on_assignment_to_Forward
            and Diagnostics.warn_on_assignment_to_Forward not in self.suppress_warnings_
        ):
            warnings.warn_explicit(
                "Forward defined here but no expression attached later using '<<=' or '<<'",
                UserWarning,
                filename=self.caller_frame.filename,
                lineno=self.caller_frame.lineno,
            )

    def parseImpl(self, instring, loc, doActions=True):
        if (
            self.expr is None
            and __diag__.warn_on_parse_using_empty_Forward
            and Diagnostics.warn_on_parse_using_empty_Forward
            not in self.suppress_warnings_
        ):

            parse_fns = [
                "parse_string",
                "scan_string",
                "search_string",
                "transform_string",
            ]
            tb = traceback.extract_stack(limit=200)
            for i, frm in enumerate(reversed(tb), start=1):
                if frm.name in parse_fns:
                    stacklevel = i + 1
                    break
            else:
                stacklevel = 2
            warnings.warn(
                "Forward expression was never assigned a value, will not parse any input",
                stacklevel=stacklevel,
            )
        if not ParserElement._left_recursion_enabled:
            return super().parseImpl(instring, loc, doActions)


        with ParserElement.recursion_lock:
            memo = ParserElement.recursion_memos
            try:

                prev_loc, prev_result = memo[loc, self, doActions]
                if isinstance(prev_result, Exception):
                    raise prev_result
                return prev_loc, prev_result.copy()
            except KeyError:
                act_key = (loc, self, True)
                peek_key = (loc, self, False)


                prev_loc, prev_peek = memo[peek_key] = (
                    loc - 1,
                    ParseException(
                        instring, loc, "Forward recursion without base case", self
                    ),
                )
                if doActions:
                    memo[act_key] = memo[peek_key]
                while True:
                    try:
                        new_loc, new_peek = super().parseImpl(instring, loc, False)
                    except ParseException:

                        if isinstance(prev_peek, Exception):
                            raise
                        new_loc, new_peek = prev_loc, prev_peek

                    if new_loc <= prev_loc:
                        if doActions:


                            prev_loc, prev_result = memo[peek_key] = memo[act_key]
                            del memo[peek_key], memo[act_key]
                            return prev_loc, prev_result.copy()
                        del memo[peek_key]
                        return prev_loc, prev_peek.copy()

                    else:
                        if doActions:
                            try:
                                memo[act_key] = super().parseImpl(instring, loc, True)
                            except ParseException as e:
                                memo[peek_key] = memo[act_key] = (new_loc, e)
                                raise
                        prev_loc, prev_peek = memo[peek_key] = new_loc, new_peek

    def leave_whitespace(self, recursive: bool = True) -> ParserElement:
        self.skipWhitespace = False
        return self

    def ignore_whitespace(self, recursive: bool = True) -> ParserElement:
        self.skipWhitespace = True
        return self

    def streamline(self) -> ParserElement:
        if not self.streamlined:
            self.streamlined = True
            if self.expr is not None:
                self.expr.streamline()
        return self

    def validate(self, validateTrace=None) -> None:
        if validateTrace is None:
            validateTrace = []

        if self not in validateTrace:
            tmp = validateTrace[:] + [self]
            if self.expr is not None:
                self.expr.validate(tmp)
        self._checkRecursion([])

    def _generateDefaultName(self):

        self._defaultName = ": ..."


        retString = "..."
        try:
            if self.expr is not None:
                retString = str(self.expr)[:1000]
            else:
                retString = "None"
        finally:
            return self.__class__.__name__ + ": " + retString

    def copy(self) -> ParserElement:
        if self.expr is not None:
            return super().copy()
        else:
            ret = Forward()
            ret <<= self
            return ret

    def _setResultsName(self, name, list_all_matches=False):
        if (
            __diag__.warn_name_set_on_empty_Forward
            and Diagnostics.warn_name_set_on_empty_Forward
            not in self.suppress_warnings_
        ):
            if self.expr is None:
                warnings.warn(
                    "{}: setting results name {!r} on {} expression "
                    "that has no contained expression".format(
                        "warn_name_set_on_empty_Forward", name, type(self).__name__
                    ),
                    stacklevel=3,
                )

        return super()._setResultsName(name, list_all_matches)

    ignoreWhitespace = ignore_whitespace
    leaveWhitespace = leave_whitespace


class TokenConverter(ParseElementEnhance):

    def __init__(self, expr: Union[ParserElement, str], savelist=False):
        super().__init__(expr)
        self.saveAsList = False


class Combine(TokenConverter):

    def __init__(
        self,
        expr: ParserElement,
        join_string: str = "",
        adjacent: bool = True,
        *,
        joinString: OptionalType[str] = None,
    ):
        super().__init__(expr)
        joinString = joinString if joinString is not None else join_string

        if adjacent:
            self.leave_whitespace()
        self.adjacent = adjacent
        self.skipWhitespace = True
        self.joinString = joinString
        self.callPreparse = True

    def ignore(self, other) -> ParserElement:
        if self.adjacent:
            ParserElement.ignore(self, other)
        else:
            super().ignore(other)
        return self

    def postParse(self, instring, loc, tokenlist):
        retToks = tokenlist.copy()
        del retToks[:]
        retToks += ParseResults(
            ["".join(tokenlist._asStringList(self.joinString))], modal=self.modalResults
        )

        if self.resultsName and retToks.haskeys():
            return [retToks]
        else:
            return retToks


class Group(TokenConverter):

    def __init__(self, expr: ParserElement, aslist: bool = False):
        super().__init__(expr)
        self.saveAsList = True
        self._asPythonList = aslist

    def postParse(self, instring, loc, tokenlist):
        if self._asPythonList:
            return ParseResults.List(
                tokenlist.asList()
                if isinstance(tokenlist, ParseResults)
                else list(tokenlist)
            )
        else:
            return [tokenlist]


class Dict(TokenConverter):

    def __init__(self, expr: ParserElement, asdict: bool = False):
        super().__init__(expr)
        self.saveAsList = True
        self._asPythonDict = asdict

    def postParse(self, instring, loc, tokenlist):
        for i, tok in enumerate(tokenlist):
            if len(tok) == 0:
                continue

            ikey = tok[0]
            if isinstance(ikey, int):
                ikey = str(ikey).strip()

            if len(tok) == 1:
                tokenlist[ikey] = _ParseResultsWithOffset("", i)

            elif len(tok) == 2 and not isinstance(tok[1], ParseResults):
                tokenlist[ikey] = _ParseResultsWithOffset(tok[1], i)

            else:
                try:
                    dictvalue = tok.copy()
                except Exception:
                    exc = TypeError(
                        "could not extract dict values from parsed results"
                        " - Dict expression must contain Grouped expressions"
                    )
                    raise exc from None

                del dictvalue[0]

                if len(dictvalue) != 1 or (
                    isinstance(dictvalue, ParseResults) and dictvalue.haskeys()
                ):
                    tokenlist[ikey] = _ParseResultsWithOffset(dictvalue, i)
                else:
                    tokenlist[ikey] = _ParseResultsWithOffset(dictvalue[0], i)

        if self._asPythonDict:
            return [tokenlist.as_dict()] if self.resultsName else tokenlist.as_dict()
        else:
            return [tokenlist] if self.resultsName else tokenlist


class Suppress(TokenConverter):

    def __init__(self, expr: Union[ParserElement, str], savelist: bool = False):
        if expr is ...:
            expr = _PendingSkip(NoMatch())
        super().__init__(expr)

    def __add__(self, other):
        if isinstance(self.expr, _PendingSkip):
            return Suppress(SkipTo(other)) + other
        else:
            return super().__add__(other)

    def __sub__(self, other):
        if isinstance(self.expr, _PendingSkip):
            return Suppress(SkipTo(other)) - other
        else:
            return super().__sub__(other)

    def postParse(self, instring, loc, tokenlist):
        return []

    def suppress(self) -> ParserElement:
        return self


def trace_parse_action(f: ParseAction) -> ParseAction:
    f = _trim_arity(f)

    def z(*paArgs):
        thisFunc = f.__name__
        s, l, t = paArgs[-3:]
        if len(paArgs) > 3:
            thisFunc = paArgs[0].__class__.__name__ + "." + thisFunc
        sys.stderr.write(
            ">>entering {}(line: {!r}, {}, {!r})\n".format(thisFunc, line(l, s), l, t)
        )
        try:
            ret = f(*paArgs)
        except Exception as exc:
            sys.stderr.write("<<leaving {} (exception: {})\n".format(thisFunc, exc))
            raise
        sys.stderr.write("<<leaving {} (ret: {!r})\n".format(thisFunc, ret))
        return ret

    z.__name__ = f.__name__
    return z


empty = Empty().set_name("empty")
line_start = LineStart().set_name("line_start")
line_end = LineEnd().set_name("line_end")
string_start = StringStart().set_name("string_start")
string_end = StringEnd().set_name("string_end")

_escapedPunc = Word(_bslash, r"\[]-*.$+^?()~ ", exact=2).set_parse_action(
    lambda s, l, t: t[0][1]
)
_escapedHexChar = Regex(r"\\0?[xX][0-9a-fA-F]+").set_parse_action(
    lambda s, l, t: chr(int(t[0].lstrip(r"\0x"), 16))
)
_escapedOctChar = Regex(r"\\0[0-7]+").set_parse_action(
    lambda s, l, t: chr(int(t[0][1:], 8))
)
_singleChar = (
    _escapedPunc | _escapedHexChar | _escapedOctChar | CharsNotIn(r"\]", exact=1)
)
_charRange = Group(_singleChar + Suppress("-") + _singleChar)
_reBracketExpr = (
    Literal("[")
    + Opt("^").set_results_name("negate")
    + Group(OneOrMore(_charRange | _singleChar)).set_results_name("body")
    + "]"
)


def srange(s: str) -> str:
    _expanded = (
        lambda p: p
        if not isinstance(p, ParseResults)
        else "".join(chr(c) for c in range(ord(p[0]), ord(p[1]) + 1))
    )
    try:
        return "".join(_expanded(part) for part in _reBracketExpr.parse_string(s).body)
    except Exception:
        return ""


def token_map(func, *args) -> ParseAction:

    def pa(s, l, t):
        return [func(tokn, *args) for tokn in t]

    func_name = getattr(func, "__name__", getattr(func, "__class__").__name__)
    pa.__name__ = func_name

    return pa


def autoname_elements() -> None:
    for name, var in sys._getframe().f_back.f_locals.items():
        if isinstance(var, ParserElement) and not var.customName:
            var.set_name(name)


dbl_quoted_string = Combine(
    Regex(r'"(?:[^"\n\r\\]|(?:"")|(?:\\(?:[^x]|x[0-9a-fA-F]+)))*') + '"'
).set_name("string enclosed in double quotes")

sgl_quoted_string = Combine(
    Regex(r"'(?:[^'\n\r\\]|(?:'')|(?:\\(?:[^x]|x[0-9a-fA-F]+)))*") + "'"
).set_name("string enclosed in single quotes")

quoted_string = Combine(
    Regex(r'"(?:[^"\n\r\\]|(?:"")|(?:\\(?:[^x]|x[0-9a-fA-F]+)))*') + '"'
    | Regex(r"'(?:[^'\n\r\\]|(?:'')|(?:\\(?:[^x]|x[0-9a-fA-F]+)))*") + "'"
).set_name("quotedString using single or double quotes")

unicode_string = Combine("u" + quoted_string.copy()).set_name("unicode string literal")


alphas8bit = srange(r"[\0xc0-\0xd6\0xd8-\0xf6\0xf8-\0xff]")
punc8bit = srange(r"[\0xa1-\0xbf\0xd7\0xf7]")


_builtin_exprs = [v for v in vars().values() if isinstance(v, ParserElement)]


tokenMap = token_map
conditionAsParseAction = condition_as_parse_action
nullDebugAction = null_debug_action
sglQuotedString = sgl_quoted_string
dblQuotedString = dbl_quoted_string
quotedString = quoted_string
unicodeString = unicode_string
lineStart = line_start
lineEnd = line_end
stringStart = string_start
stringEnd = string_end
traceParseAction = trace_parse_action
