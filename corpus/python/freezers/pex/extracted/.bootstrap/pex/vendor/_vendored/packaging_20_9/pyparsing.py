# -*- coding: utf-8 -*-


__doc__ = \
"""
pyparsing module - Classes and methods to define and execute parsing grammars
=============================================================================

The pyparsing module is an alternative approach to creating and
executing simple grammars, vs. the traditional lex/yacc approach, or the
use of regular expressions.  With pyparsing, you don't need to learn
a new syntax for defining grammars or matching expressions - the parsing
module provides a library of classes that you use to construct the
grammar directly in Python.

Here is a program to parse "Hello, World!" (or any greeting of the form
``"<salutation>, <addressee>!"``), built up using :class:`Word`,
:class:`Literal`, and :class:`And` elements
(the :class:`'+'<ParserElement.__add__>` operators create :class:`And` expressions,
and the strings are auto-converted to :class:`Literal` expressions)::

    from pyparsing import Word, alphas

    # define grammar of a greeting
    greet = Word(alphas) + "," + Word(alphas) + "!"

    hello = "Hello, World!"
    print (hello, "->", greet.parseString(hello))

The program outputs the following::

    Hello, World! -> ['Hello', ',', 'World', '!']

The Python representation of the grammar is quite readable, owing to the
self-explanatory class names, and the use of '+', '|' and '^' operators.

The :class:`ParseResults` object returned from
:class:`ParserElement.parseString` can be
accessed as a nested list, a dictionary, or an object with named
attributes.

The pyparsing module handles some of the problems that are typically
vexing when writing text parsers:

  - extra or missing whitespace (the above program will also handle
    "Hello,World!", "Hello  ,  World  !", etc.)
  - quoted strings
  - embedded comments


Getting Started -
-----------------
Visit the classes :class:`ParserElement` and :class:`ParseResults` to
see the base classes that most other pyparsing
classes inherit from. Use the docstrings for examples of how to:

 - construct literal match expressions from :class:`Literal` and
   :class:`CaselessLiteral` classes
 - construct character word-group expressions using the :class:`Word`
   class
 - see how to create repetitive expressions using :class:`ZeroOrMore`
   and :class:`OneOrMore` classes
 - use :class:`'+'<And>`, :class:`'|'<MatchFirst>`, :class:`'^'<Or>`,
   and :class:`'&'<Each>` operators to combine simple expressions into
   more complex ones
 - associate names with your parsed results using
   :class:`ParserElement.setResultsName`
 - access the parsed data, which is returned as a :class:`ParseResults`
   object
 - find some helpful expression short-cuts like :class:`delimitedList`
   and :class:`oneOf`
 - find more useful common expressions in the :class:`pyparsing_common`
   namespace class
"""

__version__ = "2.4.7"
__versionTime__ = "30 Mar 2020 00:43 UTC"
__author__ = "Paul McGuire <ptmcg@users.sourceforge.net>"

import string
from weakref import ref as wkref
import copy
import sys
import warnings
import re
import sre_constants
import collections
import pprint
import traceback
import types
from datetime import datetime
from operator import itemgetter
import itertools
from functools import wraps
from contextlib import contextmanager

try:
    # Python 3
    from itertools import filterfalse
except ImportError:
    from itertools import ifilterfalse as filterfalse

try:
    from _thread import RLock
except ImportError:
    from threading import RLock

try:
    # Python 3
    from collections.abc import Iterable
    from collections.abc import MutableMapping, Mapping
except ImportError:
    # Python 2.7
    from collections import Iterable
    from collections import MutableMapping, Mapping

try:
    from collections import OrderedDict as _OrderedDict
except ImportError:
    try:
        from ordereddict import OrderedDict as _OrderedDict
    except ImportError:
        _OrderedDict = None

try:
    from types import SimpleNamespace
except ImportError:
    class SimpleNamespace: pass


__compat__ = SimpleNamespace()
__compat__.__doc__ = """
    A cross-version compatibility configuration for pyparsing features that will be
    released in a future version. By setting values in this configuration to True,
    those features can be enabled in prior versions for compatibility development
    and testing.

     - collect_all_And_tokens - flag to enable fix for Issue #63 that fixes erroneous grouping
       of results names when an And expression is nested within an Or or MatchFirst; set to
       True to enable bugfix released in pyparsing 2.3.0, or False to preserve
       pre-2.3.0 handling of named results
"""
__compat__.collect_all_And_tokens = True

__diag__ = SimpleNamespace()
__diag__.__doc__ = """
Diagnostic configuration (all default to False)
     - warn_multiple_tokens_in_named_alternation - flag to enable warnings when a results
       name is defined on a MatchFirst or Or expression with one or more And subexpressions
       (only warns if __compat__.collect_all_And_tokens is False)
     - warn_ungrouped_named_tokens_in_collection - flag to enable warnings when a results
       name is defined on a containing expression with ungrouped subexpressions that also
       have results names
     - warn_name_set_on_empty_Forward - flag to enable warnings whan a Forward is defined
       with a results name, but has no contents defined
     - warn_on_multiple_string_args_to_oneof - flag to enable warnings whan oneOf is
       incorrectly called with multiple str arguments
     - enable_debug_on_named_expressions - flag to auto-enable debug on all subsequent
       calls to ParserElement.setName()
"""
__diag__.warn_multiple_tokens_in_named_alternation = False
__diag__.warn_ungrouped_named_tokens_in_collection = False
__diag__.warn_name_set_on_empty_Forward = False
__diag__.warn_on_multiple_string_args_to_oneof = False
__diag__.enable_debug_on_named_expressions = False
__diag__._all_names = [nm for nm in vars(__diag__) if nm.startswith("enable_") or nm.startswith("warn_")]

def _enable_all_warnings():
    __diag__.warn_multiple_tokens_in_named_alternation = True
    __diag__.warn_ungrouped_named_tokens_in_collection = True
    __diag__.warn_name_set_on_empty_Forward = True
    __diag__.warn_on_multiple_string_args_to_oneof = True
__diag__.enable_all_warnings = _enable_all_warnings


__all__ = ['__version__', '__versionTime__', '__author__', '__compat__', '__diag__',
           'And', 'CaselessKeyword', 'CaselessLiteral', 'CharsNotIn', 'Combine', 'Dict', 'Each', 'Empty',
           'FollowedBy', 'Forward', 'GoToColumn', 'Group', 'Keyword', 'LineEnd', 'LineStart', 'Literal',
           'PrecededBy', 'MatchFirst', 'NoMatch', 'NotAny', 'OneOrMore', 'OnlyOnce', 'Optional', 'Or',
           'ParseBaseException', 'ParseElementEnhance', 'ParseException', 'ParseExpression', 'ParseFatalException',
           'ParseResults', 'ParseSyntaxException', 'ParserElement', 'QuotedString', 'RecursiveGrammarException',
           'Regex', 'SkipTo', 'StringEnd', 'StringStart', 'Suppress', 'Token', 'TokenConverter',
           'White', 'Word', 'WordEnd', 'WordStart', 'ZeroOrMore', 'Char',
           'alphanums', 'alphas', 'alphas8bit', 'anyCloseTag', 'anyOpenTag', 'cStyleComment', 'col',
           'commaSeparatedList', 'commonHTMLEntity', 'countedArray', 'cppStyleComment', 'dblQuotedString',
           'dblSlashComment', 'delimitedList', 'dictOf', 'downcaseTokens', 'empty', 'hexnums',
           'htmlComment', 'javaStyleComment', 'line', 'lineEnd', 'lineStart', 'lineno',
           'makeHTMLTags', 'makeXMLTags', 'matchOnlyAtCol', 'matchPreviousExpr', 'matchPreviousLiteral',
           'nestedExpr', 'nullDebugAction', 'nums', 'oneOf', 'opAssoc', 'operatorPrecedence', 'printables',
           'punc8bit', 'pythonStyleComment', 'quotedString', 'removeQuotes', 'replaceHTMLEntity',
           'replaceWith', 'restOfLine', 'sglQuotedString', 'srange', 'stringEnd',
           'stringStart', 'traceParseAction', 'unicodeString', 'upcaseTokens', 'withAttribute',
           'indentedBlock', 'originalTextFor', 'ungroup', 'infixNotation', 'locatedExpr', 'withClass',
           'CloseMatch', 'tokenMap', 'pyparsing_common', 'pyparsing_unicode', 'unicode_set',
           'conditionAsParseAction', 're',
           ]

system_version = tuple(sys.version_info)[:3]
PY_3 = system_version[0] == 3
if PY_3:
    _MAX_INT = sys.maxsize
    basestring = str
    unichr = chr
    unicode = str
    _ustr = str


    singleArgBuiltins = [sum, len, sorted, reversed, list, tuple, set, any, all, min, max]

else:
    _MAX_INT = sys.maxint
    range = xrange

    def _ustr(obj):
        if isinstance(obj, unicode):
            return obj

        try:


            return str(obj)

        except UnicodeEncodeError:

            ret = unicode(obj).encode(sys.getdefaultencoding(), 'xmlcharrefreplace')
            xmlcharref = Regex(r'&#\d+;')
            xmlcharref.setParseAction(lambda t: '\\u' + hex(int(t[0][2:-1]))[2:])
            return xmlcharref.transformString(ret)


    singleArgBuiltins = []
    import __builtin__

    for fname in "sum len sorted reversed list tuple set any all min max".split():
        try:
            singleArgBuiltins.append(getattr(__builtin__, fname))
        except AttributeError:
            continue

_generatorType = type((y for y in range(1)))

def _xml_escape(data):


    from_symbols = '&><"\''
    to_symbols = ('&' + s + ';' for s in "amp gt lt quot apos".split())
    for from_, to_ in zip(from_symbols, to_symbols):
        data = data.replace(from_, to_)
    return data

alphas = string.ascii_uppercase + string.ascii_lowercase
nums = "0123456789"
hexnums = nums + "ABCDEFabcdef"
alphanums = alphas + nums
_bslash = chr(92)
printables = "".join(c for c in string.printable if c not in string.whitespace)


def conditionAsParseAction(fn, message=None, fatal=False):
    msg = message if message is not None else "failed user-defined condition"
    exc_type = ParseFatalException if fatal else ParseException
    fn = _trim_arity(fn)

    @wraps(fn)
    def pa(s, l, t):
        if not bool(fn(s, l, t)):
            raise exc_type(s, l, msg)

    return pa

class ParseBaseException(Exception):


    def __init__(self, pstr, loc=0, msg=None, elem=None):
        self.loc = loc
        if msg is None:
            self.msg = pstr
            self.pstr = ""
        else:
            self.msg = msg
            self.pstr = pstr
        self.parserElement = elem
        self.args = (pstr, loc, msg)

    @classmethod
    def _from_exception(cls, pe):
        return cls(pe.pstr, pe.loc, pe.msg, pe.parserElement)

    def __getattr__(self, aname):
        if aname == "lineno":
            return lineno(self.loc, self.pstr)
        elif aname in ("col", "column"):
            return col(self.loc, self.pstr)
        elif aname == "line":
            return line(self.loc, self.pstr)
        else:
            raise AttributeError(aname)

    def __str__(self):
        if self.pstr:
            if self.loc >= len(self.pstr):
                foundstr = ', found end of text'
            else:
                foundstr = (', found %r' % self.pstr[self.loc:self.loc + 1]).replace(r'\\', '\\')
        else:
            foundstr = ''
        return ("%s%s  (at char %d), (line:%d, col:%d)" %
                   (self.msg, foundstr, self.loc, self.lineno, self.column))
    def __repr__(self):
        return _ustr(self)
    def markInputline(self, markerString=">!<"):
        line_str = self.line
        line_column = self.column - 1
        if markerString:
            line_str = "".join((line_str[:line_column],
                                markerString, line_str[line_column:]))
        return line_str.strip()
    def __dir__(self):
        return "lineno col line".split() + dir(type(self))

class ParseException(ParseBaseException):

    @staticmethod
    def explain(exc, depth=16):
        import inspect

        if depth is None:
            depth = sys.getrecursionlimit()
        ret = []
        if isinstance(exc, ParseBaseException):
            ret.append(exc.line)
            ret.append(' ' * (exc.col - 1) + '^')
        ret.append("{0}: {1}".format(type(exc).__name__, exc))

        if depth > 0:
            callers = inspect.getinnerframes(exc.__traceback__, context=depth)
            seen = set()
            for i, ff in enumerate(callers[-depth:]):
                frm = ff[0]

                f_self = frm.f_locals.get('self', None)
                if isinstance(f_self, ParserElement):
                    if frm.f_code.co_name not in ('parseImpl', '_parseNoCache'):
                        continue
                    if f_self in seen:
                        continue
                    seen.add(f_self)

                    self_type = type(f_self)
                    ret.append("{0}.{1} - {2}".format(self_type.__module__,
                                                      self_type.__name__,
                                                      f_self))
                elif f_self is not None:
                    self_type = type(f_self)
                    ret.append("{0}.{1}".format(self_type.__module__,
                                                self_type.__name__))
                else:
                    code = frm.f_code
                    if code.co_name in ('wrapper', '<module>'):
                        continue

                    ret.append("{0}".format(code.co_name))

                depth -= 1
                if not depth:
                    break

        return '\n'.join(ret)


class ParseFatalException(ParseBaseException):
    pass

class ParseSyntaxException(ParseFatalException):
    pass


class RecursiveGrammarException(Exception):
    def __init__(self, parseElementList):
        self.parseElementTrace = parseElementList

    def __str__(self):
        return "RecursiveGrammarException: %s" % self.parseElementTrace

class _ParseResultsWithOffset(object):
    def __init__(self, p1, p2):
        self.tup = (p1, p2)
    def __getitem__(self, i):
        return self.tup[i]
    def __repr__(self):
        return repr(self.tup[0])
    def setOffset(self, i):
        self.tup = (self.tup[0], i)

class ParseResults(object):
    def __new__(cls, toklist=None, name=None, asList=True, modal=True):
        if isinstance(toklist, cls):
            return toklist
        retobj = object.__new__(cls)
        retobj.__doinit = True
        return retobj


    def __init__(self, toklist=None, name=None, asList=True, modal=True, isinstance=isinstance):
        if self.__doinit:
            self.__doinit = False
            self.__name = None
            self.__parent = None
            self.__accumNames = {}
            self.__asList = asList
            self.__modal = modal
            if toklist is None:
                toklist = []
            if isinstance(toklist, list):
                self.__toklist = toklist[:]
            elif isinstance(toklist, _generatorType):
                self.__toklist = list(toklist)
            else:
                self.__toklist = [toklist]
            self.__tokdict = dict()

        if name is not None and name:
            if not modal:
                self.__accumNames[name] = 0
            if isinstance(name, int):
                name = _ustr(name)
            self.__name = name
            if not (isinstance(toklist, (type(None), basestring, list)) and toklist in (None, '', [])):
                if isinstance(toklist, basestring):
                    toklist = [toklist]
                if asList:
                    if isinstance(toklist, ParseResults):
                        self[name] = _ParseResultsWithOffset(ParseResults(toklist.__toklist), 0)
                    else:
                        self[name] = _ParseResultsWithOffset(ParseResults(toklist[0]), 0)
                    self[name].__name = name
                else:
                    try:
                        self[name] = toklist[0]
                    except (KeyError, TypeError, IndexError):
                        self[name] = toklist

    def __getitem__(self, i):
        if isinstance(i, (int, slice)):
            return self.__toklist[i]
        else:
            if i not in self.__accumNames:
                return self.__tokdict[i][-1][0]
            else:
                return ParseResults([v[0] for v in self.__tokdict[i]])

    def __setitem__(self, k, v, isinstance=isinstance):
        if isinstance(v, _ParseResultsWithOffset):
            self.__tokdict[k] = self.__tokdict.get(k, list()) + [v]
            sub = v[0]
        elif isinstance(k, (int, slice)):
            self.__toklist[k] = v
            sub = v
        else:
            self.__tokdict[k] = self.__tokdict.get(k, list()) + [_ParseResultsWithOffset(v, 0)]
            sub = v
        if isinstance(sub, ParseResults):
            sub.__parent = wkref(self)

    def __delitem__(self, i):
        if isinstance(i, (int, slice)):
            mylen = len(self.__toklist)
            del self.__toklist[i]


            if isinstance(i, int):
                if i < 0:
                    i += mylen
                i = slice(i, i + 1)

            removed = list(range(*i.indices(mylen)))
            removed.reverse()

            for name, occurrences in self.__tokdict.items():
                for j in removed:
                    for k, (value, position) in enumerate(occurrences):
                        occurrences[k] = _ParseResultsWithOffset(value, position - (position > j))
        else:
            del self.__tokdict[i]

    def __contains__(self, k):
        return k in self.__tokdict

    def __len__(self):
        return len(self.__toklist)

    def __bool__(self):
        return (not not self.__toklist)
    __nonzero__ = __bool__

    def __iter__(self):
        return iter(self.__toklist)

    def __reversed__(self):
        return iter(self.__toklist[::-1])

    def _iterkeys(self):
        if hasattr(self.__tokdict, "iterkeys"):
            return self.__tokdict.iterkeys()
        else:
            return iter(self.__tokdict)

    def _itervalues(self):
        return (self[k] for k in self._iterkeys())

    def _iteritems(self):
        return ((k, self[k]) for k in self._iterkeys())

    if PY_3:
        keys = _iterkeys
        """Returns an iterator of all named result keys."""

        values = _itervalues
        """Returns an iterator of all named result values."""

        items = _iteritems
        """Returns an iterator of all named result key-value tuples."""

    else:
        iterkeys = _iterkeys
        """Returns an iterator of all named result keys (Python 2.x only)."""

        itervalues = _itervalues
        """Returns an iterator of all named result values (Python 2.x only)."""

        iteritems = _iteritems
        """Returns an iterator of all named result key-value tuples (Python 2.x only)."""

        def keys(self):
            return list(self.iterkeys())

        def values(self):
            return list(self.itervalues())

        def items(self):
            return list(self.iteritems())

    def haskeys(self):
        return bool(self.__tokdict)

    def pop(self, *args, **kwargs):
        if not args:
            args = [-1]
        for k, v in kwargs.items():
            if k == 'default':
                args = (args[0], v)
            else:
                raise TypeError("pop() got an unexpected keyword argument '%s'" % k)
        if (isinstance(args[0], int)
                or len(args) == 1
                or args[0] in self):
            index = args[0]
            ret = self[index]
            del self[index]
            return ret
        else:
            defaultvalue = args[1]
            return defaultvalue

    def get(self, key, defaultValue=None):
        if key in self:
            return self[key]
        else:
            return defaultValue

    def insert(self, index, insStr):
        self.__toklist.insert(index, insStr)

        for name, occurrences in self.__tokdict.items():
            for k, (value, position) in enumerate(occurrences):
                occurrences[k] = _ParseResultsWithOffset(value, position + (position > index))

    def append(self, item):
        self.__toklist.append(item)

    def extend(self, itemseq):
        if isinstance(itemseq, ParseResults):
            self.__iadd__(itemseq)
        else:
            self.__toklist.extend(itemseq)

    def clear(self):
        del self.__toklist[:]
        self.__tokdict.clear()

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            return ""

    def __add__(self, other):
        ret = self.copy()
        ret += other
        return ret

    def __iadd__(self, other):
        if other.__tokdict:
            offset = len(self.__toklist)
            addoffset = lambda a: offset if a < 0 else a + offset
            otheritems = other.__tokdict.items()
            otherdictitems = [(k, _ParseResultsWithOffset(v[0], addoffset(v[1])))
                              for k, vlist in otheritems for v in vlist]
            for k, v in otherdictitems:
                self[k] = v
                if isinstance(v[0], ParseResults):
                    v[0].__parent = wkref(self)

        self.__toklist += other.__toklist
        self.__accumNames.update(other.__accumNames)
        return self

    def __radd__(self, other):
        if isinstance(other, int) and other == 0:

            return self.copy()
        else:

            return other + self

    def __repr__(self):
        return "(%s, %s)" % (repr(self.__toklist), repr(self.__tokdict))

    def __str__(self):
        return '[' + ', '.join(_ustr(i) if isinstance(i, ParseResults) else repr(i) for i in self.__toklist) + ']'

    def _asStringList(self, sep=''):
        out = []
        for item in self.__toklist:
            if out and sep:
                out.append(sep)
            if isinstance(item, ParseResults):
                out += item._asStringList()
            else:
                out.append(_ustr(item))
        return out

    def asList(self):
        return [res.asList() if isinstance(res, ParseResults) else res for res in self.__toklist]

    def asDict(self):
        if PY_3:
            item_fn = self.items
        else:
            item_fn = self.iteritems

        def toItem(obj):
            if isinstance(obj, ParseResults):
                if obj.haskeys():
                    return obj.asDict()
                else:
                    return [toItem(v) for v in obj]
            else:
                return obj

        return dict((k, toItem(v)) for k, v in item_fn())

    def copy(self):
        ret = ParseResults(self.__toklist)
        ret.__tokdict = dict(self.__tokdict.items())
        ret.__parent = self.__parent
        ret.__accumNames.update(self.__accumNames)
        ret.__name = self.__name
        return ret

    def asXML(self, doctag=None, namedItemsOnly=False, indent="", formatted=True):
        nl = "\n"
        out = []
        namedItems = dict((v[1], k) for (k, vlist) in self.__tokdict.items()
                          for v in vlist)
        nextLevelIndent = indent + "  "


        if not formatted:
            indent = ""
            nextLevelIndent = ""
            nl = ""

        selfTag = None
        if doctag is not None:
            selfTag = doctag
        else:
            if self.__name:
                selfTag = self.__name

        if not selfTag:
            if namedItemsOnly:
                return ""
            else:
                selfTag = "ITEM"

        out += [nl, indent, "<", selfTag, ">"]

        for i, res in enumerate(self.__toklist):
            if isinstance(res, ParseResults):
                if i in namedItems:
                    out += [res.asXML(namedItems[i],
                                      namedItemsOnly and doctag is None,
                                      nextLevelIndent,
                                      formatted)]
                else:
                    out += [res.asXML(None,
                                      namedItemsOnly and doctag is None,
                                      nextLevelIndent,
                                      formatted)]
            else:

                resTag = None
                if i in namedItems:
                    resTag = namedItems[i]
                if not resTag:
                    if namedItemsOnly:
                        continue
                    else:
                        resTag = "ITEM"
                xmlBodyText = _xml_escape(_ustr(res))
                out += [nl, nextLevelIndent, "<", resTag, ">",
                        xmlBodyText,
                                                "</", resTag, ">"]

        out += [nl, indent, "</", selfTag, ">"]
        return "".join(out)

    def __lookup(self, sub):
        for k, vlist in self.__tokdict.items():
            for v, loc in vlist:
                if sub is v:
                    return k
        return None

    def getName(self):
        if self.__name:
            return self.__name
        elif self.__parent:
            par = self.__parent()
            if par:
                return par.__lookup(self)
            else:
                return None
        elif (len(self) == 1
              and len(self.__tokdict) == 1
              and next(iter(self.__tokdict.values()))[0][1] in (0, -1)):
            return next(iter(self.__tokdict.keys()))
        else:
            return None

    def dump(self, indent='', full=True, include_list=True, _depth=0):
        out = []
        NL = '\n'
        if include_list:
            out.append(indent + _ustr(self.asList()))
        else:
            out.append('')

        if full:
            if self.haskeys():
                items = sorted((str(k), v) for k, v in self.items())
                for k, v in items:
                    if out:
                        out.append(NL)
                    out.append("%s%s- %s: " % (indent, ('  ' * _depth), k))
                    if isinstance(v, ParseResults):
                        if v:
                            out.append(v.dump(indent=indent, full=full, include_list=include_list, _depth=_depth + 1))
                        else:
                            out.append(_ustr(v))
                    else:
                        out.append(repr(v))
            elif any(isinstance(vv, ParseResults) for vv in self):
                v = self
                for i, vv in enumerate(v):
                    if isinstance(vv, ParseResults):
                        out.append("\n%s%s[%d]:\n%s%s%s" % (indent,
                                                            ('  ' * (_depth)),
                                                            i,
                                                            indent,
                                                            ('  ' * (_depth + 1)),
                                                            vv.dump(indent=indent,
                                                                    full=full,
                                                                    include_list=include_list,
                                                                    _depth=_depth + 1)))
                    else:
                        out.append("\n%s%s[%d]:\n%s%s%s" % (indent,
                                                            ('  ' * (_depth)),
                                                            i,
                                                            indent,
                                                            ('  ' * (_depth + 1)),
                                                            _ustr(vv)))

        return "".join(out)

    def pprint(self, *args, **kwargs):
        pprint.pprint(self.asList(), *args, **kwargs)


    def __getstate__(self):
        return (self.__toklist,
                (self.__tokdict.copy(),
                 self.__parent is not None and self.__parent() or None,
                 self.__accumNames,
                 self.__name))

    def __setstate__(self, state):
        self.__toklist = state[0]
        self.__tokdict, par, inAccumNames, self.__name = state[1]
        self.__accumNames = {}
        self.__accumNames.update(inAccumNames)
        if par is not None:
            self.__parent = wkref(par)
        else:
            self.__parent = None

    def __getnewargs__(self):
        return self.__toklist, self.__name, self.__asList, self.__modal

    def __dir__(self):
        return dir(type(self)) + list(self.keys())

    @classmethod
    def from_dict(cls, other, name=None):
        def is_iterable(obj):
            try:
                iter(obj)
            except Exception:
                return False
            else:
                if PY_3:
                    return not isinstance(obj, (str, bytes))
                else:
                    return not isinstance(obj, basestring)

        ret = cls([])
        for k, v in other.items():
            if isinstance(v, Mapping):
                ret += cls.from_dict(v, name=k)
            else:
                ret += cls([v], name=k, asList=is_iterable(v))
        if name is not None:
            ret = cls([ret], name=name)
        return ret

MutableMapping.register(ParseResults)

def col (loc, strg):
    s = strg
    return 1 if 0 < loc < len(s) and s[loc-1] == '\n' else loc - s.rfind("\n", 0, loc)

def lineno(loc, strg):
    return strg.count("\n", 0, loc) + 1

def line(loc, strg):
    lastCR = strg.rfind("\n", 0, loc)
    nextCR = strg.find("\n", loc)
    if nextCR >= 0:
        return strg[lastCR + 1:nextCR]
    else:
        return strg[lastCR + 1:]

def _defaultStartDebugAction(instring, loc, expr):
    print(("Match " + _ustr(expr) + " at loc " + _ustr(loc) + "(%d,%d)" % (lineno(loc, instring), col(loc, instring))))

def _defaultSuccessDebugAction(instring, startloc, endloc, expr, toks):
    print("Matched " + _ustr(expr) + " -> " + str(toks.asList()))

def _defaultExceptionDebugAction(instring, loc, expr, exc):
    print("Exception raised:" + _ustr(exc))

def nullDebugAction(*args):
    pass


'decorator to trim function calls to match the arity of the target'
def _trim_arity(func, maxargs=2):
    if func in singleArgBuiltins:
        return lambda s, l, t: func(t)
    limit = [0]
    foundArity = [False]


    if system_version[:2] >= (3, 5):
        def extract_stack(limit=0):

            offset = -3 if system_version == (3, 5, 0) else -2
            frame_summary = traceback.extract_stack(limit=-offset + limit - 1)[offset]
            return [frame_summary[:2]]
        def extract_tb(tb, limit=0):
            frames = traceback.extract_tb(tb, limit=limit)
            frame_summary = frames[-1]
            return [frame_summary[:2]]
    else:
        extract_stack = traceback.extract_stack
        extract_tb = traceback.extract_tb


    LINE_DIFF = 6


    this_line = extract_stack(limit=2)[-1]
    pa_call_line_synth = (this_line[0], this_line[1] + LINE_DIFF)

    def wrapper(*args):
        while 1:
            try:
                ret = func(*args[limit[0]:])
                foundArity[0] = True
                return ret
            except TypeError:

                if foundArity[0]:
                    raise
                else:
                    try:
                        tb = sys.exc_info()[-1]
                        if not extract_tb(tb, limit=2)[-1][:2] == pa_call_line_synth:
                            raise
                    finally:
                        try:
                            del tb
                        except NameError:
                            pass

                if limit[0] <= maxargs:
                    limit[0] += 1
                    continue
                raise


    func_name = "<parse action>"
    try:
        func_name = getattr(func, '__name__',
                            getattr(func, '__class__').__name__)
    except Exception:
        func_name = str(func)
    wrapper.__name__ = func_name

    return wrapper


class ParserElement(object):
    DEFAULT_WHITE_CHARS = " \n\t\r"
    verbose_stacktrace = False

    @staticmethod
    def setDefaultWhitespaceChars(chars):
        ParserElement.DEFAULT_WHITE_CHARS = chars

    @staticmethod
    def inlineLiteralsUsing(cls):
        ParserElement._literalStringClass = cls

    @classmethod
    def _trim_traceback(cls, tb):
        while tb.tb_next:
            tb = tb.tb_next
        return tb

    def __init__(self, savelist=False):
        self.parseAction = list()
        self.failAction = None

        self.strRepr = None
        self.resultsName = None
        self.saveAsList = savelist
        self.skipWhitespace = True
        self.whiteChars = set(ParserElement.DEFAULT_WHITE_CHARS)
        self.copyDefaultWhiteChars = True
        self.mayReturnEmpty = False
        self.keepTabs = False
        self.ignoreExprs = list()
        self.debug = False
        self.streamlined = False
        self.mayIndexError = True
        self.errmsg = ""
        self.modalResults = True
        self.debugActions = (None, None, None)
        self.re = None
        self.callPreparse = True
        self.callDuringTry = False

    def copy(self):
        cpy = copy.copy(self)
        cpy.parseAction = self.parseAction[:]
        cpy.ignoreExprs = self.ignoreExprs[:]
        if self.copyDefaultWhiteChars:
            cpy.whiteChars = ParserElement.DEFAULT_WHITE_CHARS
        return cpy

    def setName(self, name):
        self.name = name
        self.errmsg = "Expected " + self.name
        if __diag__.enable_debug_on_named_expressions:
            self.setDebug()
        return self

    def setResultsName(self, name, listAllMatches=False):
        return self._setResultsName(name, listAllMatches)

    def _setResultsName(self, name, listAllMatches=False):
        newself = self.copy()
        if name.endswith("*"):
            name = name[:-1]
            listAllMatches = True
        newself.resultsName = name
        newself.modalResults = not listAllMatches
        return newself

    def setBreak(self, breakFlag=True):
        if breakFlag:
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

    def setParseAction(self, *fns, **kwargs):
        if list(fns) == [None,]:
            self.parseAction = []
        else:
            if not all(callable(fn) for fn in fns):
                raise TypeError("parse actions must be callable")
            self.parseAction = list(map(_trim_arity, list(fns)))
            self.callDuringTry = kwargs.get("callDuringTry", False)
        return self

    def addParseAction(self, *fns, **kwargs):
        self.parseAction += list(map(_trim_arity, list(fns)))
        self.callDuringTry = self.callDuringTry or kwargs.get("callDuringTry", False)
        return self

    def addCondition(self, *fns, **kwargs):
        for fn in fns:
            self.parseAction.append(conditionAsParseAction(fn, message=kwargs.get('message'),
                                                           fatal=kwargs.get('fatal', False)))

        self.callDuringTry = self.callDuringTry or kwargs.get("callDuringTry", False)
        return self

    def setFailAction(self, fn):
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
            wt = self.whiteChars
            instrlen = len(instring)
            while loc < instrlen and instring[loc] in wt:
                loc += 1

        return loc

    def parseImpl(self, instring, loc, doActions=True):
        return loc, []

    def postParse(self, instring, loc, tokenlist):
        return tokenlist


    def _parseNoCache(self, instring, loc, doActions=True, callPreParse=True):
        TRY, MATCH, FAIL = 0, 1, 2
        debugging = (self.debug)

        if debugging or self.failAction:

            if self.debugActions[TRY]:
                self.debugActions[TRY](instring, loc, self)
            try:
                if callPreParse and self.callPreparse:
                    preloc = self.preParse(instring, loc)
                else:
                    preloc = loc
                tokensStart = preloc
                if self.mayIndexError or preloc >= len(instring):
                    try:
                        loc, tokens = self.parseImpl(instring, preloc, doActions)
                    except IndexError:
                        raise ParseException(instring, len(instring), self.errmsg, self)
                else:
                    loc, tokens = self.parseImpl(instring, preloc, doActions)
            except Exception as err:

                if self.debugActions[FAIL]:
                    self.debugActions[FAIL](instring, tokensStart, self, err)
                if self.failAction:
                    self.failAction(instring, tokensStart, self, err)
                raise
        else:
            if callPreParse and self.callPreparse:
                preloc = self.preParse(instring, loc)
            else:
                preloc = loc
            tokensStart = preloc
            if self.mayIndexError or preloc >= len(instring):
                try:
                    loc, tokens = self.parseImpl(instring, preloc, doActions)
                except IndexError:
                    raise ParseException(instring, len(instring), self.errmsg, self)
            else:
                loc, tokens = self.parseImpl(instring, preloc, doActions)

        tokens = self.postParse(instring, loc, tokens)

        retTokens = ParseResults(tokens, self.resultsName, asList=self.saveAsList, modal=self.modalResults)
        if self.parseAction and (doActions or self.callDuringTry):
            if debugging:
                try:
                    for fn in self.parseAction:
                        try:
                            tokens = fn(instring, tokensStart, retTokens)
                        except IndexError as parse_action_exc:
                            exc = ParseException("exception raised in parse action")
                            exc.__cause__ = parse_action_exc
                            raise exc

                        if tokens is not None and tokens is not retTokens:
                            retTokens = ParseResults(tokens,
                                                      self.resultsName,
                                                      asList=self.saveAsList and isinstance(tokens, (ParseResults, list)),
                                                      modal=self.modalResults)
                except Exception as err:

                    if self.debugActions[FAIL]:
                        self.debugActions[FAIL](instring, tokensStart, self, err)
                    raise
            else:
                for fn in self.parseAction:
                    try:
                        tokens = fn(instring, tokensStart, retTokens)
                    except IndexError as parse_action_exc:
                        exc = ParseException("exception raised in parse action")
                        exc.__cause__ = parse_action_exc
                        raise exc

                    if tokens is not None and tokens is not retTokens:
                        retTokens = ParseResults(tokens,
                                                  self.resultsName,
                                                  asList=self.saveAsList and isinstance(tokens, (ParseResults, list)),
                                                  modal=self.modalResults)
        if debugging:

            if self.debugActions[MATCH]:
                self.debugActions[MATCH](instring, tokensStart, loc, self, retTokens)

        return loc, retTokens

    def tryParse(self, instring, loc):
        try:
            return self._parse(instring, loc, doActions=False)[0]
        except ParseFatalException:
            raise ParseException(instring, loc, self.errmsg, self)

    def canParseNext(self, instring, loc):
        try:
            self.tryParse(instring, loc)
        except (ParseException, IndexError):
            return False
        else:
            return True

    class _UnboundedCache(object):
        def __init__(self):
            cache = {}
            self.not_in_cache = not_in_cache = object()

            def get(self, key):
                return cache.get(key, not_in_cache)

            def set(self, key, value):
                cache[key] = value

            def clear(self):
                cache.clear()

            def cache_len(self):
                return len(cache)

            self.get = types.MethodType(get, self)
            self.set = types.MethodType(set, self)
            self.clear = types.MethodType(clear, self)
            self.__len__ = types.MethodType(cache_len, self)

    if _OrderedDict is not None:
        class _FifoCache(object):
            def __init__(self, size):
                self.not_in_cache = not_in_cache = object()

                cache = _OrderedDict()

                def get(self, key):
                    return cache.get(key, not_in_cache)

                def set(self, key, value):
                    cache[key] = value
                    while len(cache) > size:
                        try:
                            cache.popitem(False)
                        except KeyError:
                            pass

                def clear(self):
                    cache.clear()

                def cache_len(self):
                    return len(cache)

                self.get = types.MethodType(get, self)
                self.set = types.MethodType(set, self)
                self.clear = types.MethodType(clear, self)
                self.__len__ = types.MethodType(cache_len, self)

    else:
        class _FifoCache(object):
            def __init__(self, size):
                self.not_in_cache = not_in_cache = object()

                cache = {}
                key_fifo = collections.deque([], size)

                def get(self, key):
                    return cache.get(key, not_in_cache)

                def set(self, key, value):
                    cache[key] = value
                    while len(key_fifo) > size:
                        cache.pop(key_fifo.popleft(), None)
                    key_fifo.append(key)

                def clear(self):
                    cache.clear()
                    key_fifo.clear()

                def cache_len(self):
                    return len(cache)

                self.get = types.MethodType(get, self)
                self.set = types.MethodType(set, self)
                self.clear = types.MethodType(clear, self)
                self.__len__ = types.MethodType(cache_len, self)


    packrat_cache = {}
    packrat_cache_lock = RLock()
    packrat_cache_stats = [0, 0]


    def _parseCache(self, instring, loc, doActions=True, callPreParse=True):
        HIT, MISS = 0, 1
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
                    cache.set(lookup, (value[0], value[1].copy()))
                    return value
            else:
                ParserElement.packrat_cache_stats[HIT] += 1
                if isinstance(value, Exception):
                    raise value
                return value[0], value[1].copy()

    _parse = _parseNoCache

    @staticmethod
    def resetCache():
        ParserElement.packrat_cache.clear()
        ParserElement.packrat_cache_stats[:] = [0] * len(ParserElement.packrat_cache_stats)

    _packratEnabled = False
    @staticmethod
    def enablePackrat(cache_size_limit=128):
        if not ParserElement._packratEnabled:
            ParserElement._packratEnabled = True
            if cache_size_limit is None:
                ParserElement.packrat_cache = ParserElement._UnboundedCache()
            else:
                ParserElement.packrat_cache = ParserElement._FifoCache(cache_size_limit)
            ParserElement._parse = ParserElement._parseCache

    def parseString(self, instring, parseAll=False):
        ParserElement.resetCache()
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

                if getattr(exc, '__traceback__', None) is not None:
                    exc.__traceback__ = self._trim_traceback(exc.__traceback__)
                raise exc
        else:
            return tokens

    def scanString(self, instring, maxMatches=_MAX_INT, overlap=False):
        if not self.streamlined:
            self.streamline()
        for e in self.ignoreExprs:
            e.streamline()

        if not self.keepTabs:
            instring = _ustr(instring).expandtabs()
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

                if getattr(exc, '__traceback__', None) is not None:
                    exc.__traceback__ = self._trim_traceback(exc.__traceback__)
                raise exc

    def transformString(self, instring):
        out = []
        lastE = 0


        self.keepTabs = True
        try:
            for t, s, e in self.scanString(instring):
                out.append(instring[lastE:s])
                if t:
                    if isinstance(t, ParseResults):
                        out += t.asList()
                    elif isinstance(t, list):
                        out += t
                    else:
                        out.append(t)
                lastE = e
            out.append(instring[lastE:])
            out = [o for o in out if o]
            return "".join(map(_ustr, _flatten(out)))
        except ParseBaseException as exc:
            if ParserElement.verbose_stacktrace:
                raise
            else:

                if getattr(exc, '__traceback__', None) is not None:
                    exc.__traceback__ = self._trim_traceback(exc.__traceback__)
                raise exc

    def searchString(self, instring, maxMatches=_MAX_INT):
        try:
            return ParseResults([t for t, s, e in self.scanString(instring, maxMatches)])
        except ParseBaseException as exc:
            if ParserElement.verbose_stacktrace:
                raise
            else:

                if getattr(exc, '__traceback__', None) is not None:
                    exc.__traceback__ = self._trim_traceback(exc.__traceback__)
                raise exc

    def split(self, instring, maxsplit=_MAX_INT, includeSeparators=False):
        splits = 0
        last = 0
        for t, s, e in self.scanString(instring, maxMatches=maxsplit):
            yield instring[last:s]
            if includeSeparators:
                yield t[0]
            last = e
        yield instring[last:]

    def __add__(self, other):
        if other is Ellipsis:
            return _PendingSkip(self)

        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return And([self, other])

    def __radd__(self, other):
        if other is Ellipsis:
            return SkipTo(self)("_skipped*") + self

        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return other + self

    def __sub__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return self + And._ErrorStop() + other

    def __rsub__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return other - self

    def __mul__(self, other):
        if other is Ellipsis:
            other = (0, None)
        elif isinstance(other, tuple) and other[:1] == (Ellipsis,):
            other = ((0, ) + other[1:] + (None,))[:2]

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
                raise TypeError("cannot multiply 'ParserElement' and ('%s', '%s') objects", type(other[0]), type(other[1]))
        else:
            raise TypeError("cannot multiply 'ParserElement' and '%s' objects", type(other))

        if minElements < 0:
            raise ValueError("cannot multiply ParserElement by negative value")
        if optElements < 0:
            raise ValueError("second tuple value must be greater or equal to first tuple value")
        if minElements == optElements == 0:
            raise ValueError("cannot multiply ParserElement by 0 or (0, 0)")

        if optElements:
            def makeOptionalList(n):
                if n > 1:
                    return Optional(self + makeOptionalList(n - 1))
                else:
                    return Optional(self)
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

        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return MatchFirst([self, other])

    def __ror__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return other | self

    def __xor__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return Or([self, other])

    def __rxor__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return other ^ self

    def __and__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return Each([self, other])

    def __rand__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        if not isinstance(other, ParserElement):
            warnings.warn("Cannot combine element of type %s with ParserElement" % type(other),
                          SyntaxWarning, stacklevel=2)
            return None
        return other & self

    def __invert__(self):
        return NotAny(self)

    def __iter__(self):


        raise TypeError('%r object is not iterable' % self.__class__.__name__)

    def __getitem__(self, key):


        try:
            if isinstance(key, str):
                key = (key,)
            iter(key)
        except TypeError:
            key = (key, key)

        if len(key) > 2:
            warnings.warn("only 1 or 2 index arguments supported ({0}{1})".format(key[:5],
                                                                                '... [{0}]'.format(len(key))
                                                                                if len(key) > 5 else ''))


        ret = self * tuple(key[:2])
        return ret

    def __call__(self, name=None):
        if name is not None:
            return self._setResultsName(name)
        else:
            return self.copy()

    def suppress(self):
        return Suppress(self)

    def leaveWhitespace(self):
        self.skipWhitespace = False
        return self

    def setWhitespaceChars(self, chars):
        self.skipWhitespace = True
        self.whiteChars = chars
        self.copyDefaultWhiteChars = False
        return self

    def parseWithTabs(self):
        self.keepTabs = True
        return self

    def ignore(self, other):
        if isinstance(other, basestring):
            other = Suppress(other)

        if isinstance(other, Suppress):
            if other not in self.ignoreExprs:
                self.ignoreExprs.append(other)
        else:
            self.ignoreExprs.append(Suppress(other.copy()))
        return self

    def setDebugActions(self, startAction, successAction, exceptionAction):
        self.debugActions = (startAction or _defaultStartDebugAction,
                             successAction or _defaultSuccessDebugAction,
                             exceptionAction or _defaultExceptionDebugAction)
        self.debug = True
        return self

    def setDebug(self, flag=True):
        if flag:
            self.setDebugActions(_defaultStartDebugAction, _defaultSuccessDebugAction, _defaultExceptionDebugAction)
        else:
            self.debug = False
        return self

    def __str__(self):
        return self.name

    def __repr__(self):
        return _ustr(self)

    def streamline(self):
        self.streamlined = True
        self.strRepr = None
        return self

    def checkRecursion(self, parseElementList):
        pass

    def validate(self, validateTrace=None):
        self.checkRecursion([])

    def parseFile(self, file_or_filename, parseAll=False):
        try:
            file_contents = file_or_filename.read()
        except AttributeError:
            with open(file_or_filename, "r") as f:
                file_contents = f.read()
        try:
            return self.parseString(file_contents, parseAll)
        except ParseBaseException as exc:
            if ParserElement.verbose_stacktrace:
                raise
            else:

                if getattr(exc, '__traceback__', None) is not None:
                    exc.__traceback__ = self._trim_traceback(exc.__traceback__)
                raise exc

    def __eq__(self, other):
        if self is other:
            return True
        elif isinstance(other, basestring):
            return self.matches(other)
        elif isinstance(other, ParserElement):
            return vars(self) == vars(other)
        return False

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return id(self)

    def __req__(self, other):
        return self == other

    def __rne__(self, other):
        return not (self == other)

    def matches(self, testString, parseAll=True):
        try:
            self.parseString(_ustr(testString), parseAll=parseAll)
            return True
        except ParseBaseException:
            return False

    def runTests(self, tests, parseAll=True, comment='#',
                 fullDump=True, printResults=True, failureTests=False, postParse=None,
                 file=None):
        if isinstance(tests, basestring):
            tests = list(map(str.strip, tests.rstrip().splitlines()))
        if isinstance(comment, basestring):
            comment = Literal(comment)
        if file is None:
            file = sys.stdout
        print_ = file.write

        allResults = []
        comments = []
        success = True
        NL = Literal(r'\n').addParseAction(replaceWith('\n')).ignore(quotedString)
        BOM = u'\ufeff'
        for t in tests:
            if comment is not None and comment.matches(t, False) or comments and not t:
                comments.append(t)
                continue
            if not t:
                continue
            out = ['\n' + '\n'.join(comments) if comments else '', t]
            comments = []
            try:

                t = NL.transformString(t.lstrip(BOM))
                result = self.parseString(t, parseAll=parseAll)
            except ParseBaseException as pe:
                fatal = "(FATAL)" if isinstance(pe, ParseFatalException) else ""
                if '\n' in t:
                    out.append(line(pe.loc, t))
                    out.append(' ' * (col(pe.loc, t) - 1) + '^' + fatal)
                else:
                    out.append(' ' * pe.loc + '^' + fatal)
                out.append("FAIL: " + str(pe))
                success = success and failureTests
                result = pe
            except Exception as exc:
                out.append("FAIL-EXCEPTION: " + str(exc))
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
                        out.append("{0} failed: {1}: {2}".format(postParse.__name__, type(e).__name__, e))
                else:
                    out.append(result.dump(full=fullDump))

            if printResults:
                if fullDump:
                    out.append('')
                print_('\n'.join(out))

            allResults.append((t, result))

        return success, allResults


class _PendingSkip(ParserElement):


    def __init__(self, expr, must_skip=False):
        super(_PendingSkip, self).__init__()
        self.strRepr = str(expr + Empty()).replace('Empty', '...')
        self.name = self.strRepr
        self.anchor = expr
        self.must_skip = must_skip

    def __add__(self, other):
        skipper = SkipTo(other).setName("...")("_skipped*")
        if self.must_skip:
            def must_skip(t):
                if not t._skipped or t._skipped.asList() == ['']:
                    del t[0]
                    t.pop("_skipped", None)
            def show_skip(t):
                if t._skipped.asList()[-1:] == ['']:
                    skipped = t.pop('_skipped')
                    t['_skipped'] = 'missing <' + repr(self.anchor) + '>'
            return (self.anchor + skipper().addParseAction(must_skip)
                    | skipper().addParseAction(show_skip)) + other

        return self.anchor + skipper + other

    def __repr__(self):
        return self.strRepr

    def parseImpl(self, *args):
        raise Exception("use of `...` expression without following SkipTo target expression")


class Token(ParserElement):
    def __init__(self):
        super(Token, self).__init__(savelist=False)


class Empty(Token):
    def __init__(self):
        super(Empty, self).__init__()
        self.name = "Empty"
        self.mayReturnEmpty = True
        self.mayIndexError = False


class NoMatch(Token):
    def __init__(self):
        super(NoMatch, self).__init__()
        self.name = "NoMatch"
        self.mayReturnEmpty = True
        self.mayIndexError = False
        self.errmsg = "Unmatchable token"

    def parseImpl(self, instring, loc, doActions=True):
        raise ParseException(instring, loc, self.errmsg, self)


class Literal(Token):
    def __init__(self, matchString):
        super(Literal, self).__init__()
        self.match = matchString
        self.matchLen = len(matchString)
        try:
            self.firstMatchChar = matchString[0]
        except IndexError:
            warnings.warn("null string passed to Literal; use Empty() instead",
                            SyntaxWarning, stacklevel=2)
            self.__class__ = Empty
        self.name = '"%s"' % _ustr(self.match)
        self.errmsg = "Expected " + self.name
        self.mayReturnEmpty = False
        self.mayIndexError = False


        if self.matchLen == 1 and type(self) is Literal:
            self.__class__ = _SingleCharLiteral

    def parseImpl(self, instring, loc, doActions=True):
        if instring[loc] == self.firstMatchChar and instring.startswith(self.match, loc):
            return loc + self.matchLen, self.match
        raise ParseException(instring, loc, self.errmsg, self)

class _SingleCharLiteral(Literal):
    def parseImpl(self, instring, loc, doActions=True):
        if instring[loc] == self.firstMatchChar:
            return loc + 1, self.match
        raise ParseException(instring, loc, self.errmsg, self)

_L = Literal
ParserElement._literalStringClass = Literal

class Keyword(Token):
    DEFAULT_KEYWORD_CHARS = alphanums + "_$"

    def __init__(self, matchString, identChars=None, caseless=False):
        super(Keyword, self).__init__()
        if identChars is None:
            identChars = Keyword.DEFAULT_KEYWORD_CHARS
        self.match = matchString
        self.matchLen = len(matchString)
        try:
            self.firstMatchChar = matchString[0]
        except IndexError:
            warnings.warn("null string passed to Keyword; use Empty() instead",
                          SyntaxWarning, stacklevel=2)
        self.name = '"%s"' % self.match
        self.errmsg = "Expected " + self.name
        self.mayReturnEmpty = False
        self.mayIndexError = False
        self.caseless = caseless
        if caseless:
            self.caselessmatch = matchString.upper()
            identChars = identChars.upper()
        self.identChars = set(identChars)

    def parseImpl(self, instring, loc, doActions=True):
        if self.caseless:
            if ((instring[loc:loc + self.matchLen].upper() == self.caselessmatch)
                    and (loc >= len(instring) - self.matchLen
                         or instring[loc + self.matchLen].upper() not in self.identChars)
                    and (loc == 0
                         or instring[loc - 1].upper() not in self.identChars)):
                return loc + self.matchLen, self.match

        else:
            if instring[loc] == self.firstMatchChar:
                if ((self.matchLen == 1 or instring.startswith(self.match, loc))
                        and (loc >= len(instring) - self.matchLen
                             or instring[loc + self.matchLen] not in self.identChars)
                        and (loc == 0 or instring[loc - 1] not in self.identChars)):
                    return loc + self.matchLen, self.match

        raise ParseException(instring, loc, self.errmsg, self)

    def copy(self):
        c = super(Keyword, self).copy()
        c.identChars = Keyword.DEFAULT_KEYWORD_CHARS
        return c

    @staticmethod
    def setDefaultKeywordChars(chars):
        Keyword.DEFAULT_KEYWORD_CHARS = chars

class CaselessLiteral(Literal):
    def __init__(self, matchString):
        super(CaselessLiteral, self).__init__(matchString.upper())

        self.returnString = matchString
        self.name = "'%s'" % self.returnString
        self.errmsg = "Expected " + self.name

    def parseImpl(self, instring, loc, doActions=True):
        if instring[loc:loc + self.matchLen].upper() == self.match:
            return loc + self.matchLen, self.returnString
        raise ParseException(instring, loc, self.errmsg, self)

class CaselessKeyword(Keyword):
    def __init__(self, matchString, identChars=None):
        super(CaselessKeyword, self).__init__(matchString, identChars, caseless=True)

class CloseMatch(Token):
    def __init__(self, match_string, maxMismatches=1):
        super(CloseMatch, self).__init__()
        self.name = match_string
        self.match_string = match_string
        self.maxMismatches = maxMismatches
        self.errmsg = "Expected %r (with up to %d mismatches)" % (self.match_string, self.maxMismatches)
        self.mayIndexError = False
        self.mayReturnEmpty = False

    def parseImpl(self, instring, loc, doActions=True):
        start = loc
        instrlen = len(instring)
        maxloc = start + len(self.match_string)

        if maxloc <= instrlen:
            match_string = self.match_string
            match_stringloc = 0
            mismatches = []
            maxMismatches = self.maxMismatches

            for match_stringloc, s_m in enumerate(zip(instring[loc:maxloc], match_string)):
                src, mat = s_m
                if src != mat:
                    mismatches.append(match_stringloc)
                    if len(mismatches) > maxMismatches:
                        break
            else:
                loc = match_stringloc + 1
                results = ParseResults([instring[start:loc]])
                results['original'] = match_string
                results['mismatches'] = mismatches
                return loc, results

        raise ParseException(instring, loc, self.errmsg, self)


class Word(Token):
    def __init__(self, initChars, bodyChars=None, min=1, max=0, exact=0, asKeyword=False, excludeChars=None):
        super(Word, self).__init__()
        if excludeChars:
            excludeChars = set(excludeChars)
            initChars = ''.join(c for c in initChars if c not in excludeChars)
            if bodyChars:
                bodyChars = ''.join(c for c in bodyChars if c not in excludeChars)
        self.initCharsOrig = initChars
        self.initChars = set(initChars)
        if bodyChars:
            self.bodyCharsOrig = bodyChars
            self.bodyChars = set(bodyChars)
        else:
            self.bodyCharsOrig = initChars
            self.bodyChars = set(initChars)

        self.maxSpecified = max > 0

        if min < 1:
            raise ValueError("cannot specify a minimum length < 1; use Optional(Word()) if zero-length word is permitted")

        self.minLen = min

        if max > 0:
            self.maxLen = max
        else:
            self.maxLen = _MAX_INT

        if exact > 0:
            self.maxLen = exact
            self.minLen = exact

        self.name = _ustr(self)
        self.errmsg = "Expected " + self.name
        self.mayIndexError = False
        self.asKeyword = asKeyword

        if ' ' not in self.initCharsOrig + self.bodyCharsOrig and (min == 1 and max == 0 and exact == 0):
            if self.bodyCharsOrig == self.initCharsOrig:
                self.reString = "[%s]+" % _escapeRegexRangeChars(self.initCharsOrig)
            elif len(self.initCharsOrig) == 1:
                self.reString = "%s[%s]*" % (re.escape(self.initCharsOrig),
                                             _escapeRegexRangeChars(self.bodyCharsOrig),)
            else:
                self.reString = "[%s][%s]*" % (_escapeRegexRangeChars(self.initCharsOrig),
                                               _escapeRegexRangeChars(self.bodyCharsOrig),)
            if self.asKeyword:
                self.reString = r"\b" + self.reString + r"\b"

            try:
                self.re = re.compile(self.reString)
            except Exception:
                self.re = None
            else:
                self.re_match = self.re.match
                self.__class__ = _WordRegex

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
            if (start > 0 and instring[start - 1] in bodychars
                    or loc < instrlen and instring[loc] in bodychars):
                throwException = True

        if throwException:
            raise ParseException(instring, loc, self.errmsg, self)

        return loc, instring[start:loc]

    def __str__(self):
        try:
            return super(Word, self).__str__()
        except Exception:
            pass

        if self.strRepr is None:

            def charsAsStr(s):
                if len(s) > 4:
                    return s[:4] + "..."
                else:
                    return s

            if self.initCharsOrig != self.bodyCharsOrig:
                self.strRepr = "W:(%s, %s)" % (charsAsStr(self.initCharsOrig), charsAsStr(self.bodyCharsOrig))
            else:
                self.strRepr = "W:(%s)" % charsAsStr(self.initCharsOrig)

        return self.strRepr

class _WordRegex(Word):
    def parseImpl(self, instring, loc, doActions=True):
        result = self.re_match(instring, loc)
        if not result:
            raise ParseException(instring, loc, self.errmsg, self)

        loc = result.end()
        return loc, result.group()


class Char(_WordRegex):
    def __init__(self, charset, asKeyword=False, excludeChars=None):
        super(Char, self).__init__(charset, exact=1, asKeyword=asKeyword, excludeChars=excludeChars)
        self.reString = "[%s]" % _escapeRegexRangeChars(''.join(self.initChars))
        if asKeyword:
            self.reString = r"\b%s\b" % self.reString
        self.re = re.compile(self.reString)
        self.re_match = self.re.match


class Regex(Token):
    def __init__(self, pattern, flags=0, asGroupList=False, asMatch=False):
        super(Regex, self).__init__()

        if isinstance(pattern, basestring):
            if not pattern:
                warnings.warn("null string passed to Regex; use Empty() instead",
                              SyntaxWarning, stacklevel=2)

            self.pattern = pattern
            self.flags = flags

            try:
                self.re = re.compile(self.pattern, self.flags)
                self.reString = self.pattern
            except sre_constants.error:
                warnings.warn("invalid pattern (%s) passed to Regex" % pattern,
                              SyntaxWarning, stacklevel=2)
                raise

        elif hasattr(pattern, 'pattern') and hasattr(pattern, 'match'):
            self.re = pattern
            self.pattern = self.reString = pattern.pattern
            self.flags = flags

        else:
            raise TypeError("Regex may only be constructed with a string or a compiled RE object")

        self.re_match = self.re.match

        self.name = _ustr(self)
        self.errmsg = "Expected " + self.name
        self.mayIndexError = False
        self.mayReturnEmpty = self.re_match("") is not None
        self.asGroupList = asGroupList
        self.asMatch = asMatch
        if self.asGroupList:
            self.parseImpl = self.parseImplAsGroupList
        if self.asMatch:
            self.parseImpl = self.parseImplAsMatch

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

    def __str__(self):
        try:
            return super(Regex, self).__str__()
        except Exception:
            pass

        if self.strRepr is None:
            self.strRepr = "Re:(%s)" % repr(self.pattern)

        return self.strRepr

    def sub(self, repl):
        if self.asGroupList:
            warnings.warn("cannot use sub() with Regex(asGroupList=True)",
                          SyntaxWarning, stacklevel=2)
            raise SyntaxError()

        if self.asMatch and callable(repl):
            warnings.warn("cannot use sub() with a callable with Regex(asMatch=True)",
                          SyntaxWarning, stacklevel=2)
            raise SyntaxError()

        if self.asMatch:
            def pa(tokens):
                return tokens[0].expand(repl)
        else:
            def pa(tokens):
                return self.re.sub(repl, tokens[0])
        return self.addParseAction(pa)

class QuotedString(Token):
    def __init__(self, quoteChar, escChar=None, escQuote=None, multiline=False,
                 unquoteResults=True, endQuoteChar=None, convertWhitespaceEscapes=True):
        super(QuotedString, self).__init__()


        quoteChar = quoteChar.strip()
        if not quoteChar:
            warnings.warn("quoteChar cannot be the empty string", SyntaxWarning, stacklevel=2)
            raise SyntaxError()

        if endQuoteChar is None:
            endQuoteChar = quoteChar
        else:
            endQuoteChar = endQuoteChar.strip()
            if not endQuoteChar:
                warnings.warn("endQuoteChar cannot be the empty string", SyntaxWarning, stacklevel=2)
                raise SyntaxError()

        self.quoteChar = quoteChar
        self.quoteCharLen = len(quoteChar)
        self.firstQuoteChar = quoteChar[0]
        self.endQuoteChar = endQuoteChar
        self.endQuoteCharLen = len(endQuoteChar)
        self.escChar = escChar
        self.escQuote = escQuote
        self.unquoteResults = unquoteResults
        self.convertWhitespaceEscapes = convertWhitespaceEscapes

        if multiline:
            self.flags = re.MULTILINE | re.DOTALL
            self.pattern = r'%s(?:[^%s%s]' % (re.escape(self.quoteChar),
                                              _escapeRegexRangeChars(self.endQuoteChar[0]),
                                              (escChar is not None and _escapeRegexRangeChars(escChar) or ''))
        else:
            self.flags = 0
            self.pattern = r'%s(?:[^%s\n\r%s]' % (re.escape(self.quoteChar),
                                                  _escapeRegexRangeChars(self.endQuoteChar[0]),
                                                  (escChar is not None and _escapeRegexRangeChars(escChar) or ''))
        if len(self.endQuoteChar) > 1:
            self.pattern += (
                '|(?:' + ')|(?:'.join("%s[^%s]" % (re.escape(self.endQuoteChar[:i]),
                                                   _escapeRegexRangeChars(self.endQuoteChar[i]))
                                      for i in range(len(self.endQuoteChar) - 1, 0, -1)) + ')')

        if escQuote:
            self.pattern += (r'|(?:%s)' % re.escape(escQuote))
        if escChar:
            self.pattern += (r'|(?:%s.)' % re.escape(escChar))
            self.escCharReplacePattern = re.escape(self.escChar) + "(.)"
        self.pattern += (r')*%s' % re.escape(self.endQuoteChar))

        try:
            self.re = re.compile(self.pattern, self.flags)
            self.reString = self.pattern
            self.re_match = self.re.match
        except sre_constants.error:
            warnings.warn("invalid pattern (%s) passed to Regex" % self.pattern,
                          SyntaxWarning, stacklevel=2)
            raise

        self.name = _ustr(self)
        self.errmsg = "Expected " + self.name
        self.mayIndexError = False
        self.mayReturnEmpty = True

    def parseImpl(self, instring, loc, doActions=True):
        result = instring[loc] == self.firstQuoteChar and self.re_match(instring, loc) or None
        if not result:
            raise ParseException(instring, loc, self.errmsg, self)

        loc = result.end()
        ret = result.group()

        if self.unquoteResults:


            ret = ret[self.quoteCharLen: -self.endQuoteCharLen]

            if isinstance(ret, basestring):

                if '\\' in ret and self.convertWhitespaceEscapes:
                    ws_map = {
                        r'\t': '\t',
                        r'\n': '\n',
                        r'\f': '\f',
                        r'\r': '\r',
                    }
                    for wslit, wschar in ws_map.items():
                        ret = ret.replace(wslit, wschar)


                if self.escChar:
                    ret = re.sub(self.escCharReplacePattern, r"\g<1>", ret)


                if self.escQuote:
                    ret = ret.replace(self.escQuote, self.endQuoteChar)

        return loc, ret

    def __str__(self):
        try:
            return super(QuotedString, self).__str__()
        except Exception:
            pass

        if self.strRepr is None:
            self.strRepr = "quoted string, starting with %s ending with %s" % (self.quoteChar, self.endQuoteChar)

        return self.strRepr


class CharsNotIn(Token):
    def __init__(self, notChars, min=1, max=0, exact=0):
        super(CharsNotIn, self).__init__()
        self.skipWhitespace = False
        self.notChars = notChars

        if min < 1:
            raise ValueError("cannot specify a minimum length < 1; use "
                             "Optional(CharsNotIn()) if zero-length char group is permitted")

        self.minLen = min

        if max > 0:
            self.maxLen = max
        else:
            self.maxLen = _MAX_INT

        if exact > 0:
            self.maxLen = exact
            self.minLen = exact

        self.name = _ustr(self)
        self.errmsg = "Expected " + self.name
        self.mayReturnEmpty = (self.minLen == 0)
        self.mayIndexError = False

    def parseImpl(self, instring, loc, doActions=True):
        if instring[loc] in self.notChars:
            raise ParseException(instring, loc, self.errmsg, self)

        start = loc
        loc += 1
        notchars = self.notChars
        maxlen = min(start + self.maxLen, len(instring))
        while loc < maxlen and instring[loc] not in notchars:
            loc += 1

        if loc - start < self.minLen:
            raise ParseException(instring, loc, self.errmsg, self)

        return loc, instring[start:loc]

    def __str__(self):
        try:
            return super(CharsNotIn, self).__str__()
        except Exception:
            pass

        if self.strRepr is None:
            if len(self.notChars) > 4:
                self.strRepr = "!W:(%s...)" % self.notChars[:4]
            else:
                self.strRepr = "!W:(%s)" % self.notChars

        return self.strRepr

class White(Token):
    whiteStrs = {
        ' ' : '<SP>',
        '\t': '<TAB>',
        '\n': '<LF>',
        '\r': '<CR>',
        '\f': '<FF>',
        u'\u00A0': '<NBSP>',
        u'\u1680': '<OGHAM_SPACE_MARK>',
        u'\u180E': '<MONGOLIAN_VOWEL_SEPARATOR>',
        u'\u2000': '<EN_QUAD>',
        u'\u2001': '<EM_QUAD>',
        u'\u2002': '<EN_SPACE>',
        u'\u2003': '<EM_SPACE>',
        u'\u2004': '<THREE-PER-EM_SPACE>',
        u'\u2005': '<FOUR-PER-EM_SPACE>',
        u'\u2006': '<SIX-PER-EM_SPACE>',
        u'\u2007': '<FIGURE_SPACE>',
        u'\u2008': '<PUNCTUATION_SPACE>',
        u'\u2009': '<THIN_SPACE>',
        u'\u200A': '<HAIR_SPACE>',
        u'\u200B': '<ZERO_WIDTH_SPACE>',
        u'\u202F': '<NNBSP>',
        u'\u205F': '<MMSP>',
        u'\u3000': '<IDEOGRAPHIC_SPACE>',
        }
    def __init__(self, ws=" \t\r\n", min=1, max=0, exact=0):
        super(White, self).__init__()
        self.matchWhite = ws
        self.setWhitespaceChars("".join(c for c in self.whiteChars if c not in self.matchWhite))

        self.name = ("".join(White.whiteStrs[c] for c in self.matchWhite))
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


class _PositionToken(Token):
    def __init__(self):
        super(_PositionToken, self).__init__()
        self.name = self.__class__.__name__
        self.mayReturnEmpty = True
        self.mayIndexError = False

class GoToColumn(_PositionToken):
    def __init__(self, colno):
        super(GoToColumn, self).__init__()
        self.col = colno

    def preParse(self, instring, loc):
        if col(loc, instring) != self.col:
            instrlen = len(instring)
            if self.ignoreExprs:
                loc = self._skipIgnorables(instring, loc)
            while loc < instrlen and instring[loc].isspace() and col(loc, instring) != self.col:
                loc += 1
        return loc

    def parseImpl(self, instring, loc, doActions=True):
        thiscol = col(loc, instring)
        if thiscol > self.col:
            raise ParseException(instring, loc, "Text not in expected column", self)
        newloc = loc + self.col - thiscol
        ret = instring[loc: newloc]
        return newloc, ret


class LineStart(_PositionToken):
    def __init__(self):
        super(LineStart, self).__init__()
        self.errmsg = "Expected start of line"

    def parseImpl(self, instring, loc, doActions=True):
        if col(loc, instring) == 1:
            return loc, []
        raise ParseException(instring, loc, self.errmsg, self)

class LineEnd(_PositionToken):
    def __init__(self):
        super(LineEnd, self).__init__()
        self.setWhitespaceChars(ParserElement.DEFAULT_WHITE_CHARS.replace("\n", ""))
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

class StringStart(_PositionToken):
    def __init__(self):
        super(StringStart, self).__init__()
        self.errmsg = "Expected start of text"

    def parseImpl(self, instring, loc, doActions=True):
        if loc != 0:

            if loc != self.preParse(instring, 0):
                raise ParseException(instring, loc, self.errmsg, self)
        return loc, []

class StringEnd(_PositionToken):
    def __init__(self):
        super(StringEnd, self).__init__()
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

class WordStart(_PositionToken):
    def __init__(self, wordChars=printables):
        super(WordStart, self).__init__()
        self.wordChars = set(wordChars)
        self.errmsg = "Not at the start of a word"

    def parseImpl(self, instring, loc, doActions=True):
        if loc != 0:
            if (instring[loc - 1] in self.wordChars
                    or instring[loc] not in self.wordChars):
                raise ParseException(instring, loc, self.errmsg, self)
        return loc, []

class WordEnd(_PositionToken):
    def __init__(self, wordChars=printables):
        super(WordEnd, self).__init__()
        self.wordChars = set(wordChars)
        self.skipWhitespace = False
        self.errmsg = "Not at the end of a word"

    def parseImpl(self, instring, loc, doActions=True):
        instrlen = len(instring)
        if instrlen > 0 and loc < instrlen:
            if (instring[loc] in self.wordChars or
                    instring[loc - 1] not in self.wordChars):
                raise ParseException(instring, loc, self.errmsg, self)
        return loc, []


class ParseExpression(ParserElement):
    def __init__(self, exprs, savelist=False):
        super(ParseExpression, self).__init__(savelist)
        if isinstance(exprs, _generatorType):
            exprs = list(exprs)

        if isinstance(exprs, basestring):
            self.exprs = [self._literalStringClass(exprs)]
        elif isinstance(exprs, ParserElement):
            self.exprs = [exprs]
        elif isinstance(exprs, Iterable):
            exprs = list(exprs)

            if any(isinstance(expr, basestring) for expr in exprs):
                exprs = (self._literalStringClass(e) if isinstance(e, basestring) else e for e in exprs)
            self.exprs = list(exprs)
        else:
            try:
                self.exprs = list(exprs)
            except TypeError:
                self.exprs = [exprs]
        self.callPreparse = False

    def append(self, other):
        self.exprs.append(other)
        self.strRepr = None
        return self

    def leaveWhitespace(self):
        self.skipWhitespace = False
        self.exprs = [e.copy() for e in self.exprs]
        for e in self.exprs:
            e.leaveWhitespace()
        return self

    def ignore(self, other):
        if isinstance(other, Suppress):
            if other not in self.ignoreExprs:
                super(ParseExpression, self).ignore(other)
                for e in self.exprs:
                    e.ignore(self.ignoreExprs[-1])
        else:
            super(ParseExpression, self).ignore(other)
            for e in self.exprs:
                e.ignore(self.ignoreExprs[-1])
        return self

    def __str__(self):
        try:
            return super(ParseExpression, self).__str__()
        except Exception:
            pass

        if self.strRepr is None:
            self.strRepr = "%s:(%s)" % (self.__class__.__name__, _ustr(self.exprs))
        return self.strRepr

    def streamline(self):
        super(ParseExpression, self).streamline()

        for e in self.exprs:
            e.streamline()


        if len(self.exprs) == 2:
            other = self.exprs[0]
            if (isinstance(other, self.__class__)
                    and not other.parseAction
                    and other.resultsName is None
                    and not other.debug):
                self.exprs = other.exprs[:] + [self.exprs[1]]
                self.strRepr = None
                self.mayReturnEmpty |= other.mayReturnEmpty
                self.mayIndexError  |= other.mayIndexError

            other = self.exprs[-1]
            if (isinstance(other, self.__class__)
                    and not other.parseAction
                    and other.resultsName is None
                    and not other.debug):
                self.exprs = self.exprs[:-1] + other.exprs[:]
                self.strRepr = None
                self.mayReturnEmpty |= other.mayReturnEmpty
                self.mayIndexError  |= other.mayIndexError

        self.errmsg = "Expected " + _ustr(self)

        return self

    def validate(self, validateTrace=None):
        tmp = (validateTrace if validateTrace is not None else [])[:] + [self]
        for e in self.exprs:
            e.validate(tmp)
        self.checkRecursion([])

    def copy(self):
        ret = super(ParseExpression, self).copy()
        ret.exprs = [e.copy() for e in self.exprs]
        return ret

    def _setResultsName(self, name, listAllMatches=False):
        if __diag__.warn_ungrouped_named_tokens_in_collection:
            for e in self.exprs:
                if isinstance(e, ParserElement) and e.resultsName:
                    warnings.warn("{0}: setting results name {1!r} on {2} expression "
                                  "collides with {3!r} on contained expression".format("warn_ungrouped_named_tokens_in_collection",
                                                                                       name,
                                                                                       type(self).__name__,
                                                                                       e.resultsName),
                                  stacklevel=3)

        return super(ParseExpression, self)._setResultsName(name, listAllMatches)


class And(ParseExpression):

    class _ErrorStop(Empty):
        def __init__(self, *args, **kwargs):
            super(And._ErrorStop, self).__init__(*args, **kwargs)
            self.name = '-'
            self.leaveWhitespace()

    def __init__(self, exprs, savelist=True):
        exprs = list(exprs)
        if exprs and Ellipsis in exprs:
            tmp = []
            for i, expr in enumerate(exprs):
                if expr is Ellipsis:
                    if i < len(exprs) - 1:
                        skipto_arg = (Empty() + exprs[i + 1]).exprs[-1]
                        tmp.append(SkipTo(skipto_arg)("_skipped*"))
                    else:
                        raise Exception("cannot construct And with sequence ending in ...")
                else:
                    tmp.append(expr)
            exprs[:] = tmp
        super(And, self).__init__(exprs, savelist)
        self.mayReturnEmpty = all(e.mayReturnEmpty for e in self.exprs)
        self.setWhitespaceChars(self.exprs[0].whiteChars)
        self.skipWhitespace = self.exprs[0].skipWhitespace
        self.callPreparse = True

    def streamline(self):

        if self.exprs:
            if any(isinstance(e, ParseExpression) and e.exprs and isinstance(e.exprs[-1], _PendingSkip)
                   for e in self.exprs[:-1]):
                for i, e in enumerate(self.exprs[:-1]):
                    if e is None:
                        continue
                    if (isinstance(e, ParseExpression)
                            and e.exprs and isinstance(e.exprs[-1], _PendingSkip)):
                        e.exprs[-1] = e.exprs[-1] + self.exprs[i + 1]
                        self.exprs[i + 1] = None
                self.exprs = [e for e in self.exprs if e is not None]

        super(And, self).streamline()
        self.mayReturnEmpty = all(e.mayReturnEmpty for e in self.exprs)
        return self

    def parseImpl(self, instring, loc, doActions=True):


        loc, resultlist = self.exprs[0]._parse(instring, loc, doActions, callPreParse=False)
        errorStop = False
        for e in self.exprs[1:]:
            if isinstance(e, And._ErrorStop):
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
                    raise ParseSyntaxException(instring, len(instring), self.errmsg, self)
            else:
                loc, exprtokens = e._parse(instring, loc, doActions)
            if exprtokens or exprtokens.haskeys():
                resultlist += exprtokens
        return loc, resultlist

    def __iadd__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        return self.append(other)

    def checkRecursion(self, parseElementList):
        subRecCheckList = parseElementList[:] + [self]
        for e in self.exprs:
            e.checkRecursion(subRecCheckList)
            if not e.mayReturnEmpty:
                break

    def __str__(self):
        if hasattr(self, "name"):
            return self.name

        if self.strRepr is None:
            self.strRepr = "{" + " ".join(_ustr(e) for e in self.exprs) + "}"

        return self.strRepr


class Or(ParseExpression):
    def __init__(self, exprs, savelist=False):
        super(Or, self).__init__(exprs, savelist)
        if self.exprs:
            self.mayReturnEmpty = any(e.mayReturnEmpty for e in self.exprs)
        else:
            self.mayReturnEmpty = True

    def streamline(self):
        super(Or, self).streamline()
        if __compat__.collect_all_And_tokens:
            self.saveAsList = any(e.saveAsList for e in self.exprs)
        return self

    def parseImpl(self, instring, loc, doActions=True):
        maxExcLoc = -1
        maxException = None
        matches = []
        for e in self.exprs:
            try:
                loc2 = e.tryParse(instring, loc)
            except ParseException as err:
                err.__traceback__ = None
                if err.loc > maxExcLoc:
                    maxException = err
                    maxExcLoc = err.loc
            except IndexError:
                if len(instring) > maxExcLoc:
                    maxException = ParseException(instring, len(instring), e.errmsg, self)
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

        if maxException is not None:
            maxException.msg = self.errmsg
            raise maxException
        else:
            raise ParseException(instring, loc, "no defined alternatives to match", self)


    def __ixor__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        return self.append(other)

    def __str__(self):
        if hasattr(self, "name"):
            return self.name

        if self.strRepr is None:
            self.strRepr = "{" + " ^ ".join(_ustr(e) for e in self.exprs) + "}"

        return self.strRepr

    def checkRecursion(self, parseElementList):
        subRecCheckList = parseElementList[:] + [self]
        for e in self.exprs:
            e.checkRecursion(subRecCheckList)

    def _setResultsName(self, name, listAllMatches=False):
        if (not __compat__.collect_all_And_tokens
                and __diag__.warn_multiple_tokens_in_named_alternation):
            if any(isinstance(e, And) for e in self.exprs):
                warnings.warn("{0}: setting results name {1!r} on {2} expression "
                              "may only return a single token for an And alternative, "
                              "in future will return the full list of tokens".format(
                    "warn_multiple_tokens_in_named_alternation", name, type(self).__name__),
                    stacklevel=3)

        return super(Or, self)._setResultsName(name, listAllMatches)


class MatchFirst(ParseExpression):
    def __init__(self, exprs, savelist=False):
        super(MatchFirst, self).__init__(exprs, savelist)
        if self.exprs:
            self.mayReturnEmpty = any(e.mayReturnEmpty for e in self.exprs)
        else:
            self.mayReturnEmpty = True

    def streamline(self):
        super(MatchFirst, self).streamline()
        if __compat__.collect_all_And_tokens:
            self.saveAsList = any(e.saveAsList for e in self.exprs)
        return self

    def parseImpl(self, instring, loc, doActions=True):
        maxExcLoc = -1
        maxException = None
        for e in self.exprs:
            try:
                ret = e._parse(instring, loc, doActions)
                return ret
            except ParseException as err:
                if err.loc > maxExcLoc:
                    maxException = err
                    maxExcLoc = err.loc
            except IndexError:
                if len(instring) > maxExcLoc:
                    maxException = ParseException(instring, len(instring), e.errmsg, self)
                    maxExcLoc = len(instring)


        else:
            if maxException is not None:
                maxException.msg = self.errmsg
                raise maxException
            else:
                raise ParseException(instring, loc, "no defined alternatives to match", self)

    def __ior__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        return self.append(other)

    def __str__(self):
        if hasattr(self, "name"):
            return self.name

        if self.strRepr is None:
            self.strRepr = "{" + " | ".join(_ustr(e) for e in self.exprs) + "}"

        return self.strRepr

    def checkRecursion(self, parseElementList):
        subRecCheckList = parseElementList[:] + [self]
        for e in self.exprs:
            e.checkRecursion(subRecCheckList)

    def _setResultsName(self, name, listAllMatches=False):
        if (not __compat__.collect_all_And_tokens
                and __diag__.warn_multiple_tokens_in_named_alternation):
            if any(isinstance(e, And) for e in self.exprs):
                warnings.warn("{0}: setting results name {1!r} on {2} expression "
                              "may only return a single token for an And alternative, "
                              "in future will return the full list of tokens".format(
                    "warn_multiple_tokens_in_named_alternation", name, type(self).__name__),
                    stacklevel=3)

        return super(MatchFirst, self)._setResultsName(name, listAllMatches)


class Each(ParseExpression):
    def __init__(self, exprs, savelist=True):
        super(Each, self).__init__(exprs, savelist)
        self.mayReturnEmpty = all(e.mayReturnEmpty for e in self.exprs)
        self.skipWhitespace = True
        self.initExprGroups = True
        self.saveAsList = True

    def streamline(self):
        super(Each, self).streamline()
        self.mayReturnEmpty = all(e.mayReturnEmpty for e in self.exprs)
        return self

    def parseImpl(self, instring, loc, doActions=True):
        if self.initExprGroups:
            self.opt1map = dict((id(e.expr), e) for e in self.exprs if isinstance(e, Optional))
            opt1 = [e.expr for e in self.exprs if isinstance(e, Optional)]
            opt2 = [e for e in self.exprs if e.mayReturnEmpty and not isinstance(e, (Optional, Regex))]
            self.optionals = opt1 + opt2
            self.multioptionals = [e.expr for e in self.exprs if isinstance(e, ZeroOrMore)]
            self.multirequired = [e.expr for e in self.exprs if isinstance(e, OneOrMore)]
            self.required = [e for e in self.exprs if not isinstance(e, (Optional, ZeroOrMore, OneOrMore))]
            self.required += self.multirequired
            self.initExprGroups = False
        tmpLoc = loc
        tmpReqd = self.required[:]
        tmpOpt  = self.optionals[:]
        matchOrder = []

        keepMatching = True
        while keepMatching:
            tmpExprs = tmpReqd + tmpOpt + self.multioptionals + self.multirequired
            failed = []
            for e in tmpExprs:
                try:
                    tmpLoc = e.tryParse(instring, tmpLoc)
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

        if tmpReqd:
            missing = ", ".join(_ustr(e) for e in tmpReqd)
            raise ParseException(instring, loc, "Missing one or more required elements (%s)" % missing)


        matchOrder += [e for e in self.exprs if isinstance(e, Optional) and e.expr in tmpOpt]

        resultlist = []
        for e in matchOrder:
            loc, results = e._parse(instring, loc, doActions)
            resultlist.append(results)

        finalResults = sum(resultlist, ParseResults([]))
        return loc, finalResults

    def __str__(self):
        if hasattr(self, "name"):
            return self.name

        if self.strRepr is None:
            self.strRepr = "{" + " & ".join(_ustr(e) for e in self.exprs) + "}"

        return self.strRepr

    def checkRecursion(self, parseElementList):
        subRecCheckList = parseElementList[:] + [self]
        for e in self.exprs:
            e.checkRecursion(subRecCheckList)


class ParseElementEnhance(ParserElement):
    def __init__(self, expr, savelist=False):
        super(ParseElementEnhance, self).__init__(savelist)
        if isinstance(expr, basestring):
            if issubclass(self._literalStringClass, Token):
                expr = self._literalStringClass(expr)
            else:
                expr = self._literalStringClass(Literal(expr))
        self.expr = expr
        self.strRepr = None
        if expr is not None:
            self.mayIndexError = expr.mayIndexError
            self.mayReturnEmpty = expr.mayReturnEmpty
            self.setWhitespaceChars(expr.whiteChars)
            self.skipWhitespace = expr.skipWhitespace
            self.saveAsList = expr.saveAsList
            self.callPreparse = expr.callPreparse
            self.ignoreExprs.extend(expr.ignoreExprs)

    def parseImpl(self, instring, loc, doActions=True):
        if self.expr is not None:
            return self.expr._parse(instring, loc, doActions, callPreParse=False)
        else:
            raise ParseException("", loc, self.errmsg, self)

    def leaveWhitespace(self):
        self.skipWhitespace = False
        self.expr = self.expr.copy()
        if self.expr is not None:
            self.expr.leaveWhitespace()
        return self

    def ignore(self, other):
        if isinstance(other, Suppress):
            if other not in self.ignoreExprs:
                super(ParseElementEnhance, self).ignore(other)
                if self.expr is not None:
                    self.expr.ignore(self.ignoreExprs[-1])
        else:
            super(ParseElementEnhance, self).ignore(other)
            if self.expr is not None:
                self.expr.ignore(self.ignoreExprs[-1])
        return self

    def streamline(self):
        super(ParseElementEnhance, self).streamline()
        if self.expr is not None:
            self.expr.streamline()
        return self

    def checkRecursion(self, parseElementList):
        if self in parseElementList:
            raise RecursiveGrammarException(parseElementList + [self])
        subRecCheckList = parseElementList[:] + [self]
        if self.expr is not None:
            self.expr.checkRecursion(subRecCheckList)

    def validate(self, validateTrace=None):
        if validateTrace is None:
            validateTrace = []
        tmp = validateTrace[:] + [self]
        if self.expr is not None:
            self.expr.validate(tmp)
        self.checkRecursion([])

    def __str__(self):
        try:
            return super(ParseElementEnhance, self).__str__()
        except Exception:
            pass

        if self.strRepr is None and self.expr is not None:
            self.strRepr = "%s:(%s)" % (self.__class__.__name__, _ustr(self.expr))
        return self.strRepr


class FollowedBy(ParseElementEnhance):
    def __init__(self, expr):
        super(FollowedBy, self).__init__(expr)
        self.mayReturnEmpty = True

    def parseImpl(self, instring, loc, doActions=True):


        _, ret = self.expr._parse(instring, loc, doActions=doActions)
        del ret[:]

        return loc, ret


class PrecededBy(ParseElementEnhance):
    def __init__(self, expr, retreat=None):
        super(PrecededBy, self).__init__(expr)
        self.expr = self.expr().leaveWhitespace()
        self.mayReturnEmpty = True
        self.mayIndexError = False
        self.exact = False
        if isinstance(expr, str):
            retreat = len(expr)
            self.exact = True
        elif isinstance(expr, (Literal, Keyword)):
            retreat = expr.matchLen
            self.exact = True
        elif isinstance(expr, (Word, CharsNotIn)) and expr.maxLen != _MAX_INT:
            retreat = expr.maxLen
            self.exact = True
        elif isinstance(expr, _PositionToken):
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
            instring_slice = instring[max(0, loc - self.retreat):loc]
            last_expr = ParseException(instring, loc, self.errmsg)
            for offset in range(1, min(loc, self.retreat + 1)+1):
                try:

                    _, ret = test_expr._parse(instring_slice, len(instring_slice) - offset)
                except ParseBaseException as pbe:
                    last_expr = pbe
                else:
                    break
            else:
                raise last_expr
        return loc, ret


class NotAny(ParseElementEnhance):
    def __init__(self, expr):
        super(NotAny, self).__init__(expr)

        self.skipWhitespace = False
        self.mayReturnEmpty = True
        self.errmsg = "Found unwanted token, " + _ustr(self.expr)

    def parseImpl(self, instring, loc, doActions=True):
        if self.expr.canParseNext(instring, loc):
            raise ParseException(instring, loc, self.errmsg, self)
        return loc, []

    def __str__(self):
        if hasattr(self, "name"):
            return self.name

        if self.strRepr is None:
            self.strRepr = "~{" + _ustr(self.expr) + "}"

        return self.strRepr

class _MultipleMatch(ParseElementEnhance):
    def __init__(self, expr, stopOn=None):
        super(_MultipleMatch, self).__init__(expr)
        self.saveAsList = True
        ender = stopOn
        if isinstance(ender, basestring):
            ender = self._literalStringClass(ender)
        self.stopOn(ender)

    def stopOn(self, ender):
        if isinstance(ender, basestring):
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
        loc, tokens = self_expr_parse(instring, loc, doActions, callPreParse=False)
        try:
            hasIgnoreExprs = (not not self.ignoreExprs)
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
        if __diag__.warn_ungrouped_named_tokens_in_collection:
            for e in [self.expr] + getattr(self.expr, 'exprs', []):
                if isinstance(e, ParserElement) and e.resultsName:
                    warnings.warn("{0}: setting results name {1!r} on {2} expression "
                                  "collides with {3!r} on contained expression".format("warn_ungrouped_named_tokens_in_collection",
                                                                                       name,
                                                                                       type(self).__name__,
                                                                                       e.resultsName),
                                  stacklevel=3)

        return super(_MultipleMatch, self)._setResultsName(name, listAllMatches)


class OneOrMore(_MultipleMatch):

    def __str__(self):
        if hasattr(self, "name"):
            return self.name

        if self.strRepr is None:
            self.strRepr = "{" + _ustr(self.expr) + "}..."

        return self.strRepr

class ZeroOrMore(_MultipleMatch):
    def __init__(self, expr, stopOn=None):
        super(ZeroOrMore, self).__init__(expr, stopOn=stopOn)
        self.mayReturnEmpty = True

    def parseImpl(self, instring, loc, doActions=True):
        try:
            return super(ZeroOrMore, self).parseImpl(instring, loc, doActions)
        except (ParseException, IndexError):
            return loc, []

    def __str__(self):
        if hasattr(self, "name"):
            return self.name

        if self.strRepr is None:
            self.strRepr = "[" + _ustr(self.expr) + "]..."

        return self.strRepr


class _NullToken(object):
    def __bool__(self):
        return False
    __nonzero__ = __bool__
    def __str__(self):
        return ""

class Optional(ParseElementEnhance):
    __optionalNotMatched = _NullToken()

    def __init__(self, expr, default=__optionalNotMatched):
        super(Optional, self).__init__(expr, savelist=False)
        self.saveAsList = self.expr.saveAsList
        self.defaultValue = default
        self.mayReturnEmpty = True

    def parseImpl(self, instring, loc, doActions=True):
        try:
            loc, tokens = self.expr._parse(instring, loc, doActions, callPreParse=False)
        except (ParseException, IndexError):
            if self.defaultValue is not self.__optionalNotMatched:
                if self.expr.resultsName:
                    tokens = ParseResults([self.defaultValue])
                    tokens[self.expr.resultsName] = self.defaultValue
                else:
                    tokens = [self.defaultValue]
            else:
                tokens = []
        return loc, tokens

    def __str__(self):
        if hasattr(self, "name"):
            return self.name

        if self.strRepr is None:
            self.strRepr = "[" + _ustr(self.expr) + "]"

        return self.strRepr

class SkipTo(ParseElementEnhance):
    def __init__(self, other, include=False, ignore=None, failOn=None):
        super(SkipTo, self).__init__(other)
        self.ignoreExpr = ignore
        self.mayReturnEmpty = True
        self.mayIndexError = False
        self.includeMatch = include
        self.saveAsList = False
        if isinstance(failOn, basestring):
            self.failOn = self._literalStringClass(failOn)
        else:
            self.failOn = failOn
        self.errmsg = "No match found for " + _ustr(self.expr)

    def parseImpl(self, instring, loc, doActions=True):
        startloc = loc
        instrlen = len(instring)
        expr = self.expr
        expr_parse = self.expr._parse
        self_failOn_canParseNext = self.failOn.canParseNext if self.failOn is not None else None
        self_ignoreExpr_tryParse = self.ignoreExpr.tryParse if self.ignoreExpr is not None else None

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
                expr_parse(instring, tmploc, doActions=False, callPreParse=False)
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
            loc, mat = expr_parse(instring, loc, doActions, callPreParse=False)
            skipresult += mat

        return loc, skipresult

class Forward(ParseElementEnhance):
    def __init__(self, other=None):
        super(Forward, self).__init__(other, savelist=False)

    def __lshift__(self, other):
        if isinstance(other, basestring):
            other = self._literalStringClass(other)
        self.expr = other
        self.strRepr = None
        self.mayIndexError = self.expr.mayIndexError
        self.mayReturnEmpty = self.expr.mayReturnEmpty
        self.setWhitespaceChars(self.expr.whiteChars)
        self.skipWhitespace = self.expr.skipWhitespace
        self.saveAsList = self.expr.saveAsList
        self.ignoreExprs.extend(self.expr.ignoreExprs)
        return self

    def __ilshift__(self, other):
        return self << other

    def leaveWhitespace(self):
        self.skipWhitespace = False
        return self

    def streamline(self):
        if not self.streamlined:
            self.streamlined = True
            if self.expr is not None:
                self.expr.streamline()
        return self

    def validate(self, validateTrace=None):
        if validateTrace is None:
            validateTrace = []

        if self not in validateTrace:
            tmp = validateTrace[:] + [self]
            if self.expr is not None:
                self.expr.validate(tmp)
        self.checkRecursion([])

    def __str__(self):
        if hasattr(self, "name"):
            return self.name
        if self.strRepr is not None:
            return self.strRepr


        self.strRepr = ": ..."


        retString = '...'
        try:
            if self.expr is not None:
                retString = _ustr(self.expr)[:1000]
            else:
                retString = "None"
        finally:
            self.strRepr = self.__class__.__name__ + ": " + retString
        return self.strRepr

    def copy(self):
        if self.expr is not None:
            return super(Forward, self).copy()
        else:
            ret = Forward()
            ret <<= self
            return ret

    def _setResultsName(self, name, listAllMatches=False):
        if __diag__.warn_name_set_on_empty_Forward:
            if self.expr is None:
                warnings.warn("{0}: setting results name {0!r} on {1} expression "
                              "that has no contained expression".format("warn_name_set_on_empty_Forward",
                                                                        name,
                                                                        type(self).__name__),
                              stacklevel=3)

        return super(Forward, self)._setResultsName(name, listAllMatches)

class TokenConverter(ParseElementEnhance):
    def __init__(self, expr, savelist=False):
        super(TokenConverter, self).__init__(expr)
        self.saveAsList = False

class Combine(TokenConverter):
    def __init__(self, expr, joinString="", adjacent=True):
        super(Combine, self).__init__(expr)

        if adjacent:
            self.leaveWhitespace()
        self.adjacent = adjacent
        self.skipWhitespace = True
        self.joinString = joinString
        self.callPreparse = True

    def ignore(self, other):
        if self.adjacent:
            ParserElement.ignore(self, other)
        else:
            super(Combine, self).ignore(other)
        return self

    def postParse(self, instring, loc, tokenlist):
        retToks = tokenlist.copy()
        del retToks[:]
        retToks += ParseResults(["".join(tokenlist._asStringList(self.joinString))], modal=self.modalResults)

        if self.resultsName and retToks.haskeys():
            return [retToks]
        else:
            return retToks

class Group(TokenConverter):
    def __init__(self, expr):
        super(Group, self).__init__(expr)
        self.saveAsList = True

    def postParse(self, instring, loc, tokenlist):
        return [tokenlist]

class Dict(TokenConverter):
    def __init__(self, expr):
        super(Dict, self).__init__(expr)
        self.saveAsList = True

    def postParse(self, instring, loc, tokenlist):
        for i, tok in enumerate(tokenlist):
            if len(tok) == 0:
                continue
            ikey = tok[0]
            if isinstance(ikey, int):
                ikey = _ustr(tok[0]).strip()
            if len(tok) == 1:
                tokenlist[ikey] = _ParseResultsWithOffset("", i)
            elif len(tok) == 2 and not isinstance(tok[1], ParseResults):
                tokenlist[ikey] = _ParseResultsWithOffset(tok[1], i)
            else:
                dictvalue = tok.copy()
                del dictvalue[0]
                if len(dictvalue) != 1 or (isinstance(dictvalue, ParseResults) and dictvalue.haskeys()):
                    tokenlist[ikey] = _ParseResultsWithOffset(dictvalue, i)
                else:
                    tokenlist[ikey] = _ParseResultsWithOffset(dictvalue[0], i)

        if self.resultsName:
            return [tokenlist]
        else:
            return tokenlist


class Suppress(TokenConverter):
    def postParse(self, instring, loc, tokenlist):
        return []

    def suppress(self):
        return self


class OnlyOnce(object):
    def __init__(self, methodCall):
        self.callable = _trim_arity(methodCall)
        self.called = False
    def __call__(self, s, l, t):
        if not self.called:
            results = self.callable(s, l, t)
            self.called = True
            return results
        raise ParseException(s, l, "")
    def reset(self):
        self.called = False

def traceParseAction(f):
    f = _trim_arity(f)
    def z(*paArgs):
        thisFunc = f.__name__
        s, l, t = paArgs[-3:]
        if len(paArgs) > 3:
            thisFunc = paArgs[0].__class__.__name__ + '.' + thisFunc
        sys.stderr.write(">>entering %s(line: '%s', %d, %r)\n" % (thisFunc, line(l, s), l, t))
        try:
            ret = f(*paArgs)
        except Exception as exc:
            sys.stderr.write("<<leaving %s (exception: %s)\n" % (thisFunc, exc))
            raise
        sys.stderr.write("<<leaving %s (ret: %r)\n" % (thisFunc, ret))
        return ret
    try:
        z.__name__ = f.__name__
    except AttributeError:
        pass
    return z


def delimitedList(expr, delim=",", combine=False):
    dlName = _ustr(expr) + " [" + _ustr(delim) + " " + _ustr(expr) + "]..."
    if combine:
        return Combine(expr + ZeroOrMore(delim + expr)).setName(dlName)
    else:
        return (expr + ZeroOrMore(Suppress(delim) + expr)).setName(dlName)

def countedArray(expr, intExpr=None):
    arrayExpr = Forward()
    def countFieldParseAction(s, l, t):
        n = t[0]
        arrayExpr << (n and Group(And([expr] * n)) or Group(empty))
        return []
    if intExpr is None:
        intExpr = Word(nums).setParseAction(lambda t: int(t[0]))
    else:
        intExpr = intExpr.copy()
    intExpr.setName("arrayLen")
    intExpr.addParseAction(countFieldParseAction, callDuringTry=True)
    return (intExpr + arrayExpr).setName('(len) ' + _ustr(expr) + '...')

def _flatten(L):
    ret = []
    for i in L:
        if isinstance(i, list):
            ret.extend(_flatten(i))
        else:
            ret.append(i)
    return ret

def matchPreviousLiteral(expr):
    rep = Forward()
    def copyTokenToRepeater(s, l, t):
        if t:
            if len(t) == 1:
                rep << t[0]
            else:

                tflat = _flatten(t.asList())
                rep << And(Literal(tt) for tt in tflat)
        else:
            rep << Empty()
    expr.addParseAction(copyTokenToRepeater, callDuringTry=True)
    rep.setName('(prev) ' + _ustr(expr))
    return rep

def matchPreviousExpr(expr):
    rep = Forward()
    e2 = expr.copy()
    rep <<= e2
    def copyTokenToRepeater(s, l, t):
        matchTokens = _flatten(t.asList())
        def mustMatchTheseTokens(s, l, t):
            theseTokens = _flatten(t.asList())
            if theseTokens != matchTokens:
                raise ParseException('', 0, '')
        rep.setParseAction(mustMatchTheseTokens, callDuringTry=True)
    expr.addParseAction(copyTokenToRepeater, callDuringTry=True)
    rep.setName('(prev) ' + _ustr(expr))
    return rep

def _escapeRegexRangeChars(s):

    for c in r"\^-[]":
        s = s.replace(c, _bslash + c)
    s = s.replace("\n", r"\n")
    s = s.replace("\t", r"\t")
    return _ustr(s)

def oneOf(strs, caseless=False, useRegex=True, asKeyword=False):
    if isinstance(caseless, basestring):
        warnings.warn("More than one string argument passed to oneOf, pass "
                      "choices as a list or space-delimited string", stacklevel=2)

    if caseless:
        isequal = (lambda a, b: a.upper() == b.upper())
        masks = (lambda a, b: b.upper().startswith(a.upper()))
        parseElementClass = CaselessKeyword if asKeyword else CaselessLiteral
    else:
        isequal = (lambda a, b: a == b)
        masks = (lambda a, b: b.startswith(a))
        parseElementClass = Keyword if asKeyword else Literal

    symbols = []
    if isinstance(strs, basestring):
        symbols = strs.split()
    elif isinstance(strs, Iterable):
        symbols = list(strs)
    else:
        warnings.warn("Invalid argument to oneOf, expected string or iterable",
                      SyntaxWarning, stacklevel=2)
    if not symbols:
        return NoMatch()

    if not asKeyword:


        i = 0
        while i < len(symbols) - 1:
            cur = symbols[i]
            for j, other in enumerate(symbols[i + 1:]):
                if isequal(other, cur):
                    del symbols[i + j + 1]
                    break
                elif masks(cur, other):
                    del symbols[i + j + 1]
                    symbols.insert(i, other)
                    break
            else:
                i += 1

    if not (caseless or asKeyword) and useRegex:

        try:
            if len(symbols) == len("".join(symbols)):
                return Regex("[%s]" % "".join(_escapeRegexRangeChars(sym) for sym in symbols)).setName(' | '.join(symbols))
            else:
                return Regex("|".join(re.escape(sym) for sym in symbols)).setName(' | '.join(symbols))
        except Exception:
            warnings.warn("Exception creating Regex for oneOf, building MatchFirst",
                    SyntaxWarning, stacklevel=2)


    return MatchFirst(parseElementClass(sym) for sym in symbols).setName(' | '.join(symbols))

def dictOf(key, value):
    return Dict(OneOrMore(Group(key + value)))

def originalTextFor(expr, asString=True):
    locMarker = Empty().setParseAction(lambda s, loc, t: loc)
    endlocMarker = locMarker.copy()
    endlocMarker.callPreparse = False
    matchExpr = locMarker("_original_start") + expr + endlocMarker("_original_end")
    if asString:
        extractText = lambda s, l, t: s[t._original_start: t._original_end]
    else:
        def extractText(s, l, t):
            t[:] = [s[t.pop('_original_start'):t.pop('_original_end')]]
    matchExpr.setParseAction(extractText)
    matchExpr.ignoreExprs = expr.ignoreExprs
    return matchExpr

def ungroup(expr):
    return TokenConverter(expr).addParseAction(lambda t: t[0])

def locatedExpr(expr):
    locator = Empty().setParseAction(lambda s, l, t: l)
    return Group(locator("locn_start") + expr("value") + locator.copy().leaveWhitespace()("locn_end"))


empty       = Empty().setName("empty")
lineStart   = LineStart().setName("lineStart")
lineEnd     = LineEnd().setName("lineEnd")
stringStart = StringStart().setName("stringStart")
stringEnd   = StringEnd().setName("stringEnd")

_escapedPunc = Word(_bslash, r"\[]-*.$+^?()~ ", exact=2).setParseAction(lambda s, l, t: t[0][1])
_escapedHexChar = Regex(r"\\0?[xX][0-9a-fA-F]+").setParseAction(lambda s, l, t: unichr(int(t[0].lstrip(r'\0x'), 16)))
_escapedOctChar = Regex(r"\\0[0-7]+").setParseAction(lambda s, l, t: unichr(int(t[0][1:], 8)))
_singleChar = _escapedPunc | _escapedHexChar | _escapedOctChar | CharsNotIn(r'\]', exact=1)
_charRange = Group(_singleChar + Suppress("-") + _singleChar)
_reBracketExpr = Literal("[") + Optional("^").setResultsName("negate") + Group(OneOrMore(_charRange | _singleChar)).setResultsName("body") + "]"

def srange(s):
    _expanded = lambda p: p if not isinstance(p, ParseResults) else ''.join(unichr(c) for c in range(ord(p[0]), ord(p[1]) + 1))
    try:
        return "".join(_expanded(part) for part in _reBracketExpr.parseString(s).body)
    except Exception:
        return ""

def matchOnlyAtCol(n):
    def verifyCol(strg, locn, toks):
        if col(locn, strg) != n:
            raise ParseException(strg, locn, "matched token not at column %d" % n)
    return verifyCol

def replaceWith(replStr):
    return lambda s, l, t: [replStr]

def removeQuotes(s, l, t):
    return t[0][1:-1]

def tokenMap(func, *args):
    def pa(s, l, t):
        return [func(tokn, *args) for tokn in t]

    try:
        func_name = getattr(func, '__name__',
                            getattr(func, '__class__').__name__)
    except Exception:
        func_name = str(func)
    pa.__name__ = func_name

    return pa

upcaseTokens = tokenMap(lambda t: _ustr(t).upper())
"""(Deprecated) Helper parse action to convert tokens to upper case.
Deprecated in favor of :class:`pyparsing_common.upcaseTokens`"""

downcaseTokens = tokenMap(lambda t: _ustr(t).lower())
"""(Deprecated) Helper parse action to convert tokens to lower case.
Deprecated in favor of :class:`pyparsing_common.downcaseTokens`"""

def _makeTags(tagStr, xml,
              suppress_LT=Suppress("<"),
              suppress_GT=Suppress(">")):
    if isinstance(tagStr, basestring):
        resname = tagStr
        tagStr = Keyword(tagStr, caseless=not xml)
    else:
        resname = tagStr.name

    tagAttrName = Word(alphas, alphanums + "_-:")
    if xml:
        tagAttrValue = dblQuotedString.copy().setParseAction(removeQuotes)
        openTag = (suppress_LT
                   + tagStr("tag")
                   + Dict(ZeroOrMore(Group(tagAttrName + Suppress("=") + tagAttrValue)))
                   + Optional("/", default=[False])("empty").setParseAction(lambda s, l, t: t[0] == '/')
                   + suppress_GT)
    else:
        tagAttrValue = quotedString.copy().setParseAction(removeQuotes) | Word(printables, excludeChars=">")
        openTag = (suppress_LT
                   + tagStr("tag")
                   + Dict(ZeroOrMore(Group(tagAttrName.setParseAction(downcaseTokens)
                                           + Optional(Suppress("=") + tagAttrValue))))
                   + Optional("/", default=[False])("empty").setParseAction(lambda s, l, t: t[0] == '/')
                   + suppress_GT)
    closeTag = Combine(_L("</") + tagStr + ">", adjacent=False)

    openTag.setName("<%s>" % resname)

    openTag.addParseAction(lambda t: t.__setitem__("start" + "".join(resname.replace(":", " ").title().split()), t.copy()))
    closeTag = closeTag("end" + "".join(resname.replace(":", " ").title().split())).setName("</%s>" % resname)
    openTag.tag = resname
    closeTag.tag = resname
    openTag.tag_body = SkipTo(closeTag())
    return openTag, closeTag

def makeHTMLTags(tagStr):
    return _makeTags(tagStr, False)

def makeXMLTags(tagStr):
    return _makeTags(tagStr, True)

def withAttribute(*args, **attrDict):
    if args:
        attrs = args[:]
    else:
        attrs = attrDict.items()
    attrs = [(k, v) for k, v in attrs]
    def pa(s, l, tokens):
        for attrName, attrValue in attrs:
            if attrName not in tokens:
                raise ParseException(s, l, "no matching attribute " + attrName)
            if attrValue != withAttribute.ANY_VALUE and tokens[attrName] != attrValue:
                raise ParseException(s, l, "attribute '%s' has value '%s', must be '%s'" %
                                            (attrName, tokens[attrName], attrValue))
    return pa
withAttribute.ANY_VALUE = object()

def withClass(classname, namespace=''):
    classattr = "%s:class" % namespace if namespace else "class"
    return withAttribute(**{classattr: classname})

opAssoc = SimpleNamespace()
opAssoc.LEFT = object()
opAssoc.RIGHT = object()

def infixNotation(baseExpr, opList, lpar=Suppress('('), rpar=Suppress(')')):

    class _FB(FollowedBy):
        def parseImpl(self, instring, loc, doActions=True):
            self.expr.tryParse(instring, loc)
            return loc, []

    ret = Forward()
    lastExpr = baseExpr | (lpar + ret + rpar)
    for i, operDef in enumerate(opList):
        opExpr, arity, rightLeftAssoc, pa = (operDef + (None, ))[:4]
        termName = "%s term" % opExpr if arity < 3 else "%s%s term" % opExpr
        if arity == 3:
            if opExpr is None or len(opExpr) != 2:
                raise ValueError(
                    "if numterms=3, opExpr must be a tuple or list of two expressions")
            opExpr1, opExpr2 = opExpr
        thisExpr = Forward().setName(termName)
        if rightLeftAssoc == opAssoc.LEFT:
            if arity == 1:
                matchExpr = _FB(lastExpr + opExpr) + Group(lastExpr + OneOrMore(opExpr))
            elif arity == 2:
                if opExpr is not None:
                    matchExpr = _FB(lastExpr + opExpr + lastExpr) + Group(lastExpr + OneOrMore(opExpr + lastExpr))
                else:
                    matchExpr = _FB(lastExpr + lastExpr) + Group(lastExpr + OneOrMore(lastExpr))
            elif arity == 3:
                matchExpr = (_FB(lastExpr + opExpr1 + lastExpr + opExpr2 + lastExpr)
                             + Group(lastExpr + OneOrMore(opExpr1 + lastExpr + opExpr2 + lastExpr)))
            else:
                raise ValueError("operator must be unary (1), binary (2), or ternary (3)")
        elif rightLeftAssoc == opAssoc.RIGHT:
            if arity == 1:

                if not isinstance(opExpr, Optional):
                    opExpr = Optional(opExpr)
                matchExpr = _FB(opExpr.expr + thisExpr) + Group(opExpr + thisExpr)
            elif arity == 2:
                if opExpr is not None:
                    matchExpr = _FB(lastExpr + opExpr + thisExpr) + Group(lastExpr + OneOrMore(opExpr + thisExpr))
                else:
                    matchExpr = _FB(lastExpr + thisExpr) + Group(lastExpr + OneOrMore(thisExpr))
            elif arity == 3:
                matchExpr = (_FB(lastExpr + opExpr1 + thisExpr + opExpr2 + thisExpr)
                             + Group(lastExpr + opExpr1 + thisExpr + opExpr2 + thisExpr))
            else:
                raise ValueError("operator must be unary (1), binary (2), or ternary (3)")
        else:
            raise ValueError("operator must indicate right or left associativity")
        if pa:
            if isinstance(pa, (tuple, list)):
                matchExpr.setParseAction(*pa)
            else:
                matchExpr.setParseAction(pa)
        thisExpr <<= (matchExpr.setName(termName) | lastExpr)
        lastExpr = thisExpr
    ret <<= lastExpr
    return ret

operatorPrecedence = infixNotation
"""(Deprecated) Former name of :class:`infixNotation`, will be
dropped in a future release."""

dblQuotedString = Combine(Regex(r'"(?:[^"\n\r\\]|(?:"")|(?:\\(?:[^x]|x[0-9a-fA-F]+)))*') + '"').setName("string enclosed in double quotes")
sglQuotedString = Combine(Regex(r"'(?:[^'\n\r\\]|(?:'')|(?:\\(?:[^x]|x[0-9a-fA-F]+)))*") + "'").setName("string enclosed in single quotes")
quotedString = Combine(Regex(r'"(?:[^"\n\r\\]|(?:"")|(?:\\(?:[^x]|x[0-9a-fA-F]+)))*') + '"'
                       | Regex(r"'(?:[^'\n\r\\]|(?:'')|(?:\\(?:[^x]|x[0-9a-fA-F]+)))*") + "'").setName("quotedString using single or double quotes")
unicodeString = Combine(_L('u') + quotedString.copy()).setName("unicode string literal")

def nestedExpr(opener="(", closer=")", content=None, ignoreExpr=quotedString.copy()):
    if opener == closer:
        raise ValueError("opening and closing strings cannot be the same")
    if content is None:
        if isinstance(opener, basestring) and isinstance(closer, basestring):
            if len(opener) == 1 and len(closer) == 1:
                if ignoreExpr is not None:
                    content = (Combine(OneOrMore(~ignoreExpr
                                                 + CharsNotIn(opener
                                                              + closer
                                                              + ParserElement.DEFAULT_WHITE_CHARS, exact=1)
                                                 )
                                       ).setParseAction(lambda t: t[0].strip()))
                else:
                    content = (empty.copy() + CharsNotIn(opener
                                                         + closer
                                                         + ParserElement.DEFAULT_WHITE_CHARS
                                                         ).setParseAction(lambda t: t[0].strip()))
            else:
                if ignoreExpr is not None:
                    content = (Combine(OneOrMore(~ignoreExpr
                                                 + ~Literal(opener)
                                                 + ~Literal(closer)
                                                 + CharsNotIn(ParserElement.DEFAULT_WHITE_CHARS, exact=1))
                                       ).setParseAction(lambda t: t[0].strip()))
                else:
                    content = (Combine(OneOrMore(~Literal(opener)
                                                 + ~Literal(closer)
                                                 + CharsNotIn(ParserElement.DEFAULT_WHITE_CHARS, exact=1))
                                       ).setParseAction(lambda t: t[0].strip()))
        else:
            raise ValueError("opening and closing arguments must be strings if no content expression is given")
    ret = Forward()
    if ignoreExpr is not None:
        ret <<= Group(Suppress(opener) + ZeroOrMore(ignoreExpr | ret | content) + Suppress(closer))
    else:
        ret <<= Group(Suppress(opener) + ZeroOrMore(ret | content)  + Suppress(closer))
    ret.setName('nested %s%s expression' % (opener, closer))
    return ret

def indentedBlock(blockStatementExpr, indentStack, indent=True):
    backup_stack = indentStack[:]

    def reset_stack():
        indentStack[:] = backup_stack

    def checkPeerIndent(s, l, t):
        if l >= len(s): return
        curCol = col(l, s)
        if curCol != indentStack[-1]:
            if curCol > indentStack[-1]:
                raise ParseException(s, l, "illegal nesting")
            raise ParseException(s, l, "not a peer entry")

    def checkSubIndent(s, l, t):
        curCol = col(l, s)
        if curCol > indentStack[-1]:
            indentStack.append(curCol)
        else:
            raise ParseException(s, l, "not a subentry")

    def checkUnindent(s, l, t):
        if l >= len(s): return
        curCol = col(l, s)
        if not(indentStack and curCol in indentStack):
            raise ParseException(s, l, "not an unindent")
        if curCol < indentStack[-1]:
            indentStack.pop()

    NL = OneOrMore(LineEnd().setWhitespaceChars("\t ").suppress(), stopOn=StringEnd())
    INDENT = (Empty() + Empty().setParseAction(checkSubIndent)).setName('INDENT')
    PEER   = Empty().setParseAction(checkPeerIndent).setName('')
    UNDENT = Empty().setParseAction(checkUnindent).setName('UNINDENT')
    if indent:
        smExpr = Group(Optional(NL)
                       + INDENT
                       + OneOrMore(PEER + Group(blockStatementExpr) + Optional(NL), stopOn=StringEnd())
                       + UNDENT)
    else:
        smExpr = Group(Optional(NL)
                       + OneOrMore(PEER + Group(blockStatementExpr) + Optional(NL), stopOn=StringEnd())
                       + UNDENT)
    smExpr.setFailAction(lambda a, b, c, d: reset_stack())
    blockStatementExpr.ignore(_bslash + LineEnd())
    return smExpr.setName('indented block')

alphas8bit = srange(r"[\0xc0-\0xd6\0xd8-\0xf6\0xf8-\0xff]")
punc8bit = srange(r"[\0xa1-\0xbf\0xd7\0xf7]")

anyOpenTag, anyCloseTag = makeHTMLTags(Word(alphas, alphanums + "_:").setName('any tag'))
_htmlEntityMap = dict(zip("gt lt amp nbsp quot apos".split(), '><& "\''))
commonHTMLEntity = Regex('&(?P<entity>' + '|'.join(_htmlEntityMap.keys()) +");").setName("common HTML entity")
def replaceHTMLEntity(t):
    return _htmlEntityMap.get(t.entity)


cStyleComment = Combine(Regex(r"/\*(?:[^*]|\*(?!/))*") + '*/').setName("C style comment")
"Comment of the form ``/* ... */``"

htmlComment = Regex(r"<!--[\s\S]*?-->").setName("HTML comment")
"Comment of the form ``<!-- ... -->``"

restOfLine = Regex(r".*").leaveWhitespace().setName("rest of line")
dblSlashComment = Regex(r"//(?:\\\n|[^\n])*").setName("// comment")
"Comment of the form ``// ... (to end of line)``"

cppStyleComment = Combine(Regex(r"/\*(?:[^*]|\*(?!/))*") + '*/' | dblSlashComment).setName("C++ style comment")
"Comment of either form :class:`cStyleComment` or :class:`dblSlashComment`"

javaStyleComment = cppStyleComment
"Same as :class:`cppStyleComment`"

pythonStyleComment = Regex(r"#.*").setName("Python style comment")
"Comment of the form ``# ... (to end of line)``"

_commasepitem = Combine(OneOrMore(Word(printables, excludeChars=',')
                                  + Optional(Word(" \t")
                                             + ~Literal(",") + ~LineEnd()))).streamline().setName("commaItem")
commaSeparatedList = delimitedList(Optional(quotedString.copy() | _commasepitem, default="")).setName("commaSeparatedList")
"""(Deprecated) Predefined expression of 1 or more printable words or
quoted strings, separated by commas.

This expression is deprecated in favor of :class:`pyparsing_common.comma_separated_list`.
"""


class pyparsing_common:

    convertToInteger = tokenMap(int)
    """
    Parse action for converting parsed integers to Python int
    """

    convertToFloat = tokenMap(float)
    """
    Parse action for converting parsed numbers to Python float
    """

    integer = Word(nums).setName("integer").setParseAction(convertToInteger)
    """expression that parses an unsigned integer, returns an int"""

    hex_integer = Word(hexnums).setName("hex integer").setParseAction(tokenMap(int, 16))
    """expression that parses a hexadecimal integer, returns an int"""

    signed_integer = Regex(r'[+-]?\d+').setName("signed integer").setParseAction(convertToInteger)
    """expression that parses an integer with optional leading sign, returns an int"""

    fraction = (signed_integer().setParseAction(convertToFloat) + '/' + signed_integer().setParseAction(convertToFloat)).setName("fraction")
    """fractional expression of an integer divided by an integer, returns a float"""
    fraction.addParseAction(lambda t: t[0]/t[-1])

    mixed_integer = (fraction | signed_integer + Optional(Optional('-').suppress() + fraction)).setName("fraction or mixed integer-fraction")
    """mixed integer of the form 'integer - fraction', with optional leading integer, returns float"""
    mixed_integer.addParseAction(sum)

    real = Regex(r'[+-]?(?:\d+\.\d*|\.\d+)').setName("real number").setParseAction(convertToFloat)
    """expression that parses a floating point number and returns a float"""

    sci_real = Regex(r'[+-]?(?:\d+(?:[eE][+-]?\d+)|(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?)').setName("real number with scientific notation").setParseAction(convertToFloat)
    """expression that parses a floating point number with optional
    scientific notation and returns a float"""


    number = (sci_real | real | signed_integer).streamline()
    """any numeric expression, returns the corresponding Python type"""

    fnumber = Regex(r'[+-]?\d+\.?\d*([eE][+-]?\d+)?').setName("fnumber").setParseAction(convertToFloat)
    """any int or real number, returned as float"""

    identifier = Word(alphas + '_', alphanums + '_').setName("identifier")
    """typical code identifier (leading alpha or '_', followed by 0 or more alphas, nums, or '_')"""

    ipv4_address = Regex(r'(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}').setName("IPv4 address")
    "IPv4 address (``0.0.0.0 - 255.255.255.255``)"

    _ipv6_part = Regex(r'[0-9a-fA-F]{1,4}').setName("hex_integer")
    _full_ipv6_address = (_ipv6_part + (':' + _ipv6_part) * 7).setName("full IPv6 address")
    _short_ipv6_address = (Optional(_ipv6_part + (':' + _ipv6_part) * (0, 6))
                           + "::"
                           + Optional(_ipv6_part + (':' + _ipv6_part) * (0, 6))
                           ).setName("short IPv6 address")
    _short_ipv6_address.addCondition(lambda t: sum(1 for tt in t if pyparsing_common._ipv6_part.matches(tt)) < 8)
    _mixed_ipv6_address = ("::ffff:" + ipv4_address).setName("mixed IPv6 address")
    ipv6_address = Combine((_full_ipv6_address | _mixed_ipv6_address | _short_ipv6_address).setName("IPv6 address")).setName("IPv6 address")
    "IPv6 address (long, short, or mixed form)"

    mac_address = Regex(r'[0-9a-fA-F]{2}([:.-])[0-9a-fA-F]{2}(?:\1[0-9a-fA-F]{2}){4}').setName("MAC address")
    "MAC address xx:xx:xx:xx:xx (may also have '-' or '.' delimiters)"

    @staticmethod
    def convertToDate(fmt="%Y-%m-%d"):
        def cvt_fn(s, l, t):
            try:
                return datetime.strptime(t[0], fmt).date()
            except ValueError as ve:
                raise ParseException(s, l, str(ve))
        return cvt_fn

    @staticmethod
    def convertToDatetime(fmt="%Y-%m-%dT%H:%M:%S.%f"):
        def cvt_fn(s, l, t):
            try:
                return datetime.strptime(t[0], fmt)
            except ValueError as ve:
                raise ParseException(s, l, str(ve))
        return cvt_fn

    iso8601_date = Regex(r'(?P<year>\d{4})(?:-(?P<month>\d\d)(?:-(?P<day>\d\d))?)?').setName("ISO8601 date")
    "ISO8601 date (``yyyy-mm-dd``)"

    iso8601_datetime = Regex(r'(?P<year>\d{4})-(?P<month>\d\d)-(?P<day>\d\d)[T ](?P<hour>\d\d):(?P<minute>\d\d)(:(?P<second>\d\d(\.\d*)?)?)?(?P<tz>Z|[+-]\d\d:?\d\d)?').setName("ISO8601 datetime")
    "ISO8601 datetime (``yyyy-mm-ddThh:mm:ss.s(Z|+-00:00)``) - trailing seconds, milliseconds, and timezone optional; accepts separating ``'T'`` or ``' '``"

    uuid = Regex(r'[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}').setName("UUID")
    "UUID (``xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx``)"

    _html_stripper = anyOpenTag.suppress() | anyCloseTag.suppress()
    @staticmethod
    def stripHTMLTags(s, l, tokens):
        return pyparsing_common._html_stripper.transformString(tokens[0])

    _commasepitem = Combine(OneOrMore(~Literal(",")
                                      + ~LineEnd()
                                      + Word(printables, excludeChars=',')
                                      + Optional(White(" \t")))).streamline().setName("commaItem")
    comma_separated_list = delimitedList(Optional(quotedString.copy()
                                                  | _commasepitem, default='')
                                         ).setName("comma separated list")
    """Predefined expression of 1 or more printable words or quoted strings, separated by commas."""

    upcaseTokens = staticmethod(tokenMap(lambda t: _ustr(t).upper()))
    """Parse action to convert tokens to upper case."""

    downcaseTokens = staticmethod(tokenMap(lambda t: _ustr(t).lower()))
    """Parse action to convert tokens to lower case."""


class _lazyclassproperty(object):
    def __init__(self, fn):
        self.fn = fn
        self.__doc__ = fn.__doc__
        self.__name__ = fn.__name__

    def __get__(self, obj, cls):
        if cls is None:
            cls = type(obj)
        if not hasattr(cls, '_intern') or any(cls._intern is getattr(superclass, '_intern', [])
                                              for superclass in cls.__mro__[1:]):
            cls._intern = {}
        attrname = self.fn.__name__
        if attrname not in cls._intern:
            cls._intern[attrname] = self.fn(cls)
        return cls._intern[attrname]


class unicode_set(object):
    _ranges = []

    @classmethod
    def _get_chars_for_ranges(cls):
        ret = []
        for cc in cls.__mro__:
            if cc is unicode_set:
                break
            for rr in cc._ranges:
                ret.extend(range(rr[0], rr[-1] + 1))
        return [unichr(c) for c in sorted(set(ret))]

    @_lazyclassproperty
    def printables(cls):
        return u''.join(filterfalse(unicode.isspace, cls._get_chars_for_ranges()))

    @_lazyclassproperty
    def alphas(cls):
        return u''.join(filter(unicode.isalpha, cls._get_chars_for_ranges()))

    @_lazyclassproperty
    def nums(cls):
        return u''.join(filter(unicode.isdigit, cls._get_chars_for_ranges()))

    @_lazyclassproperty
    def alphanums(cls):
        return cls.alphas + cls.nums


class pyparsing_unicode(unicode_set):
    _ranges = [(32, sys.maxunicode)]

    class Latin1(unicode_set):
        _ranges = [(0x0020, 0x007e), (0x00a0, 0x00ff),]

    class LatinA(unicode_set):
        _ranges = [(0x0100, 0x017f),]

    class LatinB(unicode_set):
        _ranges = [(0x0180, 0x024f),]

    class Greek(unicode_set):
        _ranges = [
            (0x0370, 0x03ff), (0x1f00, 0x1f15), (0x1f18, 0x1f1d), (0x1f20, 0x1f45), (0x1f48, 0x1f4d),
            (0x1f50, 0x1f57), (0x1f59,), (0x1f5b,), (0x1f5d,), (0x1f5f, 0x1f7d), (0x1f80, 0x1fb4), (0x1fb6, 0x1fc4),
            (0x1fc6, 0x1fd3), (0x1fd6, 0x1fdb), (0x1fdd, 0x1fef), (0x1ff2, 0x1ff4), (0x1ff6, 0x1ffe),
        ]

    class Cyrillic(unicode_set):
        _ranges = [(0x0400, 0x04ff)]

    class Chinese(unicode_set):
        _ranges = [(0x4e00, 0x9fff), (0x3000, 0x303f),]

    class Japanese(unicode_set):
        _ranges = []

        class Kanji(unicode_set):
            _ranges = [(0x4E00, 0x9Fbf), (0x3000, 0x303f),]

        class Hiragana(unicode_set):
            _ranges = [(0x3040, 0x309f),]

        class Katakana(unicode_set):
            _ranges = [(0x30a0, 0x30ff),]

    class Korean(unicode_set):
        _ranges = [(0xac00, 0xd7af), (0x1100, 0x11ff), (0x3130, 0x318f), (0xa960, 0xa97f), (0xd7b0, 0xd7ff), (0x3000, 0x303f),]

    class CJK(Chinese, Japanese, Korean):
        pass

    class Thai(unicode_set):
        _ranges = [(0x0e01, 0x0e3a), (0x0e3f, 0x0e5b),]

    class Arabic(unicode_set):
        _ranges = [(0x0600, 0x061b), (0x061e, 0x06ff), (0x0700, 0x077f),]

    class Hebrew(unicode_set):
        _ranges = [(0x0590, 0x05ff),]

    class Devanagari(unicode_set):
        _ranges = [(0x0900, 0x097f), (0xa8e0, 0xa8ff)]

pyparsing_unicode.Japanese._ranges = (pyparsing_unicode.Japanese.Kanji._ranges
                                      + pyparsing_unicode.Japanese.Hiragana._ranges
                                      + pyparsing_unicode.Japanese.Katakana._ranges)


if PY_3:
    setattr(pyparsing_unicode, u"العربية", pyparsing_unicode.Arabic)
    setattr(pyparsing_unicode, u"中文", pyparsing_unicode.Chinese)
    setattr(pyparsing_unicode, u"кириллица", pyparsing_unicode.Cyrillic)
    setattr(pyparsing_unicode, u"Ελληνικά", pyparsing_unicode.Greek)
    setattr(pyparsing_unicode, u"עִברִית", pyparsing_unicode.Hebrew)
    setattr(pyparsing_unicode, u"日本語", pyparsing_unicode.Japanese)
    setattr(pyparsing_unicode.Japanese, u"漢字", pyparsing_unicode.Japanese.Kanji)
    setattr(pyparsing_unicode.Japanese, u"カタカナ", pyparsing_unicode.Japanese.Katakana)
    setattr(pyparsing_unicode.Japanese, u"ひらがな", pyparsing_unicode.Japanese.Hiragana)
    setattr(pyparsing_unicode, u"한국어", pyparsing_unicode.Korean)
    setattr(pyparsing_unicode, u"ไทย", pyparsing_unicode.Thai)
    setattr(pyparsing_unicode, u"देवनागरी", pyparsing_unicode.Devanagari)


class pyparsing_test:

    class reset_pyparsing_context:

        def __init__(self):
            self._save_context = {}

        def save(self):
            self._save_context["default_whitespace"] = ParserElement.DEFAULT_WHITE_CHARS
            self._save_context["default_keyword_chars"] = Keyword.DEFAULT_KEYWORD_CHARS
            self._save_context[
                "literal_string_class"
            ] = ParserElement._literalStringClass
            self._save_context["packrat_enabled"] = ParserElement._packratEnabled
            self._save_context["packrat_parse"] = ParserElement._parse
            self._save_context["__diag__"] = {
                name: getattr(__diag__, name) for name in __diag__._all_names
            }
            self._save_context["__compat__"] = {
                "collect_all_And_tokens": __compat__.collect_all_And_tokens
            }
            return self

        def restore(self):

            if (
                ParserElement.DEFAULT_WHITE_CHARS
                != self._save_context["default_whitespace"]
            ):
                ParserElement.setDefaultWhitespaceChars(
                    self._save_context["default_whitespace"]
                )
            Keyword.DEFAULT_KEYWORD_CHARS = self._save_context["default_keyword_chars"]
            ParserElement.inlineLiteralsUsing(
                self._save_context["literal_string_class"]
            )
            for name, value in self._save_context["__diag__"].items():
                setattr(__diag__, name, value)
            ParserElement._packratEnabled = self._save_context["packrat_enabled"]
            ParserElement._parse = self._save_context["packrat_parse"]
            __compat__.collect_all_And_tokens = self._save_context["__compat__"]

        def __enter__(self):
            return self.save()

        def __exit__(self, *args):
            return self.restore()

    class TestParseResultsAsserts:
        def assertParseResultsEquals(
            self, result, expected_list=None, expected_dict=None, msg=None
        ):
            if expected_list is not None:
                self.assertEqual(expected_list, result.asList(), msg=msg)
            if expected_dict is not None:
                self.assertEqual(expected_dict, result.asDict(), msg=msg)

        def assertParseAndCheckList(
            self, expr, test_string, expected_list, msg=None, verbose=True
        ):
            result = expr.parseString(test_string, parseAll=True)
            if verbose:
                print(result.dump())
            self.assertParseResultsEquals(result, expected_list=expected_list, msg=msg)

        def assertParseAndCheckDict(
            self, expr, test_string, expected_dict, msg=None, verbose=True
        ):
            result = expr.parseString(test_string, parseAll=True)
            if verbose:
                print(result.dump())
            self.assertParseResultsEquals(result, expected_dict=expected_dict, msg=msg)

        def assertRunTestResults(
            self, run_tests_report, expected_parse_results=None, msg=None
        ):
            run_test_success, run_test_results = run_tests_report

            if expected_parse_results is not None:
                merged = [
                    (rpt[0], rpt[1], expected)
                    for rpt, expected in zip(run_test_results, expected_parse_results)
                ]
                for test_string, result, expected in merged:


                    fail_msg = next(
                        (exp for exp in expected if isinstance(exp, str)), None
                    )
                    expected_exception = next(
                        (
                            exp
                            for exp in expected
                            if isinstance(exp, type) and issubclass(exp, Exception)
                        ),
                        None,
                    )
                    if expected_exception is not None:
                        with self.assertRaises(
                            expected_exception=expected_exception, msg=fail_msg or msg
                        ):
                            if isinstance(result, Exception):
                                raise result
                    else:
                        expected_list = next(
                            (exp for exp in expected if isinstance(exp, list)), None
                        )
                        expected_dict = next(
                            (exp for exp in expected if isinstance(exp, dict)), None
                        )
                        if (expected_list, expected_dict) != (None, None):
                            self.assertParseResultsEquals(
                                result,
                                expected_list=expected_list,
                                expected_dict=expected_dict,
                                msg=fail_msg or msg,
                            )
                        else:

                            print("no validation for {!r}".format(test_string))


            self.assertTrue(
                run_test_success, msg=msg if msg is not None else "failed runTests"
            )

        @contextmanager
        def assertRaisesParseException(self, exc_type=ParseException, msg=None):
            with self.assertRaises(exc_type, msg=msg):
                yield


if __name__ == "__main__":

    selectToken    = CaselessLiteral("select")
    fromToken      = CaselessLiteral("from")

    ident          = Word(alphas, alphanums + "_$")

    columnName     = delimitedList(ident, ".", combine=True).setParseAction(upcaseTokens)
    columnNameList = Group(delimitedList(columnName)).setName("columns")
    columnSpec     = ('*' | columnNameList)

    tableName      = delimitedList(ident, ".", combine=True).setParseAction(upcaseTokens)
    tableNameList  = Group(delimitedList(tableName)).setName("tables")

    simpleSQL      = selectToken("command") + columnSpec("columns") + fromToken + tableNameList("tables")


    simpleSQL.runTests("""
        # '*' as column list and dotted table name
        select * from SYS.XYZZY

        # caseless match on "SELECT", and casts back to "select"
        SELECT * from XYZZY, ABC

        # list of column names, and mixed case SELECT keyword
        Select AA,BB,CC from Sys.dual

        # multiple tables
        Select A, B, C from Sys.dual, Table2

        # invalid SELECT keyword - should fail
        Xelect A, B, C from Sys.dual

        # incomplete command - should fail
        Select

        # invalid column name - should fail
        Select ^^^ frox Sys.dual

        """)

    pyparsing_common.number.runTests("""
        100
        -100
        +100
        3.14159
        6.02e23
        1e-12
        """)


    pyparsing_common.fnumber.runTests("""
        100
        -100
        +100
        3.14159
        6.02e23
        1e-12
        """)

    pyparsing_common.hex_integer.runTests("""
        100
        FF
        """)

    import uuid
    pyparsing_common.uuid.setParseAction(tokenMap(uuid.UUID))
    pyparsing_common.uuid.runTests("""
        12345678-1234-5678-1234-567812345678
        """)
