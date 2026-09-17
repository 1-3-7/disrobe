
from collections.abc import MutableMapping, Mapping, MutableSequence, Iterator
import pprint
from weakref import ref as wkref
from typing import Tuple, Any

str_type: Tuple[type, ...] = (str, bytes)
_generator_type = type((_ for _ in ()))


class _ParseResultsWithOffset:
    __slots__ = ["tup"]

    def __init__(self, p1, p2):
        self.tup = (p1, p2)

    def __getitem__(self, i):
        return self.tup[i]

    def __getstate__(self):
        return self.tup

    def __setstate__(self, *args):
        self.tup = args[0]


class ParseResults:

    _null_values: Tuple[Any, ...] = (None, [], "", ())

    __slots__ = [
        "_name",
        "_parent",
        "_all_names",
        "_modal",
        "_toklist",
        "_tokdict",
        "__weakref__",
    ]

    class List(list):

        def __new__(cls, contained=None):
            if contained is None:
                contained = []

            if not isinstance(contained, list):
                raise TypeError(
                    "{} may only be constructed with a list,"
                    " not {}".format(cls.__name__, type(contained).__name__)
                )

            return list.__new__(cls)

    def __new__(cls, toklist=None, name=None, **kwargs):
        if isinstance(toklist, ParseResults):
            return toklist
        self = object.__new__(cls)
        self._name = None
        self._parent = None
        self._all_names = set()

        if toklist is None:
            self._toklist = []
        elif isinstance(toklist, (list, _generator_type)):
            self._toklist = (
                [toklist[:]]
                if isinstance(toklist, ParseResults.List)
                else list(toklist)
            )
        else:
            self._toklist = [toklist]
        self._tokdict = dict()
        return self


    def __init__(
        self, toklist=None, name=None, asList=True, modal=True, isinstance=isinstance
    ):
        self._modal = modal
        if name is not None and name != "":
            if isinstance(name, int):
                name = str(name)
            if not modal:
                self._all_names = {name}
            self._name = name
            if toklist not in self._null_values:
                if isinstance(toklist, (str_type, type)):
                    toklist = [toklist]
                if asList:
                    if isinstance(toklist, ParseResults):
                        self[name] = _ParseResultsWithOffset(
                            ParseResults(toklist._toklist), 0
                        )
                    else:
                        self[name] = _ParseResultsWithOffset(
                            ParseResults(toklist[0]), 0
                        )
                    self[name]._name = name
                else:
                    try:
                        self[name] = toklist[0]
                    except (KeyError, TypeError, IndexError):
                        if toklist is not self:
                            self[name] = toklist
                        else:
                            self._name = name

    def __getitem__(self, i):
        if isinstance(i, (int, slice)):
            return self._toklist[i]
        else:
            if i not in self._all_names:
                return self._tokdict[i][-1][0]
            else:
                return ParseResults([v[0] for v in self._tokdict[i]])

    def __setitem__(self, k, v, isinstance=isinstance):
        if isinstance(v, _ParseResultsWithOffset):
            self._tokdict[k] = self._tokdict.get(k, list()) + [v]
            sub = v[0]
        elif isinstance(k, (int, slice)):
            self._toklist[k] = v
            sub = v
        else:
            self._tokdict[k] = self._tokdict.get(k, list()) + [
                _ParseResultsWithOffset(v, 0)
            ]
            sub = v
        if isinstance(sub, ParseResults):
            sub._parent = wkref(self)

    def __delitem__(self, i):
        if isinstance(i, (int, slice)):
            mylen = len(self._toklist)
            del self._toklist[i]


            if isinstance(i, int):
                if i < 0:
                    i += mylen
                i = slice(i, i + 1)

            removed = list(range(*i.indices(mylen)))
            removed.reverse()

            for name, occurrences in self._tokdict.items():
                for j in removed:
                    for k, (value, position) in enumerate(occurrences):
                        occurrences[k] = _ParseResultsWithOffset(
                            value, position - (position > j)
                        )
        else:
            del self._tokdict[i]

    def __contains__(self, k) -> bool:
        return k in self._tokdict

    def __len__(self) -> int:
        return len(self._toklist)

    def __bool__(self) -> bool:
        return not not (self._toklist or self._tokdict)

    def __iter__(self) -> Iterator:
        return iter(self._toklist)

    def __reversed__(self) -> Iterator:
        return iter(self._toklist[::-1])

    def keys(self):
        return iter(self._tokdict)

    def values(self):
        return (self[k] for k in self.keys())

    def items(self):
        return ((k, self[k]) for k in self.keys())

    def haskeys(self) -> bool:
        return bool(self._tokdict)

    def pop(self, *args, **kwargs):
        if not args:
            args = [-1]
        for k, v in kwargs.items():
            if k == "default":
                args = (args[0], v)
            else:
                raise TypeError(
                    "pop() got an unexpected keyword argument {!r}".format(k)
                )
        if isinstance(args[0], int) or len(args) == 1 or args[0] in self:
            index = args[0]
            ret = self[index]
            del self[index]
            return ret
        else:
            defaultvalue = args[1]
            return defaultvalue

    def get(self, key, default_value=None):
        if key in self:
            return self[key]
        else:
            return default_value

    def insert(self, index, ins_string):
        self._toklist.insert(index, ins_string)

        for name, occurrences in self._tokdict.items():
            for k, (value, position) in enumerate(occurrences):
                occurrences[k] = _ParseResultsWithOffset(
                    value, position + (position > index)
                )

    def append(self, item):
        self._toklist.append(item)

    def extend(self, itemseq):
        if isinstance(itemseq, ParseResults):
            self.__iadd__(itemseq)
        else:
            self._toklist.extend(itemseq)

    def clear(self):
        del self._toklist[:]
        self._tokdict.clear()

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            if name.startswith("__"):
                raise AttributeError(name)
            return ""

    def __add__(self, other) -> "ParseResults":
        ret = self.copy()
        ret += other
        return ret

    def __iadd__(self, other) -> "ParseResults":
        if other._tokdict:
            offset = len(self._toklist)
            addoffset = lambda a: offset if a < 0 else a + offset
            otheritems = other._tokdict.items()
            otherdictitems = [
                (k, _ParseResultsWithOffset(v[0], addoffset(v[1])))
                for k, vlist in otheritems
                for v in vlist
            ]
            for k, v in otherdictitems:
                self[k] = v
                if isinstance(v[0], ParseResults):
                    v[0]._parent = wkref(self)

        self._toklist += other._toklist
        self._all_names |= other._all_names
        return self

    def __radd__(self, other) -> "ParseResults":
        if isinstance(other, int) and other == 0:

            return self.copy()
        else:

            return other + self

    def __repr__(self) -> str:
        return "{}({!r}, {})".format(type(self).__name__, self._toklist, self.as_dict())

    def __str__(self) -> str:
        return (
            "["
            + ", ".join(
                [
                    str(i) if isinstance(i, ParseResults) else repr(i)
                    for i in self._toklist
                ]
            )
            + "]"
        )

    def _asStringList(self, sep=""):
        out = []
        for item in self._toklist:
            if out and sep:
                out.append(sep)
            if isinstance(item, ParseResults):
                out += item._asStringList()
            else:
                out.append(str(item))
        return out

    def as_list(self) -> list:
        return [
            res.as_list() if isinstance(res, ParseResults) else res
            for res in self._toklist
        ]

    def as_dict(self) -> dict:

        def to_item(obj):
            if isinstance(obj, ParseResults):
                return obj.as_dict() if obj.haskeys() else [to_item(v) for v in obj]
            else:
                return obj

        return dict((k, to_item(v)) for k, v in self.items())

    def copy(self) -> "ParseResults":
        ret = ParseResults(self._toklist)
        ret._tokdict = self._tokdict.copy()
        ret._parent = self._parent
        ret._all_names |= self._all_names
        ret._name = self._name
        return ret

    def get_name(self):
        if self._name:
            return self._name
        elif self._parent:
            par = self._parent()

            def find_in_parent(sub):
                return next(
                    (
                        k
                        for k, vlist in par._tokdict.items()
                        for v, loc in vlist
                        if sub is v
                    ),
                    None,
                )

            return find_in_parent(self) if par else None
        elif (
            len(self) == 1
            and len(self._tokdict) == 1
            and next(iter(self._tokdict.values()))[0][1] in (0, -1)
        ):
            return next(iter(self._tokdict.keys()))
        else:
            return None

    def dump(self, indent="", full=True, include_list=True, _depth=0) -> str:
        out = []
        NL = "\n"
        out.append(indent + str(self.as_list()) if include_list else "")

        if full:
            if self.haskeys():
                items = sorted((str(k), v) for k, v in self.items())
                for k, v in items:
                    if out:
                        out.append(NL)
                    out.append("{}{}- {}: ".format(indent, ("  " * _depth), k))
                    if isinstance(v, ParseResults):
                        if v:
                            out.append(
                                v.dump(
                                    indent=indent,
                                    full=full,
                                    include_list=include_list,
                                    _depth=_depth + 1,
                                )
                            )
                        else:
                            out.append(str(v))
                    else:
                        out.append(repr(v))
            if any(isinstance(vv, ParseResults) for vv in self):
                v = self
                for i, vv in enumerate(v):
                    if isinstance(vv, ParseResults):
                        out.append(
                            "\n{}{}[{}]:\n{}{}{}".format(
                                indent,
                                ("  " * (_depth)),
                                i,
                                indent,
                                ("  " * (_depth + 1)),
                                vv.dump(
                                    indent=indent,
                                    full=full,
                                    include_list=include_list,
                                    _depth=_depth + 1,
                                ),
                            )
                        )
                    else:
                        out.append(
                            "\n%s%s[%d]:\n%s%s%s"
                            % (
                                indent,
                                ("  " * (_depth)),
                                i,
                                indent,
                                ("  " * (_depth + 1)),
                                str(vv),
                            )
                        )

        return "".join(out)

    def pprint(self, *args, **kwargs):
        pprint.pprint(self.as_list(), *args, **kwargs)


    def __getstate__(self):
        return (
            self._toklist,
            (
                self._tokdict.copy(),
                self._parent is not None and self._parent() or None,
                self._all_names,
                self._name,
            ),
        )

    def __setstate__(self, state):
        self._toklist, (self._tokdict, par, inAccumNames, self._name) = state
        self._all_names = set(inAccumNames)
        if par is not None:
            self._parent = wkref(par)
        else:
            self._parent = None

    def __getnewargs__(self):
        return self._toklist, self._name

    def __dir__(self):
        return dir(type(self)) + list(self.keys())

    @classmethod
    def from_dict(cls, other, name=None) -> "ParseResults":

        def is_iterable(obj):
            try:
                iter(obj)
            except Exception:
                return False
            else:
                return not isinstance(obj, str_type)

        ret = cls([])
        for k, v in other.items():
            if isinstance(v, Mapping):
                ret += cls.from_dict(v, name=k)
            else:
                ret += cls([v], name=k, asList=is_iterable(v))
        if name is not None:
            ret = cls([ret], name=name)
        return ret

    asList = as_list
    asDict = as_dict
    getName = get_name


MutableMapping.register(ParseResults)
MutableSequence.register(ParseResults)
