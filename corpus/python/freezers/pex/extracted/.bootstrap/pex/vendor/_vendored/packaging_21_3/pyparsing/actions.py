

from .exceptions import ParseException
from .util import col


class OnlyOnce:

    def __init__(self, method_call):
        from .core import _trim_arity

        self.callable = _trim_arity(method_call)
        self.called = False

    def __call__(self, s, l, t):
        if not self.called:
            results = self.callable(s, l, t)
            self.called = True
            return results
        raise ParseException(s, l, "OnlyOnce obj called multiple times w/out reset")

    def reset(self):

        self.called = False


def match_only_at_col(n):

    def verify_col(strg, locn, toks):
        if col(locn, strg) != n:
            raise ParseException(strg, locn, "matched token not at column {}".format(n))

    return verify_col


def replace_with(repl_str):
    return lambda s, l, t: [repl_str]


def remove_quotes(s, l, t):
    return t[0][1:-1]


def with_attribute(*args, **attr_dict):
    if args:
        attrs = args[:]
    else:
        attrs = attr_dict.items()
    attrs = [(k, v) for k, v in attrs]

    def pa(s, l, tokens):
        for attrName, attrValue in attrs:
            if attrName not in tokens:
                raise ParseException(s, l, "no matching attribute " + attrName)
            if attrValue != with_attribute.ANY_VALUE and tokens[attrName] != attrValue:
                raise ParseException(
                    s,
                    l,
                    "attribute {!r} has value {!r}, must be {!r}".format(
                        attrName, tokens[attrName], attrValue
                    ),
                )

    return pa


with_attribute.ANY_VALUE = object()


def with_class(classname, namespace=""):
    classattr = "{}:class".format(namespace) if namespace else "class"
    return with_attribute(**{classattr: classname})


replaceWith = replace_with
removeQuotes = remove_quotes
withAttribute = with_attribute
withClass = with_class
matchOnlyAtCol = match_only_at_col
