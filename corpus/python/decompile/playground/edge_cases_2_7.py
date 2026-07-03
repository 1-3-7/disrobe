# -*- coding: utf-8 -*-
from __future__ import unicode_literals, division, absolute_import

import sys

__PY_BAND__ = (2, 7)


def print_statement_basic():
    print "hello from python 2"
    print "two", "args", "joined", "by", "spaces"
    print >> sys.stderr, "redirected via chevron"


def except_legacy_binding():
    try:
        return int("not-a-number")
    except ValueError, exc:
        return -1


def except_legacy_tuple():
    try:
        d = {}
        return d["missing"]
    except (KeyError, IndexError), exc:
        return None


def old_style_class_demo():
    class OldStyle:
        def __init__(self, value):
            self.value = value

        def double(self):
            return self.value * 2

    obj = OldStyle(21)
    return obj.double()


def has_key_and_iteritems():
    data = {"a": 1, "b": 2, "c": 3}
    found = data.has_key("a")
    pairs = list(data.iteritems())
    keys = list(data.iterkeys())
    values = list(data.itervalues())
    return found, len(pairs), len(keys), len(values)


def xrange_loop():
    total = 0
    for i in xrange(10):
        total += i
    return total


def long_literal_arithmetic():
    base = 100L
    grown = base * 1000000000000L
    return grown


def not_equal_diamond():
    return 1 <> 2


def unicode_literal_distinction():
    explicit = u"explicit-unicode"
    implicit = "implicit-via-future"
    raw_str = b"byte-string-on-2"
    return type(explicit).__name__, type(implicit).__name__, type(raw_str).__name__


def division_semantics():
    true_div = 5 / 2
    floor_div = 5 // 2
    return true_div, floor_div


def string_format_legacy():
    name = "world"
    count = 3
    return "hello %s, count=%d" % (name, count)


def raise_three_arg_legacy():
    try:
        raise ValueError, "legacy message"
    except ValueError:
        return "caught"


def backtick_repr_removed():
    value = [1, 2, 3]
    return `value`


def exec_as_statement():
    scope = {}
    exec "result = 42" in scope
    return scope["result"]


def function_with_tuple_params((a, b), c):
    return a + b + c


def print_to_file_chevron():
    print >> sys.stdout, "redirected to stdout"
    print >> sys.stderr, "redirected to stderr"


class StyleNewBase(object):

    def __init__(self, name):
        self.name = name

    def describe(self):
        return "new-style:%s" % self.name


def generator_with_yield_value():
    for i in xrange(5):
        yield i * 2


def list_vs_iter():
    doubled = map(lambda x: x * 2, [1, 2, 3])
    evens = filter(lambda x: x % 2 == 0, [1, 2, 3, 4])
    paired = zip([1, 2, 3], ["a", "b", "c"])
    return len(doubled), len(evens), len(paired)


def exercise():
    print_statement_basic()
    assert except_legacy_binding() == -1
    assert except_legacy_tuple() is None
    assert old_style_class_demo() == 42
    found, p, k, v = has_key_and_iteritems()
    assert found and p == 3 and k == 3 and v == 3
    assert xrange_loop() == 45
    assert long_literal_arithmetic() == 100L * 1000000000000L
    assert not_equal_diamond() is True
    explicit_t, implicit_t, raw_t = unicode_literal_distinction()
    assert explicit_t == "unicode"
    assert implicit_t == "unicode"
    assert raw_t == "str"
    td, fd = division_semantics()
    assert td == 2.5 and fd == 2
    assert string_format_legacy() == "hello world, count=3"
    assert raise_three_arg_legacy() == "caught"
    assert backtick_repr_removed() == "[1, 2, 3]"
    assert exec_as_statement() == 42
    assert function_with_tuple_params((1, 2), 3) == 6
    print_to_file_chevron()
    obj = StyleNewBase("test")
    assert obj.describe() == "new-style:test"
    assert list(generator_with_yield_value()) == [0, 2, 4, 6, 8]
    a, b, c = list_vs_iter()
    assert a == 3 and b == 2 and c == 3
    print "exercise: ok"


if __name__ == "__main__":
    exercise()
