BIG_POSITIVE = 123456789012345678901234567890
BIG_NEGATIVE = -98765432109876543210
POWER_OF_TWO = 2 ** 100
MAX_U64 = 0xFFFFFFFFFFFFFFFF
OCTAL = 0o755
BINARY = 0b1011_0110
UNDERSCORED = 1_000_000
PI_ISH = 3.141592653589793
TINY = 1e-300
HUGE = 1.7976931348623157e308
NEG_ZERO = -0.0
HALF = 0.5
COMPLEX_A = 3 + 4j
COMPLEX_B = -2.5j
RAW_BYTES = b"\x00\x01\xff\x7fbinary"
EMPTY_BYTES = b""
TEXT = "unicode \u00e9\u4e2d\U0001f600"
RAW_TEXT = r"C:\temp\new"
EMPTY_TEXT = ""
NESTED = ((1, 2), ("a", ("b", ("c",))), (None, True, False), ())
MIXED = (1, 2.0, 3j, "four", b"five", None, Ellipsis)
LIST_CONST = [1, 2, 3]
DICT_CONST = {"a": 1, "b": (2, 3), 4: "d"}
SET_CONST = {1, 2, 3}


def is_vowel(ch):
    return ch in {"a", "e", "i", "o", "u"}


def is_small_prime(n):
    return n in {2, 3, 5, 7, 11, 13}


def not_reserved(port):
    return port not in {0, 22, 80, 443}


def in_tuple(value):
    return value in (1.5, -2, "x", b"y", None)


def big_arithmetic(n):
    return (n * BIG_POSITIVE + BIG_NEGATIVE) % MAX_U64


def constants_in_body():
    return -1, -1.5, 10 ** 20, 1 << 70, ~0, "joined" "text", b"a" b"b", (1, (2, (3, (4,))))


def float_edges():
    return float("inf"), float("-inf"), TINY * 0.1, HUGE, NEG_ZERO
