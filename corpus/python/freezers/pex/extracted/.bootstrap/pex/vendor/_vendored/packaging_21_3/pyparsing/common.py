
from .core import *
from .helpers import delimited_list, any_open_tag, any_close_tag
from datetime import datetime


class pyparsing_common:

    convert_to_integer = token_map(int)
    """
    Parse action for converting parsed integers to Python int
    """

    convert_to_float = token_map(float)
    """
    Parse action for converting parsed numbers to Python float
    """

    integer = Word(nums).set_name("integer").set_parse_action(convert_to_integer)
    """expression that parses an unsigned integer, returns an int"""

    hex_integer = (
        Word(hexnums).set_name("hex integer").set_parse_action(token_map(int, 16))
    )
    """expression that parses a hexadecimal integer, returns an int"""

    signed_integer = (
        Regex(r"[+-]?\d+")
        .set_name("signed integer")
        .set_parse_action(convert_to_integer)
    )
    """expression that parses an integer with optional leading sign, returns an int"""

    fraction = (
        signed_integer().set_parse_action(convert_to_float)
        + "/"
        + signed_integer().set_parse_action(convert_to_float)
    ).set_name("fraction")
    """fractional expression of an integer divided by an integer, returns a float"""
    fraction.add_parse_action(lambda tt: tt[0] / tt[-1])

    mixed_integer = (
        fraction | signed_integer + Opt(Opt("-").suppress() + fraction)
    ).set_name("fraction or mixed integer-fraction")
    """mixed integer of the form 'integer - fraction', with optional leading integer, returns float"""
    mixed_integer.add_parse_action(sum)

    real = (
        Regex(r"[+-]?(?:\d+\.\d*|\.\d+)")
        .set_name("real number")
        .set_parse_action(convert_to_float)
    )
    """expression that parses a floating point number and returns a float"""

    sci_real = (
        Regex(r"[+-]?(?:\d+(?:[eE][+-]?\d+)|(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?)")
        .set_name("real number with scientific notation")
        .set_parse_action(convert_to_float)
    )
    """expression that parses a floating point number with optional
    scientific notation and returns a float"""


    number = (sci_real | real | signed_integer).setName("number").streamline()
    """any numeric expression, returns the corresponding Python type"""

    fnumber = (
        Regex(r"[+-]?\d+\.?\d*([eE][+-]?\d+)?")
        .set_name("fnumber")
        .set_parse_action(convert_to_float)
    )
    """any int or real number, returned as float"""

    identifier = Word(identchars, identbodychars).set_name("identifier")
    """typical code identifier (leading alpha or '_', followed by 0 or more alphas, nums, or '_')"""

    ipv4_address = Regex(
        r"(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}"
    ).set_name("IPv4 address")
    "IPv4 address (``0.0.0.0 - 255.255.255.255``)"

    _ipv6_part = Regex(r"[0-9a-fA-F]{1,4}").set_name("hex_integer")
    _full_ipv6_address = (_ipv6_part + (":" + _ipv6_part) * 7).set_name(
        "full IPv6 address"
    )
    _short_ipv6_address = (
        Opt(_ipv6_part + (":" + _ipv6_part) * (0, 6))
        + "::"
        + Opt(_ipv6_part + (":" + _ipv6_part) * (0, 6))
    ).set_name("short IPv6 address")
    _short_ipv6_address.add_condition(
        lambda t: sum(1 for tt in t if pyparsing_common._ipv6_part.matches(tt)) < 8
    )
    _mixed_ipv6_address = ("::ffff:" + ipv4_address).set_name("mixed IPv6 address")
    ipv6_address = Combine(
        (_full_ipv6_address | _mixed_ipv6_address | _short_ipv6_address).set_name(
            "IPv6 address"
        )
    ).set_name("IPv6 address")
    "IPv6 address (long, short, or mixed form)"

    mac_address = Regex(
        r"[0-9a-fA-F]{2}([:.-])[0-9a-fA-F]{2}(?:\1[0-9a-fA-F]{2}){4}"
    ).set_name("MAC address")
    "MAC address xx:xx:xx:xx:xx (may also have '-' or '.' delimiters)"

    @staticmethod
    def convert_to_date(fmt: str = "%Y-%m-%d"):

        def cvt_fn(ss, ll, tt):
            try:
                return datetime.strptime(tt[0], fmt).date()
            except ValueError as ve:
                raise ParseException(ss, ll, str(ve))

        return cvt_fn

    @staticmethod
    def convert_to_datetime(fmt: str = "%Y-%m-%dT%H:%M:%S.%f"):

        def cvt_fn(s, l, t):
            try:
                return datetime.strptime(t[0], fmt)
            except ValueError as ve:
                raise ParseException(s, l, str(ve))

        return cvt_fn

    iso8601_date = Regex(
        r"(?P<year>\d{4})(?:-(?P<month>\d\d)(?:-(?P<day>\d\d))?)?"
    ).set_name("ISO8601 date")
    "ISO8601 date (``yyyy-mm-dd``)"

    iso8601_datetime = Regex(
        r"(?P<year>\d{4})-(?P<month>\d\d)-(?P<day>\d\d)[T ](?P<hour>\d\d):(?P<minute>\d\d)(:(?P<second>\d\d(\.\d*)?)?)?(?P<tz>Z|[+-]\d\d:?\d\d)?"
    ).set_name("ISO8601 datetime")
    "ISO8601 datetime (``yyyy-mm-ddThh:mm:ss.s(Z|+-00:00)``) - trailing seconds, milliseconds, and timezone optional; accepts separating ``'T'`` or ``' '``"

    uuid = Regex(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}").set_name("UUID")
    "UUID (``xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx``)"

    _html_stripper = any_open_tag.suppress() | any_close_tag.suppress()

    @staticmethod
    def strip_html_tags(s: str, l: int, tokens: ParseResults):
        return pyparsing_common._html_stripper.transform_string(tokens[0])

    _commasepitem = (
        Combine(
            OneOrMore(
                ~Literal(",")
                + ~LineEnd()
                + Word(printables, exclude_chars=",")
                + Opt(White(" \t") + ~FollowedBy(LineEnd() | ","))
            )
        )
        .streamline()
        .set_name("commaItem")
    )
    comma_separated_list = delimited_list(
        Opt(quoted_string.copy() | _commasepitem, default="")
    ).set_name("comma separated list")
    """Predefined expression of 1 or more printable words or quoted strings, separated by commas."""

    upcase_tokens = staticmethod(token_map(lambda t: t.upper()))
    """Parse action to convert tokens to upper case."""

    downcase_tokens = staticmethod(token_map(lambda t: t.lower()))
    """Parse action to convert tokens to lower case."""

    # fmt: off
    url = Regex(


        r"^" +


        r"(?:(?:(?P<scheme>https?|ftp):)?\/\/)" +

        r"(?:(?P<auth>\S+(?::\S*)?)@)?" +
        r"(?P<host>" +


        r"(?!(?:10|127)(?:\.\d{1,3}){3})" +
        r"(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})" +
        r"(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})" +


        r"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])" +
        r"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}" +
        r"(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))" +
        r"|" +


        r"(?:" +
        r"(?:" +
        r"[a-z0-9\u00a1-\uffff]" +
        r"[a-z0-9\u00a1-\uffff_-]{0,62}" +
        r")?" +
        r"[a-z0-9\u00a1-\uffff]\." +
        r")+" +

        r"(?:[a-z\u00a1-\uffff]{2,}\.?)" +
        r")" +

        r"(:(?P<port>\d{2,5}))?" +

        r"(?P<path>\/[^?# ]*)?" +

        r"(\?(?P<query>[^#]*))?" +

        r"(#(?P<fragment>\S*))?" +
        r"$"
    ).set_name("url")
    # fmt: on


    convertToInteger = convert_to_integer
    convertToFloat = convert_to_float
    convertToDate = convert_to_date
    convertToDatetime = convert_to_datetime
    stripHTMLTags = strip_html_tags
    upcaseTokens = upcase_tokens
    downcaseTokens = downcase_tokens


_builtin_exprs = [
    v for v in vars(pyparsing_common).values() if isinstance(v, ParserElement)
]
