
import html.entities
import re

from . import __diag__
from .core import *
from .util import _bslash, _flatten, _escape_regex_range_chars


def delimited_list(
    expr: Union[str, ParserElement],
    delim: Union[str, ParserElement] = ",",
    combine: bool = False,
    min: OptionalType[int] = None,
    max: OptionalType[int] = None,
    *,
    allow_trailing_delim: bool = False,
) -> ParserElement:
    if isinstance(expr, str_type):
        expr = ParserElement._literalStringClass(expr)

    dlName = "{expr} [{delim} {expr}]...{end}".format(
        expr=str(expr.copy().streamline()),
        delim=str(delim),
        end=" [{}]".format(str(delim)) if allow_trailing_delim else "",
    )

    if not combine:
        delim = Suppress(delim)

    if min is not None:
        if min < 1:
            raise ValueError("min must be greater than 0")
        min -= 1
    if max is not None:
        if min is not None and max <= min:
            raise ValueError("max must be greater than, or equal to min")
        max -= 1
    delimited_list_expr = expr + (delim + expr)[min, max]

    if allow_trailing_delim:
        delimited_list_expr += Opt(delim)

    if combine:
        return Combine(delimited_list_expr).set_name(dlName)
    else:
        return delimited_list_expr.set_name(dlName)


def counted_array(
    expr: ParserElement,
    int_expr: OptionalType[ParserElement] = None,
    *,
    intExpr: OptionalType[ParserElement] = None,
) -> ParserElement:
    intExpr = intExpr or int_expr
    array_expr = Forward()

    def count_field_parse_action(s, l, t):
        nonlocal array_expr
        n = t[0]
        array_expr <<= (expr * n) if n else Empty()

        del t[:]

    if intExpr is None:
        intExpr = Word(nums).set_parse_action(lambda t: int(t[0]))
    else:
        intExpr = intExpr.copy()
    intExpr.set_name("arrayLen")
    intExpr.add_parse_action(count_field_parse_action, call_during_try=True)
    return (intExpr + array_expr).set_name("(len) " + str(expr) + "...")


def match_previous_literal(expr: ParserElement) -> ParserElement:
    rep = Forward()

    def copy_token_to_repeater(s, l, t):
        if t:
            if len(t) == 1:
                rep << t[0]
            else:

                tflat = _flatten(t.as_list())
                rep << And(Literal(tt) for tt in tflat)
        else:
            rep << Empty()

    expr.add_parse_action(copy_token_to_repeater, callDuringTry=True)
    rep.set_name("(prev) " + str(expr))
    return rep


def match_previous_expr(expr: ParserElement) -> ParserElement:
    rep = Forward()
    e2 = expr.copy()
    rep <<= e2

    def copy_token_to_repeater(s, l, t):
        matchTokens = _flatten(t.as_list())

        def must_match_these_tokens(s, l, t):
            theseTokens = _flatten(t.as_list())
            if theseTokens != matchTokens:
                raise ParseException(s, l, "Expected {}, found{}".format(matchTokens, theseTokens))

        rep.set_parse_action(must_match_these_tokens, callDuringTry=True)

    expr.add_parse_action(copy_token_to_repeater, callDuringTry=True)
    rep.set_name("(prev) " + str(expr))
    return rep


def one_of(
    strs: Union[IterableType[str], str],
    caseless: bool = False,
    use_regex: bool = True,
    as_keyword: bool = False,
    *,
    useRegex: bool = True,
    asKeyword: bool = False,
) -> ParserElement:
    asKeyword = asKeyword or as_keyword
    useRegex = useRegex and use_regex

    if (
        isinstance(caseless, str_type)
        and __diag__.warn_on_multiple_string_args_to_oneof
    ):
        warnings.warn(
            "More than one string argument passed to one_of, pass"
            " choices as a list or space-delimited string",
            stacklevel=2,
        )

    if caseless:
        isequal = lambda a, b: a.upper() == b.upper()
        masks = lambda a, b: b.upper().startswith(a.upper())
        parseElementClass = CaselessKeyword if asKeyword else CaselessLiteral
    else:
        isequal = lambda a, b: a == b
        masks = lambda a, b: b.startswith(a)
        parseElementClass = Keyword if asKeyword else Literal

    symbols: List[str] = []
    if isinstance(strs, str_type):
        symbols = strs.split()
    elif isinstance(strs, Iterable):
        symbols = list(strs)
    else:
        raise TypeError("Invalid argument to one_of, expected string or iterable")
    if not symbols:
        return NoMatch()


    if any(len(sym) > 1 for sym in symbols):
        i = 0
        while i < len(symbols) - 1:
            cur = symbols[i]
            for j, other in enumerate(symbols[i + 1 :]):
                if isequal(other, cur):
                    del symbols[i + j + 1]
                    break
                elif masks(cur, other):
                    del symbols[i + j + 1]
                    symbols.insert(i, other)
                    break
            else:
                i += 1

    if useRegex:
        re_flags: int = re.IGNORECASE if caseless else 0

        try:
            if all(len(sym) == 1 for sym in symbols):

                patt = "[{}]".format(
                    "".join(_escape_regex_range_chars(sym) for sym in symbols)
                )
            else:
                patt = "|".join(re.escape(sym) for sym in symbols)


            if asKeyword:
                patt = r"\b(?:{})\b".format(patt)

            ret = Regex(patt, flags=re_flags).set_name(" | ".join(symbols))

            if caseless:


                symbol_map = {sym.lower(): sym for sym in symbols}
                ret.add_parse_action(lambda s, l, t: symbol_map[t[0].lower()])

            return ret

        except sre_constants.error:
            warnings.warn(
                "Exception creating Regex for one_of, building MatchFirst", stacklevel=2
            )


    return MatchFirst(parseElementClass(sym) for sym in symbols).set_name(
        " | ".join(symbols)
    )


def dict_of(key: ParserElement, value: ParserElement) -> ParserElement:
    return Dict(OneOrMore(Group(key + value)))


def original_text_for(
    expr: ParserElement, as_string: bool = True, *, asString: bool = True
) -> ParserElement:
    asString = asString and as_string

    locMarker = Empty().set_parse_action(lambda s, loc, t: loc)
    endlocMarker = locMarker.copy()
    endlocMarker.callPreparse = False
    matchExpr = locMarker("_original_start") + expr + endlocMarker("_original_end")
    if asString:
        extractText = lambda s, l, t: s[t._original_start : t._original_end]
    else:

        def extractText(s, l, t):
            t[:] = [s[t.pop("_original_start") : t.pop("_original_end")]]

    matchExpr.set_parse_action(extractText)
    matchExpr.ignoreExprs = expr.ignoreExprs
    matchExpr.suppress_warning(Diagnostics.warn_ungrouped_named_tokens_in_collection)
    return matchExpr


def ungroup(expr: ParserElement) -> ParserElement:
    return TokenConverter(expr).add_parse_action(lambda t: t[0])


def locatedExpr(expr: ParserElement) -> ParserElement:
    locator = Empty().set_parse_action(lambda ss, ll, tt: ll)
    return Group(
        locator("locn_start")
        + expr("value")
        + locator.copy().leaveWhitespace()("locn_end")
    )


def nested_expr(
    opener: Union[str, ParserElement] = "(",
    closer: Union[str, ParserElement] = ")",
    content: OptionalType[ParserElement] = None,
    ignore_expr: ParserElement = quoted_string(),
    *,
    ignoreExpr: ParserElement = quoted_string(),
) -> ParserElement:
    if ignoreExpr != ignore_expr:
        ignoreExpr = ignore_expr if ignoreExpr == quoted_string() else ignoreExpr
    if opener == closer:
        raise ValueError("opening and closing strings cannot be the same")
    if content is None:
        if isinstance(opener, str_type) and isinstance(closer, str_type):
            if len(opener) == 1 and len(closer) == 1:
                if ignoreExpr is not None:
                    content = Combine(
                        OneOrMore(
                            ~ignoreExpr
                            + CharsNotIn(
                                opener + closer + ParserElement.DEFAULT_WHITE_CHARS,
                                exact=1,
                            )
                        )
                    ).set_parse_action(lambda t: t[0].strip())
                else:
                    content = empty.copy() + CharsNotIn(
                        opener + closer + ParserElement.DEFAULT_WHITE_CHARS
                    ).set_parse_action(lambda t: t[0].strip())
            else:
                if ignoreExpr is not None:
                    content = Combine(
                        OneOrMore(
                            ~ignoreExpr
                            + ~Literal(opener)
                            + ~Literal(closer)
                            + CharsNotIn(ParserElement.DEFAULT_WHITE_CHARS, exact=1)
                        )
                    ).set_parse_action(lambda t: t[0].strip())
                else:
                    content = Combine(
                        OneOrMore(
                            ~Literal(opener)
                            + ~Literal(closer)
                            + CharsNotIn(ParserElement.DEFAULT_WHITE_CHARS, exact=1)
                        )
                    ).set_parse_action(lambda t: t[0].strip())
        else:
            raise ValueError(
                "opening and closing arguments must be strings if no content expression is given"
            )
    ret = Forward()
    if ignoreExpr is not None:
        ret <<= Group(
            Suppress(opener) + ZeroOrMore(ignoreExpr | ret | content) + Suppress(closer)
        )
    else:
        ret <<= Group(Suppress(opener) + ZeroOrMore(ret | content) + Suppress(closer))
    ret.set_name("nested %s%s expression" % (opener, closer))
    return ret


def _makeTags(tagStr, xml, suppress_LT=Suppress("<"), suppress_GT=Suppress(">")):
    if isinstance(tagStr, str_type):
        resname = tagStr
        tagStr = Keyword(tagStr, caseless=not xml)
    else:
        resname = tagStr.name

    tagAttrName = Word(alphas, alphanums + "_-:")
    if xml:
        tagAttrValue = dbl_quoted_string.copy().set_parse_action(remove_quotes)
        openTag = (
            suppress_LT
            + tagStr("tag")
            + Dict(ZeroOrMore(Group(tagAttrName + Suppress("=") + tagAttrValue)))
            + Opt("/", default=[False])("empty").set_parse_action(
                lambda s, l, t: t[0] == "/"
            )
            + suppress_GT
        )
    else:
        tagAttrValue = quoted_string.copy().set_parse_action(remove_quotes) | Word(
            printables, exclude_chars=">"
        )
        openTag = (
            suppress_LT
            + tagStr("tag")
            + Dict(
                ZeroOrMore(
                    Group(
                        tagAttrName.set_parse_action(lambda t: t[0].lower())
                        + Opt(Suppress("=") + tagAttrValue)
                    )
                )
            )
            + Opt("/", default=[False])("empty").set_parse_action(
                lambda s, l, t: t[0] == "/"
            )
            + suppress_GT
        )
    closeTag = Combine(Literal("</") + tagStr + ">", adjacent=False)

    openTag.set_name("<%s>" % resname)

    openTag.add_parse_action(
        lambda t: t.__setitem__(
            "start" + "".join(resname.replace(":", " ").title().split()), t.copy()
        )
    )
    closeTag = closeTag(
        "end" + "".join(resname.replace(":", " ").title().split())
    ).set_name("</%s>" % resname)
    openTag.tag = resname
    closeTag.tag = resname
    openTag.tag_body = SkipTo(closeTag())
    return openTag, closeTag


def make_html_tags(
    tag_str: Union[str, ParserElement]
) -> Tuple[ParserElement, ParserElement]:
    return _makeTags(tag_str, False)


def make_xml_tags(
    tag_str: Union[str, ParserElement]
) -> Tuple[ParserElement, ParserElement]:
    return _makeTags(tag_str, True)


any_open_tag, any_close_tag = make_html_tags(
    Word(alphas, alphanums + "_:").set_name("any tag")
)

_htmlEntityMap = {k.rstrip(";"): v for k, v in html.entities.html5.items()}
common_html_entity = Regex("&(?P<entity>" + "|".join(_htmlEntityMap) + ");").set_name(
    "common HTML entity"
)


def replace_html_entity(t):
    return _htmlEntityMap.get(t.entity)


class OpAssoc(Enum):
    LEFT = 1
    RIGHT = 2


InfixNotationOperatorArgType = Union[
    ParserElement, str, Tuple[Union[ParserElement, str], Union[ParserElement, str]]
]
InfixNotationOperatorSpec = Union[
    Tuple[
        InfixNotationOperatorArgType,
        int,
        OpAssoc,
        OptionalType[ParseAction],
    ],
    Tuple[
        InfixNotationOperatorArgType,
        int,
        OpAssoc,
    ],
]


def infix_notation(
    base_expr: ParserElement,
    op_list: List[InfixNotationOperatorSpec],
    lpar: Union[str, ParserElement] = Suppress("("),
    rpar: Union[str, ParserElement] = Suppress(")"),
) -> ParserElement:

    class _FB(FollowedBy):
        def parseImpl(self, instring, loc, doActions=True):
            self.expr.try_parse(instring, loc)
            return loc, []

    _FB.__name__ = "FollowedBy>"

    ret = Forward()
    lpar = Suppress(lpar)
    rpar = Suppress(rpar)
    lastExpr = base_expr | (lpar + ret + rpar)
    for i, operDef in enumerate(op_list):
        opExpr, arity, rightLeftAssoc, pa = (operDef + (None,))[:4]
        if isinstance(opExpr, str_type):
            opExpr = ParserElement._literalStringClass(opExpr)
        if arity == 3:
            if not isinstance(opExpr, (tuple, list)) or len(opExpr) != 2:
                raise ValueError(
                    "if numterms=3, opExpr must be a tuple or list of two expressions"
                )
            opExpr1, opExpr2 = opExpr
            term_name = "{}{} term".format(opExpr1, opExpr2)
        else:
            term_name = "{} term".format(opExpr)

        if not 1 <= arity <= 3:
            raise ValueError("operator must be unary (1), binary (2), or ternary (3)")

        if rightLeftAssoc not in (OpAssoc.LEFT, OpAssoc.RIGHT):
            raise ValueError("operator must indicate right or left associativity")

        thisExpr = Forward().set_name(term_name)
        if rightLeftAssoc is OpAssoc.LEFT:
            if arity == 1:
                matchExpr = _FB(lastExpr + opExpr) + Group(lastExpr + opExpr[1, ...])
            elif arity == 2:
                if opExpr is not None:
                    matchExpr = _FB(lastExpr + opExpr + lastExpr) + Group(
                        lastExpr + (opExpr + lastExpr)[1, ...]
                    )
                else:
                    matchExpr = _FB(lastExpr + lastExpr) + Group(lastExpr[2, ...])
            elif arity == 3:
                matchExpr = _FB(
                    lastExpr + opExpr1 + lastExpr + opExpr2 + lastExpr
                ) + Group(lastExpr + OneOrMore(opExpr1 + lastExpr + opExpr2 + lastExpr))
        elif rightLeftAssoc is OpAssoc.RIGHT:
            if arity == 1:

                if not isinstance(opExpr, Opt):
                    opExpr = Opt(opExpr)
                matchExpr = _FB(opExpr.expr + thisExpr) + Group(opExpr + thisExpr)
            elif arity == 2:
                if opExpr is not None:
                    matchExpr = _FB(lastExpr + opExpr + thisExpr) + Group(
                        lastExpr + (opExpr + thisExpr)[1, ...]
                    )
                else:
                    matchExpr = _FB(lastExpr + thisExpr) + Group(
                        lastExpr + thisExpr[1, ...]
                    )
            elif arity == 3:
                matchExpr = _FB(
                    lastExpr + opExpr1 + thisExpr + opExpr2 + thisExpr
                ) + Group(lastExpr + opExpr1 + thisExpr + opExpr2 + thisExpr)
        if pa:
            if isinstance(pa, (tuple, list)):
                matchExpr.set_parse_action(*pa)
            else:
                matchExpr.set_parse_action(pa)
        thisExpr <<= (matchExpr | lastExpr).setName(term_name)
        lastExpr = thisExpr
    ret <<= lastExpr
    return ret


def indentedBlock(blockStatementExpr, indentStack, indent=True, backup_stacks=[]):
    backup_stacks.append(indentStack[:])

    def reset_stack():
        indentStack[:] = backup_stacks[-1]

    def checkPeerIndent(s, l, t):
        if l >= len(s):
            return
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
        if l >= len(s):
            return
        curCol = col(l, s)
        if not (indentStack and curCol in indentStack):
            raise ParseException(s, l, "not an unindent")
        if curCol < indentStack[-1]:
            indentStack.pop()

    NL = OneOrMore(LineEnd().set_whitespace_chars("\t ").suppress())
    INDENT = (Empty() + Empty().set_parse_action(checkSubIndent)).set_name("INDENT")
    PEER = Empty().set_parse_action(checkPeerIndent).set_name("")
    UNDENT = Empty().set_parse_action(checkUnindent).set_name("UNINDENT")
    if indent:
        smExpr = Group(
            Opt(NL)
            + INDENT
            + OneOrMore(PEER + Group(blockStatementExpr) + Opt(NL))
            + UNDENT
        )
    else:
        smExpr = Group(
            Opt(NL)
            + OneOrMore(PEER + Group(blockStatementExpr) + Opt(NL))
            + Opt(UNDENT)
        )


    smExpr.add_parse_action(
        lambda: backup_stacks.pop(-1) and None if backup_stacks else None
    )
    smExpr.set_fail_action(lambda a, b, c, d: reset_stack())
    blockStatementExpr.ignore(_bslash + LineEnd())
    return smExpr.set_name("indented block")


c_style_comment = Combine(Regex(r"/\*(?:[^*]|\*(?!/))*") + "*/").set_name(
    "C style comment"
)
"Comment of the form ``/* ... */``"

html_comment = Regex(r"<!--[\s\S]*?-->").set_name("HTML comment")
"Comment of the form ``<!-- ... -->``"

rest_of_line = Regex(r".*").leave_whitespace().set_name("rest of line")
dbl_slash_comment = Regex(r"//(?:\\\n|[^\n])*").set_name("// comment")
"Comment of the form ``// ... (to end of line)``"

cpp_style_comment = Combine(
    Regex(r"/\*(?:[^*]|\*(?!/))*") + "*/" | dbl_slash_comment
).set_name("C++ style comment")
"Comment of either form :class:`c_style_comment` or :class:`dbl_slash_comment`"

java_style_comment = cpp_style_comment
"Same as :class:`cpp_style_comment`"

python_style_comment = Regex(r"#.*").set_name("Python style comment")
"Comment of the form ``# ... (to end of line)``"


_builtin_exprs = [v for v in vars().values() if isinstance(v, ParserElement)]


delimitedList = delimited_list
countedArray = counted_array
matchPreviousLiteral = match_previous_literal
matchPreviousExpr = match_previous_expr
oneOf = one_of
dictOf = dict_of
originalTextFor = original_text_for
nestedExpr = nested_expr
makeHTMLTags = make_html_tags
makeXMLTags = make_xml_tags
anyOpenTag, anyCloseTag = any_open_tag, any_close_tag
commonHTMLEntity = common_html_entity
replaceHTMLEntity = replace_html_entity
opAssoc = OpAssoc
infixNotation = infix_notation
cStyleComment = c_style_comment
htmlComment = html_comment
restOfLine = rest_of_line
dblSlashComment = dbl_slash_comment
cppStyleComment = cpp_style_comment
javaStyleComment = java_style_comment
pythonStyleComment = python_style_comment
