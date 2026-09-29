START, NUMBER, IDENT, STRING, OPERATOR = range(5)
OPERATORS = frozenset("+-*/=<>()")


class Token:
    __slots__ = ("kind", "text", "pos")

    def __init__(self, kind, text, pos):
        self.kind = kind
        self.text = text
        self.pos = pos

    def __repr__(self):
        return "Token(%d, %r, %d)" % (self.kind, self.text, self.pos)


def tokenize(source):
    tokens = []
    state = START
    buffer = ""
    begin = 0
    index = 0
    while index <= len(source):
        ch = source[index] if index < len(source) else "\0"
        if state == START:
            begin = index
            if ch.isdigit():
                state, buffer = NUMBER, ch
            elif ch.isalpha() or ch == "_":
                state, buffer = IDENT, ch
            elif ch == '"':
                state, buffer = STRING, ""
            elif ch in OPERATORS:
                tokens.append(Token(OPERATOR, ch, index))
            elif ch == "\0" or ch.isspace():
                pass
            else:
                raise SyntaxError("unexpected %r at %d" % (ch, index))
            index += 1
        elif state == NUMBER:
            if ch.isdigit() or (ch == "." and "." not in buffer):
                buffer += ch
                index += 1
            else:
                tokens.append(Token(NUMBER, buffer, begin))
                state = START
        elif state == IDENT:
            if ch.isalnum() or ch == "_":
                buffer += ch
                index += 1
            else:
                tokens.append(Token(IDENT, buffer, begin))
                state = START
        elif state == STRING:
            if ch == "\0":
                raise SyntaxError("unterminated string")
            index += 1
            if ch == '"':
                tokens.append(Token(STRING, buffer, begin))
                state = START
            else:
                buffer += ch
    return tokens


def kinds(source):
    return [token.kind for token in tokenize(source)]
