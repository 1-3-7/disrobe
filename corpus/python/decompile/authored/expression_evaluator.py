PRECEDENCE = {"+": 1, "-": 1, "*": 2, "/": 2, "%": 2, "^": 3}
RIGHT_ASSOC = frozenset("^")


def split_tokens(text):
    tokens = []
    number = ""
    for ch in text:
        if ch.isdigit() or ch == ".":
            number += ch
            continue
        if number:
            tokens.append(float(number))
            number = ""
        if ch in PRECEDENCE or ch in "()":
            tokens.append(ch)
        elif not ch.isspace():
            raise ValueError("bad character " + repr(ch))
    if number:
        tokens.append(float(number))
    return tokens


def to_postfix(tokens):
    output = []
    stack = []
    for token in tokens:
        if isinstance(token, float):
            output.append(token)
        elif token == "(":
            stack.append(token)
        elif token == ")":
            while stack and stack[-1] != "(":
                output.append(stack.pop())
            if not stack:
                raise ValueError("unbalanced")
            stack.pop()
        else:
            while (
                stack
                and stack[-1] != "("
                and (
                    PRECEDENCE[stack[-1]] > PRECEDENCE[token]
                    or (PRECEDENCE[stack[-1]] == PRECEDENCE[token] and token not in RIGHT_ASSOC)
                )
            ):
                output.append(stack.pop())
            stack.append(token)
    while stack:
        top = stack.pop()
        if top == "(":
            raise ValueError("unbalanced")
        output.append(top)
    return output


def evaluate(text):
    stack = []
    for token in to_postfix(split_tokens(text)):
        if isinstance(token, float):
            stack.append(token)
            continue
        right = stack.pop()
        left = stack.pop()
        if token == "+":
            stack.append(left + right)
        elif token == "-":
            stack.append(left - right)
        elif token == "*":
            stack.append(left * right)
        elif token == "/":
            stack.append(left / right)
        elif token == "%":
            stack.append(left % right)
        else:
            stack.append(left ** right)
    return stack[0] if len(stack) == 1 else None
