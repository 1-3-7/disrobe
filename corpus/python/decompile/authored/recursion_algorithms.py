def factorial(n):
    return 1 if n <= 1 else n * factorial(n - 1)


def power_set(items):
    if not items:
        return [[]]
    rest = power_set(items[1:])
    return rest + [[items[0]] + subset for subset in rest]


def permutations(items):
    if len(items) <= 1:
        return [list(items)]
    result = []
    for index, item in enumerate(items):
        for perm in permutations(items[:index] + items[index + 1:]):
            result.append([item] + perm)
    return result


def hanoi(n, source="A", target="C", spare="B", moves=None):
    if moves is None:
        moves = []
    if n:
        hanoi(n - 1, source, spare, target, moves)
        moves.append((source, target))
        hanoi(n - 1, spare, target, source, moves)
    return moves


def depth(tree):
    if not isinstance(tree, dict) or not tree:
        return 0
    return 1 + max(depth(child) for child in tree.values())


def ackermann(m, n):
    if m == 0:
        return n + 1
    if n == 0:
        return ackermann(m - 1, 1)
    return ackermann(m - 1, ackermann(m, n - 1))


def is_even(n):
    return True if n == 0 else is_odd(n - 1)


def is_odd(n):
    return False if n == 0 else is_even(n - 1)


def evaluate(expr):
    if isinstance(expr, (int, float)):
        return expr
    op, left, right = expr
    a, b = evaluate(left), evaluate(right)
    if op == "+":
        return a + b
    if op == "*":
        return a * b
    if op == "-":
        return a - b
    raise ValueError(op)
