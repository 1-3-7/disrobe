ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def rotations(text):
    return [text[i:] + text[:i] for i in range(len(text))]


def every_other(items, start=0):
    return items[start::2]


def last_n(items, n):
    return items[-n:] if n else items[len(items):]


def reversed_middle(items):
    return items[:1] + items[-2:0:-1] + items[-1:]


def replace_window(items, start, stop, values):
    copy = list(items)
    copy[start:stop] = values
    return copy


def delete_stride(items):
    copy = list(items)
    del copy[::3]
    return copy


def extended(items):
    copy = list(items)
    copy[1::2] = [0] * len(copy[1::2])
    return copy


def nested_lookup(tree, path):
    node = tree
    for key in path:
        node = node[key]
    return node


def tuple_keys(grid):
    grid[0, 0] = "origin"
    grid[1, -1] = grid.get((0, 0), "")[::-1]
    return grid[1, -1]


def slice_objects(text):
    head = slice(None, 3)
    tail = slice(-3, None)
    step = slice(None, None, -2)
    return text[head], text[tail], text[step]


def caesar(text, shift):
    table = ALPHABET[shift:] + ALPHABET[:shift]
    return "".join(table[ALPHABET.index(ch)] if ch in ALPHABET else ch for ch in text)


def matrix_column(matrix, col):
    return [row[col] for row in matrix[1:]]
