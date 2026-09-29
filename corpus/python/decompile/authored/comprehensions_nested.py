WORDS = ("apple", "banana", "cherry", "date", "elderberry", "fig")


def squares_of_evens(limit):
    return [n * n for n in range(limit) if n % 2 == 0]


def vowel_set(words):
    return {ch for word in words for ch in word if ch in "aeiou"}


def index_by_initial(words):
    return {word[0]: word for word in words if len(word) > 3}


def length_histogram(words):
    return {length: [w for w in words if len(w) == length] for length in {len(w) for w in words}}


def matrix_flatten(matrix):
    return [cell for row in matrix for cell in row]


def identity(size):
    return [[1 if r == c else 0 for c in range(size)] for r in range(size)]


def pythagorean(limit):
    return [
        (a, b, c)
        for a in range(1, limit)
        for b in range(a, limit)
        for c in range(b, limit)
        if a * a + b * b == c * c
    ]


def total_letters(words):
    return sum(len(word) for word in words if not word.startswith("e"))


def any_long(words, threshold):
    return any(len(word) > threshold for word in words)


def label_numbers(values):
    return ["even" if v % 2 == 0 else "odd" for v in values]


def invert(mapping):
    return {value: key for key, value in mapping.items()}


def pairs_without_diagonal(n):
    return [(i, j) for i in range(n) for j in range(n) if i != j if (i + j) % 3]
