type Vector[T] = list[T]
type Pair[K, V] = tuple[K, V]
type Mapping[K, V] = dict[K, V]
type Recursive[T] = T | list[Recursive[T]]


def head[T](xs: Vector[T]) -> T:
    if not xs:
        raise IndexError("empty")
    return xs[0]


def swap[K, V](p: Pair[K, V]) -> Pair[V, K]:
    return (p[1], p[0])


def deep_count[T](xs: Recursive[T]) -> int:
    if isinstance(xs, list):
        return sum(deep_count(x) for x in xs)
    return 1


print(head([1, 2, 3]))
print(swap(("a", 1)))
print(deep_count([1, [2, [3, [4]]], 5]))
