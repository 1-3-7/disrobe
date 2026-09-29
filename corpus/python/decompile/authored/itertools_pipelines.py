import itertools
import operator


def running_totals(values):
    return list(itertools.accumulate(values, operator.add))


def grouped_runs(text):
    return [(key, len(list(group))) for key, group in itertools.groupby(text)]


def pairwise_diffs(values):
    a, b = itertools.tee(values)
    next(b, None)
    return [y - x for x, y in zip(a, b)]


def windows(values, size):
    iterators = itertools.tee(values, size)
    for offset, iterator in enumerate(iterators):
        for _ in range(offset):
            next(iterator, None)
    return list(zip(*iterators))


def card_deck():
    ranks = [str(n) for n in range(2, 11)] + list("JQKA")
    suits = "SHDC"
    return ["".join(card) for card in itertools.product(ranks, suits)]


def combos(items, size):
    return {
        "combinations": list(itertools.combinations(items, size)),
        "with_replacement": len(list(itertools.combinations_with_replacement(items, size))),
        "permutations": len(list(itertools.permutations(items, size))),
    }


def round_robin(*iterables):
    sentinel = object()
    for group in itertools.zip_longest(*iterables, fillvalue=sentinel):
        for item in group:
            if item is not sentinel:
                yield item


def first_n_evens(n):
    evens = (x for x in itertools.count() if x % 2 == 0)
    return list(itertools.islice(evens, n))


def cycle_labels(values, labels):
    return list(zip(values, itertools.cycle(labels)))


def until_negative(values):
    before = list(itertools.takewhile(lambda v: v >= 0, values))
    after = list(itertools.dropwhile(lambda v: v >= 0, values))
    return before, after, list(itertools.chain(after, before))
