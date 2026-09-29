from collections import Counter, OrderedDict, defaultdict, deque, namedtuple

Edge = namedtuple("Edge", "source target weight")
STOP_WORDS = frozenset({"the", "a", "and", "of", "to"})


def word_frequencies(text, top=3):
    words = [w.strip(".,;!?").lower() for w in text.split()]
    counts = Counter(w for w in words if w and w not in STOP_WORDS)
    return counts.most_common(top)


def group_by_length(words):
    groups = defaultdict(list)
    for word in words:
        groups[len(word)].append(word)
    return dict(groups)


def adjacency(edges):
    graph = defaultdict(dict)
    for edge in edges:
        graph[edge.source][edge.target] = edge.weight
        graph[edge.target].setdefault(edge.source, edge.weight)
    return graph


def breadth_first(graph, start):
    order = []
    seen = {start}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        order.append(node)
        for neighbour in sorted(graph.get(node, ())):
            if neighbour not in seen:
                seen.add(neighbour)
                queue.append(neighbour)
    return order


class LruCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.entries = OrderedDict()

    def get(self, key, default=None):
        if key not in self.entries:
            return default
        self.entries.move_to_end(key)
        return self.entries[key]

    def put(self, key, value):
        self.entries[key] = value
        self.entries.move_to_end(key)
        while len(self.entries) > self.capacity:
            self.entries.popitem(last=False)


def sliding_sums(values, width):
    window = deque(maxlen=width)
    sums = []
    for value in values:
        window.append(value)
        if len(window) == width:
            sums.append(sum(window))
    return sums
