def windows(items, size):
    head = items[:size]
    tail = items[-size:]
    middle = items[1:-1]
    stride = items[::2]
    reverse = items[::-1]
    items[0:2] = [head[-1], tail[0]]
    return head, tail, middle, stride, reverse, items


print(windows(list(range(10)), 3))
