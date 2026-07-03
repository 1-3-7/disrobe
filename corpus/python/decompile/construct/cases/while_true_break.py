def f(queue):
    while True:
        if not queue:
            break
        item = queue.pop()
        if item < 0:
            return item
    return 0
