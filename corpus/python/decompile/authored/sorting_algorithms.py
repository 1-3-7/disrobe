def insertion_sort(items):
    data = list(items)
    for i in range(1, len(data)):
        key = data[i]
        j = i - 1
        while j >= 0 and data[j] > key:
            data[j + 1] = data[j]
            j -= 1
        data[j + 1] = key
    return data


def merge_sort(items):
    if len(items) <= 1:
        return list(items)
    mid = len(items) // 2
    left, right = merge_sort(items[:mid]), merge_sort(items[mid:])
    merged = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1
    merged.extend(left[i:])
    merged.extend(right[j:])
    return merged


def quick_sort(items):
    if len(items) < 2:
        return list(items)
    pivot, *rest = items
    return quick_sort([x for x in rest if x < pivot]) + [pivot] + quick_sort([x for x in rest if x >= pivot])


def heapify(data, size, root):
    largest = root
    left, right = 2 * root + 1, 2 * root + 2
    if left < size and data[left] > data[largest]:
        largest = left
    if right < size and data[right] > data[largest]:
        largest = right
    if largest != root:
        data[root], data[largest] = data[largest], data[root]
        heapify(data, size, largest)


def heap_sort(items):
    data = list(items)
    n = len(data)
    for root in range(n // 2 - 1, -1, -1):
        heapify(data, n, root)
    for end in range(n - 1, 0, -1):
        data[0], data[end] = data[end], data[0]
        heapify(data, end, 0)
    return data


def counting_sort(items, max_value):
    counts = [0] * (max_value + 1)
    for item in items:
        counts[item] += 1
    return [value for value, count in enumerate(counts) for _ in range(count)]
