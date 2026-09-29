MAX_ATTEMPTS = 5


def collatz_steps(n):
    steps = 0
    while n != 1:
        if n % 2:
            n = 3 * n + 1
        else:
            n //= 2
        steps += 1
    return steps


def retry(operation, attempts=MAX_ATTEMPTS):
    errors = []
    attempt = 0
    while attempt < attempts:
        attempt += 1
        try:
            result = operation(attempt)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if result is None:
            continue
        break
    else:
        return None, errors
    return result, errors


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def drain(queue):
    total = 0
    while queue:
        item = queue.pop()
        if item < 0:
            break
        if item == 0:
            continue
        total += item
    else:
        total = -total
    return total


def binary_search(items, wanted):
    low, high = 0, len(items) - 1
    while low <= high:
        mid = (low + high) // 2
        if items[mid] < wanted:
            low = mid + 1
        elif items[mid] > wanted:
            high = mid - 1
        else:
            return mid
    return -1
