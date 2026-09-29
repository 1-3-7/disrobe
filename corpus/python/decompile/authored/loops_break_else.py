def first_prime_after(start):
    candidate = start + 1
    while True:
        for divisor in range(2, int(candidate ** 0.5) + 1):
            if candidate % divisor == 0:
                break
        else:
            return candidate
        candidate += 1


def find_pair(numbers, target):
    for i, left in enumerate(numbers):
        for j in range(i + 1, len(numbers)):
            if left + numbers[j] == target:
                return i, j
    return None


def all_ascii(words):
    for word in words:
        for ch in word:
            if ord(ch) > 127:
                break
        else:
            continue
        return False
    else:
        return True


def skip_comments(lines):
    kept = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if stripped == "__end__":
            break
        kept.append(stripped)
    else:
        kept.append("<eof>")
    return kept


def count_down(limit):
    trace = []
    n = limit
    while n > 0:
        n -= 1
        if n % 3 == 0:
            continue
        if n == 1:
            break
        trace.append(n)
    else:
        trace.append(-1)
    return trace
