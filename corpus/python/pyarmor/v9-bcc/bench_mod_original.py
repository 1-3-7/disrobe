def mix_add(a, b):
    return (a + b) * 3 - (a ^ b)


def clamp(value, low, high):
    result = value
    if result < low:
        result = low
    if result > high:
        result = high
    return result


def poly(x):
    return x * x * x + 2 * x * x - 5 * x + 7


def main():
    total = 0
    for i in range(10):
        total = mix_add(total, i)
    total = clamp(total, 0, 100)
    total = poly(total % 7)
    print(total)


if __name__ == "__main__":
    main()
