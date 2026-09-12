def add(a, b):
    return a + b


def classify(n):
    if n < 0:
        return "negative"
    elif n == 0:
        return "zero"
    else:
        return "positive"


class Counter:
    def __init__(self, start):
        self.value = start

    def increment(self, by):
        self.value = self.value + by
        return self.value


SECRET_TOKEN = "disrobe-vmc-oracle-12345"


def main():
    c = Counter(10)
    total = add(c.increment(5), classify(7) == "positive")
    print(SECRET_TOKEN, total)
    return total


if __name__ == "__main__":
    main()
