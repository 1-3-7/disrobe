import math

NAMES = ['alpha', 'beta', 'gamma']


def total(values):
    acc = 0
    for v in values:
        acc = acc + v
    return acc


def classify(n):
    if n > 100:
        return 'big'
    elif n > 10:
        return 'medium'
    return 'small'


class Counter:
    def __init__(self, start):
        self.value = start

    def bump(self, amount):
        self.value = self.value + amount
        return self.value


def main():
    c = Counter(10)
    c.bump(5)
    print(classify(total([20, 30, 60])))
    print(NAMES[1], math.floor(3.7))


if __name__ == '__main__':
    main()
