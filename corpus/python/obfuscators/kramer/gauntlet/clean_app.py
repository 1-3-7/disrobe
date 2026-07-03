import math


def greet(name):
    message = "Hello, " + name + "!"
    return message


def compute(values):
    total = 0
    for value in values:
        total = total + value * 2
    return total


class Calculator:
    def __init__(self, start):
        self.value = start

    def add(self, amount):
        self.value = self.value + amount
        return self.value

    def scale(self, factor):
        self.value = int(self.value * factor)
        return self.value


def main():
    print(greet("world"))
    numbers = [1, 2, 3, 4, 5]
    print(compute(numbers))
    calc = Calculator(10)
    calc.add(5)
    calc.scale(3)
    print(calc.value)
    print(math.sqrt(144))


if __name__ == "__main__":
    main()
