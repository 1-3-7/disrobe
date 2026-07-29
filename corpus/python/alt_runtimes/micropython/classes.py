class Counter:
    step = 1

    def __init__(self, start):
        self.value = start

    def bump(self, amount):
        self.value += amount
        return self.value

    def reset(self):
        self.value = 0
        return self.value


class Doubler(Counter):
    def bump(self, amount):
        return super().bump(amount * 2)


c = Doubler(3)
print(c.bump(4))
print(c.reset())
print(Counter.step)
