import math


class Ledger:
    def __init__(self, owner):
        self.owner = owner
        self.entries = []

    def add(self, amount, note=""):
        if amount == 0:
            raise ValueError("empty entry")
        self.entries.append((amount, note))
        return len(self.entries)

    def balance(self):
        return sum(amount for amount, _ in self.entries)


def classify(value):
    if value < 0:
        return "debit"
    elif value > 100:
        return "large"
    return "credit"


def summarize(ledger):
    kinds = {}
    for amount, note in ledger.entries:
        kind = classify(amount)
        kinds[kind] = kinds.get(kind, 0) + 1
    labels = [f"{name}={count}" for name, count in sorted(kinds.items())]
    return ", ".join(labels)


def main():
    ledger = Ledger("ann")
    for amount in (40, -15, 250, 7):
        ledger.add(amount, note=f"n{amount}")
    try:
        ledger.add(0)
    except ValueError as error:
        print("refused:", error)
    print(ledger.owner, ledger.balance(), summarize(ledger))
    print(round(math.sqrt(ledger.balance()), 3))


if __name__ == "__main__":
    main()
