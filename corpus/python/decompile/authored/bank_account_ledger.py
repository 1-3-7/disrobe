from decimal import Decimal

OVERDRAFT_LIMIT = Decimal("-100.00")
FEE = Decimal("2.50")


class InsufficientFunds(Exception):
    pass


class Account:
    next_number = 1000

    def __init__(self, owner, balance="0"):
        self.owner = owner
        self.balance = Decimal(balance)
        self.number = Account.next_number
        Account.next_number += 1
        self.ledger = []

    def deposit(self, amount):
        amount = Decimal(amount)
        if amount <= 0:
            raise ValueError("deposit must be positive")
        self.balance += amount
        self.ledger.append(("deposit", amount))
        return self.balance

    def withdraw(self, amount):
        amount = Decimal(amount)
        projected = self.balance - amount
        if projected < OVERDRAFT_LIMIT:
            raise InsufficientFunds("%s: %s" % (self.owner, projected))
        if projected < 0:
            projected -= FEE
            self.ledger.append(("fee", FEE))
        self.balance = projected
        self.ledger.append(("withdraw", amount))
        return self.balance

    def statement(self):
        lines = ["Account %d (%s)" % (self.number, self.owner)]
        running = Decimal(0)
        for kind, amount in self.ledger:
            running += amount if kind == "deposit" else -amount
            lines.append("%-8s %10s %10s" % (kind, amount, running))
        return "\n".join(lines)


def transfer(source, target, amount):
    try:
        source.withdraw(amount)
    except InsufficientFunds:
        return False
    else:
        target.deposit(amount)
        return True
    finally:
        source.ledger.append(("transfer", Decimal(0)))
