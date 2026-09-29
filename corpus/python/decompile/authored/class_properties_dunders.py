import functools


@functools.total_ordering
class Money:
    __slots__ = ("_cents", "currency")
    PRECISION = 100

    def __init__(self, amount, currency="EUR"):
        self._cents = round(amount * self.PRECISION)
        self.currency = currency

    @property
    def amount(self):
        return self._cents / self.PRECISION

    @amount.setter
    def amount(self, value):
        if value < 0:
            raise ValueError("negative amount")
        self._cents = round(value * self.PRECISION)

    @staticmethod
    def parse(text):
        number, _, currency = text.partition(" ")
        return Money(float(number), currency or "EUR")

    @classmethod
    def zero(cls, currency="EUR"):
        return cls(0, currency)

    def __add__(self, other):
        if not isinstance(other, Money):
            return NotImplemented
        if other.currency != self.currency:
            raise ValueError("currency mismatch")
        return Money((self._cents + other._cents) / self.PRECISION, self.currency)

    __radd__ = __add__

    def __eq__(self, other):
        return isinstance(other, Money) and (self._cents, self.currency) == (other._cents, other.currency)

    def __lt__(self, other):
        return self._cents < other._cents

    def __hash__(self):
        return hash((self._cents, self.currency))

    def __repr__(self):
        return "Money(%r, %r)" % (self.amount, self.currency)

    def __bool__(self):
        return self._cents != 0

    def __len__(self):
        return len(str(abs(self._cents)))

    def __getitem__(self, index):
        return str(self._cents)[index]

    def __contains__(self, digit):
        return str(digit) in str(self._cents)
