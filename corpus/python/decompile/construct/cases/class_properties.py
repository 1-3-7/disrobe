class C:
    def __init__(self):
        self._value = 0
    @property
    def value(self):
        return self._value
    @value.setter
    def value(self, new):
        self._value = max(0, new)
