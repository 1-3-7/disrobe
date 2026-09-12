class Base:
    def __init__(self, name):
        self.name = name
    def describe(self):
        return self.name

class Derived(Base):
    def __init__(self, name, level):
        super().__init__(name)
        self.level = level
    def describe(self):
        return super().describe() + str(self.level)
