from dataclasses import dataclass


@dataclass
class B:
    x: int
    y: int = 0

    def total(self):
        return self.x + self.y
