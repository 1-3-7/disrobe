"""Independent-oracle clean source for the differential playground gate.

This file is the ground-truth reference the differential-vs-source oracle
compares against. It is never emitted by any disrobe pass, so using it as the
oracle is non-circular: the obfuscated sibling clean_greeting.berserker.py was
produced by the real Berserker obfuscator from THIS source.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Greeter:
    name: str
    times: int

    def render(self) -> str:
        lines = [f"hello {self.name} #{i}" for i in range(self.times)]
        return "\n".join(lines)


def greet(name: str, times: int = 3) -> str:
    greeter = Greeter(name=name, times=times)
    return greeter.render()


def main() -> int:
    print(greet("disrobe"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
