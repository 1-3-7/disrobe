import dataclasses


@dataclasses.dataclass
class C[T = int]:
    x: T
