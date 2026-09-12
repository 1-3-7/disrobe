from functools import cached_property


class Vec3:
    __slots__ = ("_x", "_y", "_z", "__dict__")

    def __init__(self, x: float, y: float, z: float) -> None:
        self._x = x
        self._y = y
        self._z = z

    @property
    def x(self) -> float:
        return self._x

    @x.setter
    def x(self, v: float) -> None:
        if v != v:
            raise ValueError("NaN")
        self._x = v

    @cached_property
    def magnitude_sq(self) -> float:
        return self._x * self._x + self._y * self._y + self._z * self._z


v = Vec3(1.0, 2.0, 2.0)
v.x = 3.0
print(v.magnitude_sq, v.magnitude_sq)
