class Validated:
    def __init__(self, *, minimum: int, maximum: int) -> None:
        self.minimum = minimum
        self.maximum = maximum

    def __set_name__(self, owner: type, name: str) -> None:
        self.attr = f"_{name}"

    def __get__(self, obj, objtype=None) -> int:
        if obj is None:
            return self
        return getattr(obj, self.attr)

    def __set__(self, obj, value: int) -> None:
        if not (self.minimum <= value <= self.maximum):
            raise ValueError(f"{value} out of [{self.minimum},{self.maximum}]")
        setattr(obj, self.attr, value)


class Sensor:
    temperature = Validated(minimum=-40, maximum=125)
    humidity = Validated(minimum=0, maximum=100)


s = Sensor()
s.temperature = 22
s.humidity = 55
print(s.temperature, s.humidity)
