class Root:
    def greet(self) -> list[str]:
        return ["root"]


class LeftMixin(Root):
    def greet(self) -> list[str]:
        return [*super().greet(), "left"]


class RightMixin(Root):
    def greet(self) -> list[str]:
        return [*super().greet(), "right"]


class Diamond(LeftMixin, RightMixin):
    def greet(self) -> list[str]:
        return [*super().greet(), "diamond"]


print(Diamond.__mro__)
print(Diamond().greet())
