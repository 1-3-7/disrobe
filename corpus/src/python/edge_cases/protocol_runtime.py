from typing import Protocol, runtime_checkable


@runtime_checkable
class Greeter(Protocol):
    def greet(self) -> str: ...


class Hello:
    def greet(self) -> str:
        return "hello"


class NotGreeter:
    def shout(self) -> str:
        return "OI"


def announce(g: Greeter) -> str:
    return f"announce: {g.greet()}"


print(isinstance(Hello(), Greeter), isinstance(NotGreeter(), Greeter))
print(announce(Hello()))
