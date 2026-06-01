from abc import ABC, abstractmethod


class Pluggable(ABC):
    plugins: dict[str, type] = {}

    def __init_subclass__(cls, *, key: str | None = None, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        resolved: str = key if key is not None else cls.__name__.lower()
        Pluggable.plugins[resolved] = cls

    @abstractmethod
    def run(self) -> str: ...


class Alpha(Pluggable, key="a"):
    def run(self) -> str:
        return "alpha"


class Beta(Pluggable):
    def run(self) -> str:
        return "beta"


print(sorted(Pluggable.plugins))
print(Alpha().run(), Beta().run())
