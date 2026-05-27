# Oxyry.com minified
__oxyry__ = '1'

from typing import Generic, TypeVar
T = TypeVar('T')

class Holder(Generic[T]):
    def __init__(self, value: T) -> None:
        self.value = value
