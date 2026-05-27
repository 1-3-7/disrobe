# pyminifier output
__pyminifier__ = '2.1'
# pyminifier-reverse-map: o0=Holder; o1=__init__
from typing import Generic, TypeVar
T = TypeVar('T')

class Holder(Generic[T]):
    def __init__(self, value: T) -> None:
        self.value = value
