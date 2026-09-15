
__all__ = ["TYPE_CHECKING", "cast"]


if False:
    from typing import TYPE_CHECKING
else:
    TYPE_CHECKING = False


if TYPE_CHECKING:

    from typing import cast
else:

    def cast(type_, value):
        return value
