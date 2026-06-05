

from __future__ import absolute_import

from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


def qualified_name(item):
    # type: (Any) -> str
    if isinstance(item, property):
        item = item.fget
    if not hasattr(item, "__name__"):
        item = type(item)
    return "{module}.{type}".format(
        module=getattr(item, "__module__", "<unknown module>"),

        type=getattr(item, "__qualname__", item.__name__),
    )
