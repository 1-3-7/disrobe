

from __future__ import absolute_import, print_function

import sys

TYPE_CHECKING = False


if TYPE_CHECKING:
    from typing import Generic as Generic
    from typing import Type
    from typing import cast as cast
    from typing import overload as overload

    if sys.version_info[:2] >= (3, 8):
        from typing import Literal as Literal
    else:
        from typing_extensions import Literal as Literal
else:

    def cast(_type, value):
        return value

    def overload(_func):
        def _never_called_since_structurally_shadowed(*_args, **_kwargs):
            raise NotImplementedError(
                "You should not call an overloaded function. A series of @overload-decorated "
                "functions outside a stub module should always be followed by an implementation "
                "that is not @overload-ed."
            )

        return _never_called_since_structurally_shadowed

    class _Generic(type):
        def __getitem__(cls, type_var):
            # type: (str) -> Type
            setattr(cls, "_type_var", type_var)
            return cls

        @property
        def type_var(self):
            # type: () -> str

            from pex.exceptions import production_assert

            type_var = getattr(self, "_type_var", None)
            production_assert(
                isinstance(type_var, str),
                "Expected a string _type_var attribute on {cls}, found {type_var}",
                cls=self,
                type_var=type_var,
            )
            return type_var

    if sys.version_info[0] == 2:

        class Generic(object):
            __metaclass__ = _Generic

    else:
        eval(compile("class Generic(object, metaclass=_Generic): pass", "<Generic>", "exec"))

    del _Generic

    Literal = {}
