

from __future__ import absolute_import, print_function

import sys
import traceback

from pex.typing import TYPE_CHECKING
from pex.variables import ENV

if TYPE_CHECKING:
    from typing import Any, Callable, Text, TypeVar, Union

    import attr

    _T = TypeVar("_T")
else:
    from pex.third_party import attr


@attr.s(frozen=True)
class Result(object):
    exit_code = attr.ib()
    _message = attr.ib(default="")

    @property
    def is_error(self):
        # type: () -> bool
        return self.exit_code != 0

    def maybe_display(self):
        # type: () -> None
        if not self._message:
            return
        print(self._message, file=sys.stderr if self.is_error else sys.stdout)

    def __str__(self):
        # type: () -> str
        return str(self._message)


class Ok(Result):
    def __init__(self, message=""):
        # type: (Text) -> None
        super(Ok, self).__init__(exit_code=0, message=message)


class Error(Result):
    def __init__(
        self,
        message="",
        exit_code=1,
    ):
        # type: (...) -> None
        if exit_code == 0:
            raise ValueError("An Error must have a non-zero exit code; given: {}".format(exit_code))
        super(Error, self).__init__(exit_code=exit_code, message=message)


@attr.s
class ResultError(Exception):

    error = attr.ib()

    def __str__(self):
        # type: () -> str
        return str(self.error)


def try_(result):
    # type: (Union[_T, Error]) -> _T
    if isinstance(result, Error):
        raise ResultError(error=result)
    return result


def catch(
    func,
    *args,
    **kwargs
):
    # type: (...) -> Union[_T, Error]
    try:
        return func(*args, **kwargs)
    except ResultError as e:
        return e.error
    except Exception as e:
        if ENV.PEX_VERBOSE > 0:
            traceback.print_exc()
        return Error(str(e))
