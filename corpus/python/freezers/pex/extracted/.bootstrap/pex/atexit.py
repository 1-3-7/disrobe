

from __future__ import absolute_import, print_function

import atexit
import functools
import sys
import traceback

from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable, List, Optional


class Once(object):
    def __init__(
        self,
        fn,
        *args,
        **kwargs
    ):
        # type: (...) -> None
        self._func = functools.partial(fn, *args, **kwargs)

    def __call__(self):
        # type: () -> None
        self.execute_once()

    def execute_once(self):
        # type: () -> None
        if self._func:
            try:
                self._func()
            finally:
                self._func = None


class AtExit(object):
    def __init__(self):
        self._exit_fns = []

    def register(
        self,
        fn,
        *args,
        **kwargs
    ):
        # type: (...) -> None

        func = Once(fn, *args, **kwargs)
        self._exit_fns.append(func)
        atexit.register(func)

    def exit(self):
        # type: () -> None

        while self._exit_fns:
            func = self._exit_fns.pop()
            try:
                func()
            except:
                print("Problem executing atexit function, continuing:", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)


_ATEXIT = AtExit()


def register(
    fn,
    *args,
    **kwargs
):
    # type: (...) -> None
    _ATEXIT.register(fn, *args, **kwargs)


def perform_exit():
    # type: () -> None
    _ATEXIT.exit()
