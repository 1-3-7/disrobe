

from __future__ import absolute_import

import os

from pex.common import safe_mkdir
from pex.enum import Enum
from pex.os import WINDOWS
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

    import attr
else:
    from pex.third_party import attr


class FileLockStyle(Enum["FileLockStyle.Value"]):
    class Value(Enum.Value):
        pass

    BSD = Value("bsd")
    POSIX = Value("posix")


FileLockStyle.seal()


@attr.s(frozen=True)
class FileLock(object):
    _locked_fd = attr.ib()
    _unlock = attr.ib()

    @property
    def fd(self):
        # type: () -> int
        return self._locked_fd

    def release(self):
        # type: () -> None
        try:
            self._unlock()
        finally:
            os.close(self._locked_fd)


def acquire(
    path,
    exclusive=True,
    style=FileLockStyle.POSIX,
    fd=None,
):
    # type: (...) -> FileLock

    if fd:
        lock_fd = fd
    else:


        safe_mkdir(os.path.dirname(path))
        lock_fd = os.open(path, os.O_CREAT | os.O_WRONLY)

    if WINDOWS:
        from pex.fs._windows import WindowsFileLock

        return WindowsFileLock.acquire(lock_fd, exclusive=exclusive)
    else:
        from pex.fs._posix import PosixFileLock

        return PosixFileLock.acquire(lock_fd, exclusive=exclusive, style=style)


def release(
    fd,
    style=FileLockStyle.POSIX,
):
    # type: (...) -> None

    if WINDOWS:
        from pex.fs._windows import WindowsFileLock

        WindowsFileLock.release_lock(fd)
    else:
        from pex.fs._posix import PosixFileLock

        PosixFileLock.release_lock(fd, style=style)
