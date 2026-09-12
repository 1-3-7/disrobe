

from __future__ import absolute_import

import fcntl

from pex.fs.lock import FileLock, FileLockStyle
from pex.typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from typing import Callable


class PosixFileLock(FileLock):
    @staticmethod
    def _lock_api(style):
        # type: (FileLockStyle.Value) -> Callable[[int, int], None]

        return cast(
            "Callable[[int, int], None]",
            fcntl.flock if style is FileLockStyle.BSD else fcntl.lockf,
        )

    @classmethod
    def acquire(
        cls,
        fd,
        exclusive,
        style,
    ):
        # type: (...) -> PosixFileLock

        cls._lock_api(style)(
            fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        )
        return cls(locked_fd=fd, unlock=lambda: cls.release_lock(fd, style=style))

    @classmethod
    def release_lock(
        cls,
        fd,
        style,
    ):
        # type: (...) -> None

        cls._lock_api(style)(fd, fcntl.LOCK_UN)
