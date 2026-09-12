

from __future__ import absolute_import, print_function

import itertools
import os
from contextlib import contextmanager

from pex.common import touch
from pex.fs import lock
from pex.fs.lock import FileLockStyle
from pex.os import WINDOWS
from pex.typing import TYPE_CHECKING
from pex.variables import ENV

if TYPE_CHECKING:
    from typing import Iterator, Optional, Tuple, Union

    from pex.cache.dirs import UnzipDir, VenvDir, VenvDirs


_LOCK = None

_PEX_CACHE_ACCESS_LOCK_ENV_VAR = "_PEX_CACHE_ACCESS_LOCK"


def save_lock_state():
    # type: () -> None


    global _LOCK
    if _LOCK is not None:
        exclusive, lock_fd, lock_file = _LOCK
        os.environ[_PEX_CACHE_ACCESS_LOCK_ENV_VAR] = "|".join(
            (str(int(exclusive)), str(lock_fd), lock_file)
        )


def _maybe_restore_lock_state():
    # type: () -> None

    saved_lock_state = os.environ.pop(_PEX_CACHE_ACCESS_LOCK_ENV_VAR, None)
    if saved_lock_state:
        encoded_exclusive, encoded_lock_fd, lock_file = saved_lock_state.split("|", 2)
        global _LOCK
        _LOCK = bool(int(encoded_exclusive)), int(encoded_lock_fd), lock_file


def _lock(exclusive):
    # type: (bool) -> str

    lock_fd = None

    global _LOCK
    if _LOCK is None:
        _maybe_restore_lock_state()
    if _LOCK is not None:
        existing_exclusive, lock_fd, existing_lock_file = _LOCK
        if existing_exclusive == exclusive:
            return existing_lock_file
        elif WINDOWS:

            lock.release(lock_fd)

    lock_file = os.path.join(ENV.PEX_ROOT, "access.lck")

    file_lock = lock.acquire(lock_file, exclusive=exclusive, style=FileLockStyle.BSD, fd=lock_fd)
    _LOCK = exclusive, file_lock.fd, lock_file
    return lock_file


def read_write():
    # type: () -> str
    return _lock(exclusive=False)


@contextmanager
def await_delete_lock():
    # type: () -> Iterator[str]
    lock_file = _lock(exclusive=False)
    yield lock_file
    _lock(exclusive=True)


LAST_ACCESS_FILE = ".last-access"


def _last_access_file(pex_dir):
    # type: (Union[UnzipDir, VenvDir, VenvDirs]) -> str
    return os.path.join(pex_dir.path, LAST_ACCESS_FILE)


def record_access(
    pex_dir,
    last_access=None,
):
    # type: (...) -> None

    touch(_last_access_file(pex_dir), last_access)


def iter_all_cached_pex_dirs():
    # type: () -> Iterator[Tuple[Union[UnzipDir, VenvDirs], float]]

    from pex.cache.dirs import UnzipDir, VenvDirs

    pex_dirs = itertools.chain(
        UnzipDir.iter_all(), VenvDirs.iter_all()
    )
    for pex_dir in pex_dirs:
        last_access = os.stat(_last_access_file(pex_dir)).st_mtime
        yield pex_dir, last_access
