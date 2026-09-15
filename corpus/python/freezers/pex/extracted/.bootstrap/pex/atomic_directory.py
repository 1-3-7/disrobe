

from __future__ import absolute_import

import errno
import hashlib
import os
import threading
from contextlib import contextmanager
from uuid import uuid4

import pex
from pex import pex_warnings
from pex.common import safe_mkdir, safe_rmtree
from pex.fs import lock
from pex.fs.lock import FileLockStyle
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable, Dict, Iterator, Optional

    import attr
else:
    from pex.third_party import attr


class AtomicDirectory(object):

    def __init__(
        self,
        target_dir,
        locked=False,
    ):
        # type: (...) -> None

        head, tail = os.path.split(os.path.normpath(target_dir))
        self._lockfile = os.path.join(
            head, ".{target_dir_name}.atomic_directory.lck".format(target_dir_name=tail)
        )
        self._work_dir = "{target_dir}.{type}.work".format(
            target_dir=target_dir, type="lck" if locked else uuid4().hex
        )
        self._target_dir = target_dir

        target_basename = os.path.basename(self._work_dir)
        if len(target_basename) > 143:


            fingerprint = hashlib.sha256(target_basename.encode("utf-8")).hexdigest()
            self._work_dir = os.path.join(
                os.path.dirname(self._target_dir),
                "{prefix}...{fingerprint}".format(
                    prefix=target_basename[: 143 - 3 - len(fingerprint)], fingerprint=fingerprint
                ),
            )

    @property
    def work_dir(self):
        # type: () -> str
        return self._work_dir

    @property
    def target_dir(self):
        # type: () -> str
        return self._target_dir

    def is_finalized(self):
        # type: () -> bool
        return os.path.exists(self._target_dir)

    @property
    def lockfile(self):
        # type: () -> str
        return self._lockfile

    def lock(self, lock_style=None):
        # type: (Optional[FileLockStyle.Value]) -> Callable[[], None]
        return _LOCK_MANAGER.lock(self._lockfile, lock_style=lock_style)

    @contextmanager
    def locked(self, lock_style=None):
        # type: (Optional[FileLockStyle.Value]) -> Iterator[None]
        unlock = self.lock(lock_style=lock_style)
        try:
            yield
        finally:
            unlock()

    def finalize(self, source=None):
        # type: (Optional[str]) -> None
        if self.is_finalized():
            return

        source = os.path.join(self._work_dir, source) if source else self._work_dir
        try:


            pex.fs.safe_rename(source, self._target_dir)
        except OSError as e:
            if e.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise e
        finally:
            self.cleanup()

    def cleanup(self):
        # type: () -> None
        safe_rmtree(self._work_dir)


def _lock_style(lock_style=None):
    # type: (Optional[FileLockStyle.Value]) -> FileLockStyle.Value


    return lock_style or FileLockStyle.for_value(
        os.environ.get("_PEX_FILE_LOCK_STYLE", FileLockStyle.POSIX.value)
    )


@attr.s(frozen=True)
class _FileLock(object):
    _path = attr.ib()
    _style = attr.ib(default=None)
    _in_process_lock = attr.ib(factory=threading.Lock, init=False, eq=False)

    def acquire(self):
        # type: () -> Callable[[], None]
        self._in_process_lock.acquire()
        file_lock = lock.acquire(self._path, exclusive=True, style=_lock_style(self._style))

        def release():
            # type: () -> None
            try:
                file_lock.release()
            finally:
                self._in_process_lock.release()

        return release


@attr.s(frozen=True, eq=False)
class _LockManager(object):
    _lock = attr.ib(factory=threading.Lock, init=False)
    _file_locks = attr.ib(factory=dict, init=False)

    def lock(
        self,
        file_path,
        lock_style=None,
    ):
        # type: (...) -> Callable[[], None]
        with self._lock:
            file_lock = self._file_locks.get(file_path)
            if file_lock is None:
                file_lock = _FileLock(file_path, style=lock_style)
                self._file_locks[file_path] = file_lock

        return file_lock.acquire()


_LOCK_MANAGER = _LockManager()


@contextmanager
def atomic_directory(
    target_dir,
    lock_style=None,
    source=None,
):
    # type: (...) -> Iterator[AtomicDirectory]


    atomic_dir = AtomicDirectory(target_dir=target_dir, locked=True)
    if atomic_dir.is_finalized():

        yield atomic_dir
        return

    unlock = atomic_dir.lock(lock_style=lock_style)
    if atomic_dir.is_finalized():


        try:
            yield atomic_dir
        finally:
            unlock()
        return


    try:
        os.mkdir(atomic_dir.work_dir)
    except OSError as e:
        ident = "[pid:{pid}, tid:{tid}, cwd:{cwd}]".format(
            pid=os.getpid(), tid=threading.current_thread().ident, cwd=os.getcwd()
        )
        pex_warnings.warn(
            "{ident}: After obtaining an exclusive lock on {lockfile}, failed to establish a work "
            "directory at {workdir} due to: {err}".format(
                ident=ident,
                lockfile=atomic_dir.lockfile,
                workdir=atomic_dir.work_dir,
                err=e,
            ),
        )
        if e.errno != errno.EEXIST:
            raise
        pex_warnings.warn(
            "{ident}: Continuing to forcibly re-create the work directory at {workdir}.".format(
                ident=ident,
                workdir=atomic_dir.work_dir,
            )
        )
        safe_mkdir(atomic_dir.work_dir, clean=True)

    try:
        yield atomic_dir
    except Exception:
        atomic_dir.cleanup()
        raise
    else:
        atomic_dir.finalize(source=source)
    finally:
        unlock()
