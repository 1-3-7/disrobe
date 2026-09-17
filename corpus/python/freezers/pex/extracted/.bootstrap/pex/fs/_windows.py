

from __future__ import absolute_import

import ctypes
import msvcrt
from ctypes.wintypes import BOOL, DWORD, HANDLE, LPVOID, PULONG, ULONG

from pex.fs.lock import FileLock
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional


class Offset(ctypes.Structure):
    _fields_ = [
        ("Offset", DWORD),
        ("OffsetHigh", DWORD),
    ]


class OffsetUnion(ctypes.Union):
    _fields_ = [("Offset", Offset), ("Pointer", LPVOID)]


class Overlapped(ctypes.Structure):
    @classmethod
    def ignored(cls):
        # type: () -> Overlapped
        return cls(PULONG(ULONG(0)), PULONG(ULONG(0)), OffsetUnion(Offset(0, 0)), HANDLE(0))

    _fields_ = [
        ("Internal", PULONG),
        ("InternalHigh", PULONG),
        ("OffsetUnion", OffsetUnion),
        ("hEvent", HANDLE),
    ]


_LockFileEx = ctypes.windll.kernel32.LockFileEx
_LockFileEx.argtypes = (
    HANDLE,
    DWORD,
    DWORD,
    DWORD,
    DWORD,
    Overlapped,
)
_LockFileEx.restype = BOOL
_LOCKFILE_EXCLUSIVE_LOCK = 0x2


_UnlockFileEx = ctypes.windll.kernel32.UnlockFileEx
_UnlockFileEx.argtypes = (
    HANDLE,
    DWORD,
    DWORD,
    DWORD,
    Overlapped,
)
_UnlockFileEx.restype = BOOL


class WindowsFileLock(FileLock):
    @classmethod
    def acquire(
        cls,
        fd,
        exclusive,
    ):
        # type: (...) -> WindowsFileLock

        mode = 0
        if exclusive:
            mode |= _LOCKFILE_EXCLUSIVE_LOCK

        overlapped = Overlapped.ignored()
        fhandle = msvcrt.get_osfhandle(fd)
        if not _LockFileEx(
            HANDLE(fhandle),
            DWORD(mode),
            DWORD(0),
            DWORD(1),
            DWORD(0),
            overlapped,
        ):
            raise ctypes.WinError()
        return cls(locked_fd=fd, unlock=lambda: cls.release_lock(fd, overlapped=overlapped))

    @classmethod
    def release_lock(
        cls,
        fd,
        overlapped=None,
    ):
        # type: (...) -> None

        fhandle = msvcrt.get_osfhandle(fd)
        if not _UnlockFileEx(
            HANDLE(fhandle),
            DWORD(0),
            DWORD(1),
            DWORD(0),
            overlapped or Overlapped.ignored(),
        ):
            raise ctypes.WinError()
