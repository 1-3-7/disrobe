

from __future__ import absolute_import

import os
import sys

from pex.os import WINDOWS
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Text

if WINDOWS and not hasattr(os, "replace"):
    _MOVEFILE_REPLACE_EXISTING = 0x1

    _MF = None

    def safe_rename(
        src,
        dst,
    ):
        # type: (...) -> None

        import ctypes
        from ctypes.wintypes import BOOL, DWORD, LPCWSTR

        global _MF
        if _MF is None:
            mf = ctypes.windll.kernel32.MoveFileExW
            mf.argtypes = (

                LPCWSTR,

                LPCWSTR,

                DWORD,
            )
            mf.restype = BOOL
            _MF = mf


        if not _MF(src, dst, _MOVEFILE_REPLACE_EXISTING):
            raise ctypes.WinError()

else:
    safe_rename = getattr(os, "replace", os.rename)


if WINDOWS and (not hasattr(os, "symlink") or sys.version_info[:2] < (3, 8)):
    _SYMBOLIC_LINK_FLAG_FILE = 0x0
    _SYMBOLIC_LINK_FLAG_DIRECTORY = 0x1
    _SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = 0x2

    _CSL = None

    def safe_symlink(
        src,
        dst,
    ):
        # type: (...) -> None

        import ctypes
        from ctypes.wintypes import BOOLEAN, DWORD, LPCWSTR

        global _CSL
        if _CSL is None:
            csl = ctypes.windll.kernel32.CreateSymbolicLinkW
            csl.argtypes = (

                LPCWSTR,

                LPCWSTR,

                DWORD,
            )
            csl.restype = BOOLEAN
            _CSL = csl


        flags = _SYMBOLIC_LINK_FLAG_DIRECTORY if os.path.isdir(src) else _SYMBOLIC_LINK_FLAG_FILE
        flags |= _SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
        if not _CSL(dst, src, flags):
            raise ctypes.WinError()

else:
    safe_realpath = os.path.realpath
    safe_symlink = getattr(os, "symlink")


if WINDOWS and not hasattr(os, "link"):
    _CHL = None

    def safe_link(
        src,
        dst,
    ):
        # type: (...) -> None

        import ctypes
        from ctypes.wintypes import BOOL, LPCWSTR, LPVOID

        global _CHL
        if _CHL is None:

            chl = ctypes.windll.kernel32.CreateHardLinkW
            chl.argtypes = (

                LPCWSTR,

                LPCWSTR,

                LPVOID,
            )
            chl.restype = BOOL
            _CHL = chl

        if not _CHL(dst, src, None):
            raise ctypes.WinError()

else:
    safe_link = getattr(os, "link")
