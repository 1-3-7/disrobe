

from __future__ import absolute_import

import os
import sys

from pex import pex_root
from pex.enum import Enum
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, List, NoReturn, Text, Tuple, Union


class _CurrentOs(object):
    def __get__(self, obj, objtype=None):
        # type: (...) -> Os.Value
        if not hasattr(self, "_current"):

            if sys.platform.startswith("linux"):
                self._current = Os.LINUX
            elif sys.platform == "darwin":
                self._current = Os.MACOS
            elif sys.platform == "win32":
                self._current = Os.WINDOWS
            if not hasattr(self, "_current"):
                raise ValueError(
                    "The current operating system is not supported!: {system}".format(
                        system=sys.platform
                    )
                )
        return self._current


class Os(Enum["Os.Value"]):
    class Value(Enum.Value):
        def path_join(self, *components):
            # type: (*str) -> str
            return ("\\" if self is Os.WINDOWS else "/").join(components)

    LINUX = Value("linux")
    MACOS = Value("macos")
    WINDOWS = Value("windows")
    CURRENT = _CurrentOs()


Os.seal()


LINUX = Os.CURRENT is Os.LINUX
MAC = Os.CURRENT is Os.MACOS
WINDOWS = Os.CURRENT is Os.WINDOWS


HOME_ENV_VAR = "USERPROFILE" if WINDOWS else "HOME"


if WINDOWS:

    def safe_execv(argv):
        # type: (Union[List[str], Tuple[str, ...]]) -> NoReturn

        import subprocess
        import sys

        from pex import atexit

        atexit.perform_exit()
        with pex_root.preserve_fallback():
            sys.exit(subprocess.call(args=argv))

else:

    def safe_execv(argv):
        # type: (Union[List[str], Tuple[str, ...]]) -> NoReturn

        from pex import atexit

        atexit.perform_exit()
        with pex_root.preserve_fallback() as env:
            os.execve(argv[0], argv, env)


if WINDOWS:
    _GBT = None

    def is_exe(path):
        # type: (Text) -> bool

        if not os.path.isfile(path):
            return False

        from pex.sysconfig import EXE_EXTENSIONS

        _, ext = os.path.splitext(path)
        if ext.lower() in EXE_EXTENSIONS:
            return True

        import ctypes
        from ctypes.wintypes import BOOL, DWORD, LPCWSTR, LPDWORD

        global _GBT
        if _GBT is None:

            gbt = ctypes.windll.kernel32.GetBinaryTypeW
            gbt.argtypes = (

                LPCWSTR,

                LPDWORD,
            )
            gbt.restype = BOOL
            _GBT = gbt


        _binary_type = DWORD(0)
        return bool(_GBT(path, ctypes.byref(_binary_type)))

else:

    def is_exe(path):
        # type: (Text) -> bool
        return os.path.isfile(path) and os.access(path, os.R_OK | os.X_OK)


if WINDOWS:

    def is_alive(pid):
        # type: (int) -> bool


        import csv
        import subprocess

        args = ["tasklist", "/FI", "PID eq {pid}".format(pid=pid), "/FO", "CSV"]
        process = subprocess.Popen(args=args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(
                "Failed to query status of process with pid {pid}.\n"
                "Execution of `{args}` returned exit code {returncode}.\n"
                "{stderr}".format(
                    pid=pid,
                    args=" ".join(args),
                    returncode=process.returncode,
                    stderr=stderr.decode("utf-8"),
                )
            )

        output = stdout.decode("utf-8")
        if "No tasks are running" in output:
            return False

        lines = output.splitlines()
        if len(lines) != 2:
            return False

        csv_reader = csv.DictReader(lines)
        for row in csv_reader:
            pid_value = row.get("PID", -1)
            if pid_value == -1:
                return False
            try:
                return pid == int(pid_value)
            except (ValueError, TypeError):
                return False
        return False


    _PROCESS_TERMINATE = 0x1

    _OP = None
    _TP = None

    def kill(pid):
        # type: (int) -> None

        import ctypes
        from ctypes.wintypes import BOOL, DWORD, HANDLE, UINT

        global _OP
        if _OP is None:

            op = ctypes.windll.kernel32.OpenProcess
            op.argtypes = (
                DWORD,
                BOOL,
                DWORD,
            )
            op.restype = HANDLE
            _OP = op

        phandle = _OP(_PROCESS_TERMINATE, False, pid)
        if not phandle:


            raise ctypes.WinError()

        global _TP
        if _TP is None:

            tp = ctypes.windll.kernel32.OpenProcess
            tp.argtypes = (
                HANDLE,
                UINT,
            )
            tp.restype = BOOL
            _TP = tp

        if not _TP(phandle, 1):


            raise ctypes.WinError()

else:

    def is_alive(pid):
        # type: (int) -> bool

        import errno

        try:
            os.kill(pid, 0)
            return True
        except OSError as e:
            if e.errno == errno.ESRCH:
                return False
            raise

    def kill(pid):
        # type: (int) -> None

        import errno
        import signal

        try:
            os.kill(pid, signal.SIGKILL)
        except OSError as e:
            if e.errno != errno.ESRCH:
                raise
