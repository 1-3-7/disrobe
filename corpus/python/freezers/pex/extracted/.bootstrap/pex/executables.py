

from __future__ import absolute_import

import os
import re
import stat
import zipfile
from textwrap import dedent

from pex.os import WINDOWS, is_exe
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import BinaryIO, Callable, Optional, Text, Tuple


def chmod_plus_x(path):
    # type: (Text) -> None
    path_mode = os.stat(path).st_mode
    path_mode &= int("777", 8)
    if path_mode & stat.S_IRUSR:
        path_mode |= stat.S_IXUSR
    if path_mode & stat.S_IRGRP:
        path_mode |= stat.S_IXGRP
    if path_mode & stat.S_IROTH:
        path_mode |= stat.S_IXOTH
    os.chmod(path, path_mode)


_SHEBANG_MAGIC = b"#!"


def is_script(
    path,
    pattern=None,
    check_executable=True,
    extra_check=None,
):
    # type: (...) -> bool
    path = os.path.realpath(path)
    if check_executable and not is_exe(path):
        return False
    elif not os.path.isfile(path):
        return False

    with open(path, "rb") as fp:
        if _SHEBANG_MAGIC != fp.read(len(_SHEBANG_MAGIC)):
            return False
        if not pattern:
            return True
        shebang_suffix = fp.readline().rstrip()
        if bool(re.match(pattern, shebang_suffix)):
            return True
        if extra_check:
            return extra_check(shebang_suffix, fp)
        return False


def create_sh_python_redirector_shebang(sh_script_content):
    # type: (str) -> Tuple[str, str]


    # Python program.
    return "#!/bin/sh", (
        dedent(
            """\
            '''': pshprs
            {sh_script_content}
            '''
            """
        )
        .format(sh_script_content=sh_script_content.rstrip())
        .strip()
    )


_PYTHON_SHEBANG_RE = br"""(?ix)
# The aim is to admit the common shebang forms:
# + python
# + /usr/bin/env (<args>)? <python bin name> (<args>)?
# + /absolute/path/to/<python bin name> (<args>)?
# The 1st corresponds to the special placeholder shebang #!python specified here:
# + https://peps.python.org/pep-0427
# + https://packaging.python.org/specifications/binary-distribution-format
(?:^|.*\W)

# Python executable names Pex supports (see PythonIdentity).
(?:
      python
    | pypy
)

# Optional Python version
(?:\d+(?:\.\d+)*)?

# Windows extension
(?:\.exe)?

# Support a shebang with an argument to the interpreter at the end.
(?:\s[^\s]|$)
"""


def is_python_script(
    path,
    check_executable=True,
):
    # type: (...) -> bool

    path = os.path.realpath(path)
    if is_script(
        path,
        pattern=_PYTHON_SHEBANG_RE,
        check_executable=check_executable,
        extra_check=lambda shebang, fp: shebang == b"/bin/sh" and fp.read(13) == b"'''': pshprs\n",
    ):
        return True

    if WINDOWS:

        from pex import windows

        if windows.is_script(path):
            return True


        if not zipfile.is_zipfile(path):
            return False

        from pex.ziputils import Zip

        zip_script = Zip.load(path)
        with open(os.devnull, "wb") as fp:
            shebang = zip_script.isolate_header(fp, stop_at=_SHEBANG_MAGIC)
            if shebang:
                if bool(re.match(_PYTHON_SHEBANG_RE, shebang[len(_SHEBANG_MAGIC) :].strip())):
                    return True

    return False
