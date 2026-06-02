

from __future__ import absolute_import

import os
import sys

from pex.compatibility import safe_commonpath
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional


def prog_path(prog=None):
    # type: (Optional[str]) -> str

    exe_path = os.path.abspath(prog or sys.argv[0])
    cwd = os.path.abspath(os.getcwd())
    if safe_commonpath((exe_path, cwd)) == cwd:
        exe_path = os.path.relpath(exe_path, cwd)

        if not os.path.dirname(exe_path) and os.curdir not in os.environ.get("PATH", "").split(
            os.pathsep
        ):
            exe_path = os.path.join(os.curdir, exe_path)
    else:
        exe_dir = os.path.dirname(exe_path)
        for path_entry in os.environ.get("PATH", "").split(os.pathsep):
            abs_path_entry = os.path.abspath(path_entry)
            if exe_dir == abs_path_entry:
                return os.path.basename(exe_path)
    return exe_path
