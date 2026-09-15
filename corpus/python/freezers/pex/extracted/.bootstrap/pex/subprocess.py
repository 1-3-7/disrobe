

from __future__ import absolute_import

import os
import subprocess
import sys

from pex.os import WINDOWS
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Dict, List


def subprocess_daemon_kwargs():
    # type: () -> Dict[str, Any]

    if WINDOWS:
        return {
            "creationflags": (


                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
            )
        }
    elif sys.version_info[:2] >= (3, 2):
        return {"start_new_session": True}
    else:
        return {

            "preexec_fn": os.setsid
        }


def launch_python_daemon(
    args,
    **kwargs
):
    # type: (...) -> subprocess.Popen
    if WINDOWS:
        python, _ = os.path.splitext(os.path.basename(args[0]))
        if python == "python":
            pythonw = os.path.join(os.path.dirname(args[0]), "pythonw.exe")
            if os.path.exists(pythonw):
                args[0] = pythonw
    kwargs.update(subprocess_daemon_kwargs())
    return subprocess.Popen(args=args, **kwargs)
