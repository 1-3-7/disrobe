

from __future__ import absolute_import

import os
import sys

from pex.compatibility import PY2, exec_function
from pex.tracer import TRACER
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Iterator


def iter_pth_paths(filename):
    # type: (str) -> Iterator[str]
    try:
        f = open(filename, "rU" if PY2 else "r")
    except IOError:
        return

    seen = set()
    with f:
        for i, line in enumerate(f, start=1):
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            elif line.startswith(("import ", "import\t")):


                original_sys_path = sys.path[:]
                try:


                    sys.path = []
                    exec_function(line, globals_map={})
                    for path in sys.path:
                        norm_path = os.path.normcase(path)
                        if norm_path not in seen:
                            yield path
                            seen.add(norm_path)
                except Exception as e:


                    TRACER.log(
                        "Error executing line {linenumber} of {pth_file} with content:\n"
                        "{content}\n"
                        "Error was:\n"
                        "{error}".format(linenumber=i, pth_file=filename, content=line, error=e),
                        V=9,
                    )


                    return
                finally:
                    sys.path = original_sys_path
            else:
                extras_dir = os.path.abspath(os.path.join(os.path.dirname(filename), line))
                norm_extras_dir = os.path.normcase(extras_dir)
                if norm_extras_dir not in seen and os.path.exists(extras_dir):
                    yield extras_dir
                    seen.add(norm_extras_dir)
