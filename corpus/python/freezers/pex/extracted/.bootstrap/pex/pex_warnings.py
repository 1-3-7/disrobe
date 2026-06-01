# coding=utf-8


from __future__ import absolute_import

import warnings

from pex.typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from typing import Optional

    from pex.pex_info import PexInfo
    from pex.variables import Variables


class PEXWarning(Warning):


def configure_warnings(
    env,
    pex_info=None,
):
    # type: (...) -> None
    if env.PEX_VERBOSE > 0:
        emit_warnings = True
    elif env.PEX_EMIT_WARNINGS is not None:
        emit_warnings = env.PEX_EMIT_WARNINGS
    elif pex_info:
        emit_warnings = pex_info.emit_warnings
    else:
        emit_warnings = True

    action = "default" if emit_warnings else "ignore"
    warnings.filterwarnings(action, category=PEXWarning)


def warn(message):
    # type: (str) -> None
    warnings.warn(message, category=PEXWarning, stacklevel=2)
