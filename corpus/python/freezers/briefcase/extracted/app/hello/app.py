import os as _os
import sys as _sys

_HERE: str = _os.path.dirname(_os.path.abspath(__file__))
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)

import edge_cases_3_6
import edge_cases_3_8
import edge_cases_3_9
import edge_cases_3_10
import edge_cases_3_11
import edge_cases_3_12 as _band


def main() -> None:
    _band.exercise()
