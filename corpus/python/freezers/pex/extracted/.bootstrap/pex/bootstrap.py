# coding=utf-8


from __future__ import absolute_import, print_function

import os
import sys
import types

from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, List


class Bootstrap(object):

    _INSTANCE = None

    @classmethod
    def locate(cls):
        # type: () -> Bootstrap
        if cls._INSTANCE is None:
            bootstrap_path = __file__
            module_import_path = __name__.split(".")


            for _ in module_import_path:
                bootstrap_path = os.path.dirname(bootstrap_path)

            cls._INSTANCE = cls(sys_path_entry=bootstrap_path)
        return cls._INSTANCE

    def __init__(self, sys_path_entry):
        # type: (str) -> None
        self._sys_path_entry = sys_path_entry
        self._realpath = os.path.realpath(self._sys_path_entry)

    @property
    def path(self):
        # type: () -> str
        return self._sys_path_entry

    def demote(self, disable_vendor_importer=True):
        # type: (bool) -> List[types.ModuleType]

        import sys


        sys.path[:] = [path for path in sys.path if os.path.realpath(path) != self._realpath]
        sys.path.append(self._sys_path_entry)

        unimported_modules = []
        for name, module in reversed(sorted(sys.modules.items())):
            if "pex.cache.access" == name:


                module.save_lock_state()
            if "pex.third_party" == name and not disable_vendor_importer:
                continue
            if self.imported_from_bootstrap(module):
                unimported_modules.append(sys.modules.pop(name))
        return unimported_modules

    def imported_from_bootstrap(self, module):
        # type: (Any) -> bool

        # Python 2.7 does some funky imports in the email stdlib package that cause havoc with


        if not isinstance(module, types.ModuleType):
            return False


        path = getattr(module, "__file__", None)
        if path and os.path.realpath(path).startswith(self._realpath):
            return True


        path = getattr(module, "__path__", None)
        if path and any(
            os.path.realpath(path_item).startswith(self._realpath) for path_item in path
        ):
            return True

        return False

    def __repr__(self):
        # type: () -> str
        return "{cls}(sys_path_entry={sys_path_entry!r})".format(
            cls=type(self).__name__, sys_path_entry=self._sys_path_entry
        )


def demote(disable_vendor_importer=True):
    # type: (bool) -> None

    from . import third_party
    from .tracer import TRACER

    TRACER.log("Bootstrap complete, performing final sys.path modifications...")

    should_log = {level: TRACER.should_log(V=level) for level in range(1, 10)}

    def log(msg, V=1):
        if should_log.get(V, False):
            print("pex: {}".format(msg), file=sys.stderr)


    third_party.uninstall()

    bootstrap = Bootstrap.locate()
    log("Demoting code from %s" % bootstrap, V=2)
    for module in bootstrap.demote(disable_vendor_importer=disable_vendor_importer):
        log("un-imported {}".format(module), V=9)

    import pex

    log("Re-imported pex from {}".format(pex.__path__), V=3)

    log("PYTHONPATH contains:")
    for element in sys.path:
        log("  %c %s" % (" " if os.path.exists(element) else "*", element))
    log("  * - paths that do not exist or will be imported via zipimport")
