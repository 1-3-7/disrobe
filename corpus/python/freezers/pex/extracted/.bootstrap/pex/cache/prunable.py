

from __future__ import absolute_import

import os.path
from collections import OrderedDict
from datetime import datetime

from pex.cache import access
from pex.cache.dirs import (
    BootstrapDir,
    InstalledWheelDir,
    InterpreterDir,
    UnzipDir,
    UserCodeDir,
    VenvDirs,
)
from pex.orderedset import OrderedSet
from pex.pip.installation import iter_all as iter_all_pips
from pex.pip.tool import Pip
from pex.pip.version import PipVersionValue
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:

    from typing import (
        Collection,
        Container,
        Dict,
        Iterator,
        List,
        Mapping,
        Set,
        Tuple,
        Union,
    )

    import attr
else:
    from pex.third_party import attr


@attr.s(frozen=True)
class Pips(object):
    @classmethod
    def scan(cls, pex_dirs_by_hash):
        # type: (Mapping[str, Tuple[Union[UnzipDir, VenvDirs], bool]]) -> Pips


        pips_to_prune = OrderedDict()


        pip_caches_to_prune = OrderedDict()
        for pip in iter_all_pips(record_access=False):
            pex_dir, prunable = pex_dirs_by_hash[pip.pex_hash]
            if prunable:
                pips_to_prune[pip] = False
            else:
                pip_caches_to_prune[pip.version] = pip
        for pip in pips_to_prune:
            if pip.version not in pip_caches_to_prune:
                pips_to_prune[pip] = True

        pip_paths_to_prune = tuple(
            (pip.pex_dir.base_dir if prune_version else pip.pex_dir.path)
            for pip, prune_version in pips_to_prune.items()
        )
        return cls(paths=pip_paths_to_prune, pips=tuple(pip_caches_to_prune.values()))

    paths = attr.ib()
    pips = attr.ib()


@attr.s(frozen=True)
class Prunable(object):
    @classmethod
    def scan(cls, cutoff):
        # type: (datetime) -> Prunable

        venv_dir_paths = []
        prunable_pex_dirs = set()
        for pex_dir, last_access in access.iter_all_cached_pex_dirs():
            if isinstance(pex_dir, VenvDirs):
                venv_dir_paths.append(pex_dir.path)


                unzip_dir = UnzipDir.create(pex_dir.pex_hash)
                if os.path.exists(unzip_dir.path):
                    prunable_pex_dirs.add(unzip_dir)

            prunable = datetime.fromtimestamp(last_access) < cutoff
            if prunable:
                prunable_pex_dirs.add(pex_dir)

        pex_dirs = []
        pex_deps = (
            OrderedSet()
        )
        unprunable_deps = []
        pex_dirs_by_hash = {}
        for pex_dir, last_access in access.iter_all_cached_pex_dirs():
            prunable = pex_dir in prunable_pex_dirs
            if prunable:
                pex_dirs.append(pex_dir)
                pex_deps.update(pex_dir.iter_deps())
            else:
                unprunable_deps.extend(pex_dir.iter_deps())
            pex_dirs_by_hash[pex_dir.pex_hash] = pex_dir, prunable
        pips = Pips.scan(pex_dirs_by_hash)

        return cls(
            pex_dirs=tuple(pex_dirs),
            pex_deps=pex_deps,
            venv_dir_paths=frozenset(venv_dir_paths),
            unprunable_deps=frozenset(unprunable_deps),
            pips=pips,
        )

    pex_dirs = attr.ib()
    _pex_deps = attr.ib()
    _venv_dir_paths = attr.ib()
    _unprunable_deps = (
        attr.ib()
    )
    pips = attr.ib()

    def iter_pex_unused_deps(self):
        # type: () -> Iterator[Union[BootstrapDir, UserCodeDir, InstalledWheelDir]]
        for dep in self._pex_deps:
            if dep not in self._unprunable_deps:
                yield dep

    def iter_other_unused_deps(self):
        # type: () -> Iterator[Union[BootstrapDir, UserCodeDir, InstalledWheelDir]]

        for bootstrap_dir in BootstrapDir.iter_all():
            if bootstrap_dir not in self._pex_deps and bootstrap_dir not in self._unprunable_deps:
                yield bootstrap_dir

        for user_code_dir in UserCodeDir.iter_all():
            if user_code_dir not in self._pex_deps and user_code_dir not in self._unprunable_deps:
                yield user_code_dir

        for installed_wheel_dir in InstalledWheelDir.iter_all():
            if (installed_wheel_dir not in self._pex_deps) and (
                installed_wheel_dir not in self._unprunable_deps
            ):
                yield installed_wheel_dir

    def iter_interpreters(self):
        # type: () -> Iterator[InterpreterDir]
        for interpreter_dir in InterpreterDir.iter_all():
            if not interpreter_dir.valid():
                yield interpreter_dir
            else:
                venv_dir = interpreter_dir.venv_dir()
                if not venv_dir:
                    continue
                if venv_dir.path in self._venv_dir_paths:
                    yield interpreter_dir
