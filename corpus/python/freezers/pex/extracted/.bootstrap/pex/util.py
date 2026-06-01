

from __future__ import absolute_import

import contextlib
import hashlib
import importlib
import os
import shutil
import tempfile
from hashlib import sha1
from site import makepath

from pex import hashing
from pex.common import is_pyc_dir, is_pyc_file, safe_delete, safe_mkdir, safe_mkdtemp
from pex.compatibility import (
    PY2,
    exec_function,
)
from pex.orderedset import OrderedSet
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import IO, Any, Callable, Container, Iterator, Optional, Text

    from pex.hashing import Hasher


class DistributionHelper(object):


    @classmethod
    def access_zipped_assets(cls, static_module_name, static_path, dir_location=None):
        # type: (str, str, Optional[str]) -> str
        if dir_location is None:
            temp_dir = safe_mkdtemp()
        else:
            temp_dir = dir_location

        module = importlib.import_module(static_module_name)

        paths = OrderedSet(os.path.realpath(d) for d in getattr(module, "__path__", []))
        if module.__file__:

            paths.add(os.path.realpath(module.__file__))

        safe_mkdir(temp_dir)
        for path in paths:
            resource_dir = os.path.realpath(os.path.join(path, static_path))
            if os.path.isdir(resource_dir):
                for root, dirs, files in os.walk(resource_dir):
                    for d in dirs:
                        safe_mkdir(
                            os.path.join(
                                temp_dir, os.path.relpath(os.path.join(root, d), resource_dir)
                            )
                        )
                    for f in files:
                        src = os.path.join(root, f)
                        shutil.copy(src, os.path.join(temp_dir, os.path.relpath(src, resource_dir)))
        return temp_dir


class CacheHelper(object):
    @classmethod
    def hash(cls, path, digest=None, hasher=sha1):
        # type: (Text, Optional[Hasher], Callable[[], Hasher]) -> str
        if digest is None:
            digest = hasher()
        hashing.file_hash(path, digest)
        return digest.hexdigest()

    @classmethod
    def pex_code_hash(
        cls,
        directory,
        exclude_dirs=(),
        exclude_files=(),
    ):
        # type: (...) -> str
        digest = hashlib.sha1()
        hashing.dir_hash(
            directory=directory,
            digest=digest,
            dir_filter=lambda d: not is_pyc_dir(d) and d not in exclude_dirs,
            file_filter=(
                lambda f: (
                    not is_pyc_file(f)
                    and not os.path.basename(f).startswith(".")
                    and f not in exclude_files
                )
            ),
        )
        return digest.hexdigest()

    @classmethod
    def dir_hash(cls, directory, digest=None, hasher=sha1):
        # type: (str, Optional[Hasher], Callable[[], Hasher]) -> str
        if digest is None:
            digest = hasher()
        hashing.dir_hash(
            directory=directory,
            digest=digest,
            dir_filter=lambda d: not is_pyc_dir(d),
            file_filter=lambda f: not is_pyc_file(f),
        )
        return digest.hexdigest()

    @classmethod
    def zip_hash(
        cls,
        zip_path,
        relpath=None,
    ):
        # type: (...) -> str
        digest = hashlib.sha1()
        hashing.zip_hash(
            zip_path=zip_path,
            digest=digest,
            relpath=relpath,
            dir_filter=lambda d: not is_pyc_dir(d),
            file_filter=lambda f: not is_pyc_file(f),
        )
        return digest.hexdigest()


@contextlib.contextmanager
def named_temporary_file(**kwargs):
    # type: (**Any) -> Iterator[IO]
    assert "delete" not in kwargs
    kwargs["delete"] = False
    fp = tempfile.NamedTemporaryFile(**kwargs)
    try:
        with fp:
            yield fp
    finally:
        safe_delete(fp.name)
