

from __future__ import absolute_import

import base64
import csv
import hashlib
import io
import os
from fileinput import FileInput

from pex import hashing
from pex.common import safe_open
from pex.compatibility import PY2
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import IO, Callable, Iterable, Iterator, Optional, Protocol, Text, Union

    import attr

    from pex.hashing import Hasher

    class CSVWriter(Protocol):
        def writerow(self, row):
            # type: (Iterable[Union[str, int]]) -> None
            pass

else:
    from pex.third_party import attr


@attr.s(frozen=True)
class Digest(object):
    algorithm = attr.ib()
    encoded_hash = attr.ib()

    def new_hasher(self):
        # type: () -> Hasher
        return hashlib.new(self.algorithm)


@attr.s(frozen=True)
class Hash(object):
    @classmethod
    def create(cls, hasher):
        # type: (Hasher) -> Hash


        fingerprint = base64.urlsafe_b64encode(hasher.digest()).rstrip(b"=")


        alg = hasher.name.lower()

        return cls(value="{alg}={hash}".format(alg=alg, hash=fingerprint.decode("ascii")))

    value = attr.ib()

    def __str__(self):
        # type: () -> str
        return self.value


@attr.s(frozen=True)
class InstalledFile(object):

    path = attr.ib()
    hash = attr.ib(default=None)
    size = attr.ib(default=None)


@attr.s(frozen=True)
class InstalledDirectory(object):


    dir_info = attr.ib()


def create_installed_file(
    path,
    dest_dir,
):
    # type: (...) -> InstalledFile
    hasher = hashlib.sha256()
    hashing.file_hash(path, digest=hasher)
    return InstalledFile(
        path=os.path.relpath(path, dest_dir),
        hash=Hash.create(hasher),
        size=os.stat(path).st_size,
    )


class RecordError(Exception):
    pass


class RecordNotFoundError(RecordError):


class UnrecognizedInstallationSchemeError(RecordError):


@attr.s(frozen=True)
class DistInfoFile(object):
    path = attr.ib()
    content = attr.ib()


@attr.s(frozen=True)
class Record(object):

    @classmethod
    def write_fp(
        cls,
        fp,
        installed_files,
        eol="\n",
    ):
        # type: (...) -> None
        csv_writer = csv.writer(fp, delimiter=",", quotechar='"', lineterminator=eol)
        for installed_file in installed_files:
            if isinstance(installed_file, InstalledDirectory):
                csv_writer.writerow(attr.astuple(installed_file.dir_info, recurse=False))
            else:
                csv_writer.writerow(attr.astuple(installed_file, recurse=False))

    @classmethod
    def write_bytes(
        cls,
        installed_files,
        eol="\n",
    ):
        # type: (...) -> bytes
        if PY2:
            record_fp = io.BytesIO()
            cls.write_fp(fp=record_fp, installed_files=installed_files, eol=eol)
            return record_fp.getvalue()
        else:
            record_fp = io.StringIO()
            cls.write_fp(fp=record_fp, installed_files=installed_files, eol=eol)
            return record_fp.getvalue().encode("utf-8")

    @classmethod
    def write(
        cls,
        dst,
        installed_files,
        eol="\n",
    ):
        # type: (...) -> None


        with safe_open(dst, "wb" if PY2 else "w") as fp:
            cls.write_fp(fp, installed_files, eol=eol)

    @classmethod
    def read(
        cls,
        lines,
        exclude=None,
    ):
        # type: (...) -> Iterator[Union[InstalledFile, InstalledDirectory]]


        for line, (path, fingerprint, file_size) in enumerate(
            csv.reader(lines, delimiter=",", quotechar='"'), start=1
        ):
            resolved_path = path
            if exclude and exclude(resolved_path):
                continue
            file_hash = Hash(fingerprint) if fingerprint else None
            size = int(file_size) if file_size else None
            installed_file = InstalledFile(path=path, hash=file_hash, size=size)
            if path.endswith("/"):
                yield InstalledDirectory(dir_info=installed_file)
            else:
                yield installed_file

    project_name = attr.ib()
    version = attr.ib()
    prefix_dir = attr.ib()
    rel_base_dir = attr.ib()
    relative_path = attr.ib()
