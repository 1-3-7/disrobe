

from __future__ import absolute_import, print_function

import contextlib
import errno
import io
import itertools
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
import time
import zipfile
from collections import defaultdict, namedtuple
from contextlib import closing, contextmanager
from datetime import datetime
from uuid import uuid4
from zipfile import ZipFile, ZipInfo

from pex import atexit
from pex.enum import Enum
from pex.executables import chmod_plus_x
from pex.fs import safe_link, safe_rename, safe_symlink
from pex.os import is_exe
from pex.typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        Container,
        DefaultDict,
        Dict,
        Iterable,
        Iterator,
        List,
        NoReturn,
        Optional,
        Protocol,
        Set,
        Sized,
        Text,
        Tuple,
        TypeVar,
        Union,
    )

    _Text = TypeVar("_Text", bytes, str, Text)

    class Digest(Protocol):
        def update(self, data):
            # type: (bytes) -> None
            pass


DETERMINISTIC_DATETIME = datetime(
    year=1980, month=1, day=1, hour=0, minute=0, second=0, tzinfo=None
)
_UNIX_EPOCH = datetime(year=1970, month=1, day=1, hour=0, minute=0, second=0, tzinfo=None)
DETERMINISTIC_DATETIME_TIMESTAMP = int((DETERMINISTIC_DATETIME - _UNIX_EPOCH).total_seconds())


REPRODUCIBLE_BUILDS_ENV = dict(
    PYTHONHASHSEED="0", SOURCE_DATE_EPOCH=str(DETERMINISTIC_DATETIME_TIMESTAMP)
)


def is_pyc_dir(dir_path):
    # type: (Text) -> bool
    return os.path.basename(dir_path) == "__pycache__"


def is_pyc_file(file_path):
    # type: (Text) -> bool


    return file_path.endswith((".pyc", ".pyo")) or is_pyc_temporary_file(file_path)


def is_pyc_temporary_file(file_path):
    # type: (Text) -> bool


    return re.search(r"\.pyc\.[0-9]+$", file_path) is not None


def die(msg, exit_code=1):
    # type: (str, int) -> NoReturn
    print(msg, file=sys.stderr)
    sys.exit(exit_code)


def pluralize(
    subject,
    noun,
):
    # type: (...) -> str
    if noun == "":
        return ""
    count = subject if isinstance(subject, int) else len(subject)
    if count == 1:
        return noun
    if len(noun) == 1:
        raise ValueError("There is no single letter noun; given: {noun}".format(noun=noun))
    if noun[-1] == "y" and noun[-2] not in ("a", "e", "i", "o", "u"):
        return noun[:-1] + "ies"
    elif noun[-1] in ("s", "x", "z") or noun[-2:] in ("sh", "ch"):
        return noun + "es"
    else:
        return noun + "s"


def _process_diagnostic():
    # type: () -> str
    return (
        "login: {user} uid: {uid} gid: {gid}\n"
        "effective: uid: {euid} gid: {egid}\n"
        "groups: {groups}"
    ).format(
        user=os.getlogin(),
        uid=os.getuid(),
        euid=os.geteuid(),
        gid=os.getgid(),
        egid=os.getegid(),
        groups=os.getgroups(),
    )


def _path_diagnostic(path):
    # type: (Text) -> Text

    path_type = "<unknown path type>"
    if os.path.isdir(path):
        path_type = "dir"
    elif os.path.isfile(path):
        path_type = "file"

    try:
        os_stat = os.stat(path)

        mode = oct(os_stat.st_mode)
        if hasattr(stat, "filemode"):
            mode = "{mode} ({human_mode})".format(
                mode=mode, human_mode=stat.filemode(os_stat.st_mode)
            )

        return (
            "{path_type} ok? {path!r}:\n"
            "    mode: {mode} owner: {uid} group: {gid}\n"
            "    {stat}".format(
                path_type=path_type,
                path=path,
                mode=mode,
                uid=os_stat.st_uid,
                gid=os_stat.st_gid,
                stat=os_stat,
            )
        )
    except OSError as e:
        return "{path_type} err {path!r}:\n    {err}".format(path_type=path_type, path=path, err=e)


def safe_copy(source, dest, overwrite=False):
    # type: (Text, Text, bool) -> None
    def do_copy():
        # type: () -> None
        temp_dest = dest + uuid4().hex
        shutil.copy(source, temp_dest)
        safe_rename(temp_dest, dest)


    if hasattr(os, "link"):
        try:
            safe_link(source, dest)
        except OSError as e:
            if e.errno == errno.EEXIST:

                if overwrite:
                    do_copy()
            elif e.errno in (errno.EPERM, errno.EXDEV):


                do_copy()
            else:
                raise OSError(
                    e.errno,
                    "Failed to link {src} -> {dst}: {strerror}\n"
                    "{process_diagnostic}\n"
                    "{src_diagnostic}\n"
                    "{dst_diagnostic}".format(
                        src=source,
                        dst=dest,
                        strerror=e.strerror,
                        process_diagnostic=_process_diagnostic(),
                        src_diagnostic=_path_diagnostic(source),
                        dst_diagnostic=_path_diagnostic(os.path.dirname(dest)),
                    ),
                )
    elif os.path.exists(dest):
        if overwrite:
            do_copy()
    else:
        do_copy()


class MktempTeardownRegistry(object):
    def __init__(self):
        # type: () -> None
        self._registry = defaultdict(set)
        self._lock = threading.RLock()
        self._getpid = os.getpid
        self._rmtree = shutil.rmtree
        atexit.register(self.teardown)

    def __del__(self):
        # type: () -> None
        self.teardown()

    def register(self, path):
        # type: (str) -> str
        with self._lock:
            self._registry[self._getpid()].add(path)
        return path

    def teardown(self):
        # type: () -> None
        for td in self._registry.pop(self._getpid(), []):
            self._rmtree(td, ignore_errors=True)


_MKDTEMP_SINGLETON = MktempTeardownRegistry()


setattr(zipfile, "ZIP64_LIMIT", (1 << 32) - 1)


class _ZipFileTypeValue(Enum.Value):
    def __init__(
        self,
        value,
        deterministic_mode,
    ):
        # type: (...) -> None
        super(_ZipFileTypeValue, self).__init__(value)
        self.deterministic_mode = deterministic_mode

    @property
    def deterministic_external_attr(self):
        # type: () -> int
        return self.deterministic_mode << 16


class ZipFileType(Enum["ZipFileType.Value"]):
    @classmethod
    def from_zip_info(cls, zip_info):
        # type: (ZipInfo) -> ZipFileType.Value

        if zip_info.filename.endswith("/"):
            return ZipFileType.DIRECTORY

        mode = zip_info.external_attr >> 16
        if stat.S_IXUSR & mode:
            return ZipFileType.EXECUTABLE

        return ZipFileType.FILE

    @classmethod
    def from_path(cls, path):
        # type: (Text) -> ZipFileType.Value
        if os.path.isdir(path):
            return ZipFileType.DIRECTORY
        elif is_exe(path):
            return ZipFileType.EXECUTABLE
        return ZipFileType.FILE

    class Value(_ZipFileTypeValue):
        pass

    DIRECTORY = Value("directory", stat.S_IFDIR | 0o755)
    EXECUTABLE = Value("executable", stat.S_IFREG | 0o755)
    FILE = Value("file", stat.S_IFREG | 0o644)


ZipFileType.seal()


class ZipFileEx(ZipFile):

    class ZipEntry(namedtuple("ZipEntry", ["info", "data"])):
        pass

    @classmethod
    def zip_info_from_file(
        cls,
        filename,
        arcname=None,
        date_time=None,
        file_mode=None,
        compress=True,
    ):
        # type: (...) -> Tuple[ZipInfo, bool]
        st = os.stat(filename)
        is_dir = stat.S_ISDIR(st.st_mode)
        if arcname is None:
            arcname = filename
        arcname = os.path.normpath(os.path.splitdrive(arcname)[1])
        while arcname[0] in (os.sep, os.altsep):
            arcname = arcname[1:]
        if is_dir:
            arcname += "/"
        if date_time is None:
            date_time = time.localtime(st.st_mtime)
        zip_info = zipfile.ZipInfo(filename=arcname, date_time=date_time[:6])


        zip_info.external_attr = ((file_mode or st.st_mode) & 0xFFFF) << 16

        if is_dir:
            zip_info.file_size = 0
            zip_info.external_attr |= 0x10
            zip_info.compress_type = zipfile.ZIP_STORED
        else:
            zip_info.file_size = st.st_size
            zip_info.compress_type = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
        return zip_info, is_dir

    def write_deterministic(
        self,
        filename,
        arcname=None,
        digest=None,
        deterministic=True,
        compress=True,
    ):
        if deterministic:
            return self.write_ex(
                filename,
                arcname=arcname,
                date_time=DETERMINISTIC_DATETIME.timetuple(),
                file_mode=ZipFileType.from_path(filename).deterministic_mode,
                digest=digest,
                compress=compress,
            )
        return self.write_ex(filename, arcname=arcname, digest=digest, compress=compress)

    def write_ex(
        self,
        filename,
        arcname=None,
        date_time=None,
        file_mode=None,
        digest=None,
        compress=True,
    ):
        # type: (...) -> int
        zip_info, is_dir = self.zip_info_from_file(
            filename, arcname=arcname, date_time=date_time, file_mode=file_mode, compress=compress
        )
        size = 0
        if is_dir:
            self.writestr(zip_info, b"")
        elif sys.version_info[:2] >= (3, 6):
            with closing(self.open(zip_info, "w")) as dst_fp, open(filename, "rb") as src_fp:
                for chunk in iter(lambda: src_fp.read(io.DEFAULT_BUFFER_SIZE), b""):
                    size += len(chunk)
                    if digest:
                        digest.update(chunk)
                    dst_fp.write(chunk)
        else:
            with open(filename, "rb") as fp:
                data = fp.read()
            size = len(data)
            if digest:
                digest.update(data)
            self.writestr(zip_info, data)
        return size

    def _extract_member(
        self,
        member,
        targetpath,
        pwd,
    ):
        # type: (...) -> str


        result = super(ZipFileEx, self)._extract_member(
            member, targetpath, pwd
        )
        info = member if isinstance(member, zipfile.ZipInfo) else self.getinfo(member)
        self._chmod(info, result)
        return cast(str, result)

    @staticmethod
    def _chmod(
        info,
        path,
    ):
        # type: (...) -> None


        if info.external_attr > 0xFFFF:
            attr = info.external_attr >> 16

            if stat.S_ISREG(attr) and attr & 0o111:
                chmod_plus_x(path)

    # Python 3 also takes PathLike[str] for the path arg, but we only ever pass str since we support
    # Python 2.7 and don't use pathlib as a result.
    def extractall(
        self,
        path=None,
        members=None,
        pwd=None,
    ):
        # type: (...) -> None
        if sys.version_info[0] != 2:
            return super(ZipFileEx, self).extractall(path=path, members=members, pwd=pwd)


        efs_bit = 1 << 11

        target_path = path or os.getcwd()
        for member in members or self.infolist():
            info = member if isinstance(member, ZipInfo) else self.getinfo(member)
            encoding = "utf-8" if info.flag_bits & efs_bit else "cp437"
            member_path = info.filename.encode(encoding)
            target = target_path.encode(encoding)

            rel_dir = os.path.dirname(member_path)
            abs_dir = os.path.join(target, rel_dir)
            abs_path = os.path.join(abs_dir, os.path.basename(member_path))
            if member_path.endswith(b"/"):
                safe_mkdir(abs_path)
            else:
                safe_mkdir(abs_dir)
                with open(abs_path, "wb") as tfp, self.open(info) as zf_entry:
                    shutil.copyfileobj(zf_entry, tfp)
            self._chmod(info, abs_path)


@contextlib.contextmanager
def open_zip(
    path,
    *args,
    **kwargs
):
    # type: (...) -> Iterator[ZipFileEx]


    kwargs.setdefault("allowZip64", True)

    with contextlib.closing(ZipFileEx(path, *args, **kwargs)) as zip_fp:
        yield zip_fp


def deterministic_walk(*args, **kwargs):
    # type: (*Any, **Any) -> Iterator[Tuple[str, List[str], List[str]]]

    assert kwargs.get("topdown", True), "Determinism cannot be guaranteed when ``topdown`` is false"
    for root, dirs, files in os.walk(*args, **kwargs):
        dirs.sort()
        files.sort()
        yield root, dirs, files

        dirs.sort()


@contextlib.contextmanager
def temporary_dir(cleanup=True):
    # type: (bool) -> Iterator[str]
    td = tempfile.mkdtemp()
    try:
        yield td
    finally:
        if cleanup:
            safe_rmtree(td)


def safe_mkdtemp(**kw):
    # type: (**Any) -> str

    return _MKDTEMP_SINGLETON.register(tempfile.mkdtemp(**kw))


def register_rmtree(directory):
    # type: (str) -> str
    return _MKDTEMP_SINGLETON.register(directory)


def safe_mkdir(directory, clean=False):
    # type: (_Text, bool) -> _Text
    if clean:
        safe_rmtree(directory)
    try:
        os.makedirs(directory)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    return directory


def safe_open(filename, *args, **kwargs):
    parent_dir = os.path.dirname(filename)
    if parent_dir:
        safe_mkdir(parent_dir)
    return open(filename, *args, **kwargs)


def safe_delete(filename):
    # type: (Text) -> None
    try:
        os.unlink(filename)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


def safe_rmtree(directory):
    # type: (_Text) -> None
    if os.path.exists(directory):
        shutil.rmtree(directory, True)


def safe_sleep(seconds):
    # type: (float) -> None
    if sys.version_info[0:2] >= (3, 5):
        time.sleep(seconds)
    else:
        start_time = current_time = time.time()
        while current_time - start_time < seconds:
            remaining_time = seconds - (current_time - start_time)
            time.sleep(remaining_time)
            current_time = time.time()


def touch(
    file,
    times=None,
):
    # type: (...) -> _Text
    with safe_open(file, "a"):
        os.utime(file, (times, times) if isinstance(times, (int, float)) else times)
    return file


class Chroot(object):

    class Error(Exception):
        pass

    class ChrootTaggingException(Error):
        pass

    def __init__(self, chroot_base):
        # type: (str) -> None
        try:
            safe_mkdir(chroot_base)
        except OSError as e:
            raise self.Error("Unable to create chroot in %s: %s" % (chroot_base, e))
        self.chroot = chroot_base
        self.filesets = defaultdict(set)
        self._compress_by_file = {}
        self._file_index = {}

    def path(self):
        # type: () -> str
        return self.chroot

    def _normalize(self, dst):
        # type: (str) -> str
        dst = os.path.normpath(dst)
        if dst.startswith(os.sep) or dst.startswith(".."):
            raise self.Error("Destination path is not a relative path!")
        return dst

    def _check_tag(
        self,
        fn,
        label,
        compress=True,
    ):
        # type: (...) -> None
        existing_label = self._file_index.setdefault(fn, label)
        if label != existing_label:
            raise self.ChrootTaggingException(
                "Trying to add {file} to fileset({new_tag}) but already in "
                "fileset({orig_tag})!".format(file=fn, new_tag=label, orig_tag=existing_label)
            )
        existing_compress = self._compress_by_file.setdefault(fn, compress)
        if compress != existing_compress:
            raise self.ChrootTaggingException(
                "Trying to add {file} to fileset({tag}) with compress {new_compress} but already "
                "added with compress {orig_compress}!".format(
                    file=fn, tag=label, new_compress=compress, orig_compress=existing_compress
                )
            )

    def _tag(
        self,
        fn,
        label,
        compress,
    ):
        # type: (...) -> None
        self._check_tag(fn, label, compress)
        self.filesets[label].add(fn)

    def _ensure_parent(self, path):
        # type: (str) -> None
        safe_mkdir(os.path.dirname(os.path.join(self.chroot, path)))

    def copy(
        self,
        src,
        dst,
        label=None,
        compress=True,
    ):
        # type: (...) -> None
        dst = self._normalize(dst)
        self._tag(dst, label, compress)
        self._ensure_parent(dst)
        shutil.copy(src, os.path.join(self.chroot, dst))

    def link(
        self,
        src,
        dst,
        label=None,
        compress=True,
    ):
        # type: (...) -> None
        dst = self._normalize(dst)
        self._tag(dst, label, compress)
        self._ensure_parent(dst)
        abs_src = src
        abs_dst = os.path.join(self.chroot, dst)
        safe_copy(abs_src, abs_dst, overwrite=False)


    def symlink(
        self,
        src,
        dst,
        label=None,
        compress=True,
    ):
        # type: (...) -> None
        dst = self._normalize(dst)
        self._tag(dst, label, compress)
        self._ensure_parent(dst)
        abs_src = os.path.realpath(src)
        abs_dst = os.path.realpath(os.path.join(self.chroot, dst))
        safe_relative_symlink(abs_src, abs_dst)

    def write(
        self,
        data,
        dst,
        label=None,
        mode="wb",
        executable=False,
        compress=True,
    ):
        # type: (...) -> None
        dst = self._normalize(dst)
        self._tag(dst, label, compress)
        self._ensure_parent(dst)
        with open(os.path.join(self.chroot, dst), mode) as wp:
            wp.write(data)
        if executable:
            chmod_plus_x(wp.name)

    def touch(
        self,
        dst,
        label=None,
    ):
        # type: (...) -> None
        dst = self._normalize(dst)
        self._tag(dst, label, compress=False)
        touch(os.path.join(self.chroot, dst))

    def get(self, label):
        # type: (Optional[str]) -> Set[str]
        return self.filesets.get(label, set())

    def files(self):
        # type: () -> Set[str]
        all_files = set()
        for label in self.filesets:
            all_files.update(self.filesets[label])
        return all_files

    def labels(self):
        # type: () -> Iterable[Optional[str]]
        return self.filesets.keys()

    def __str__(self):
        # type: () -> str
        return "Chroot(%s {fs:%s})" % (
            self.chroot,
            " ".join("%s" % foo for foo in self.filesets.keys()),
        )

    def delete(self):
        # type: () -> None
        shutil.rmtree(self.chroot)

    def zip(
        self,
        filename,
        mode="w",
        deterministic=False,
        exclude_file=lambda _: False,
        strip_prefix=None,
        labels=None,
        compress=True,
    ):
        # type: (...) -> None

        if labels:
            selected_files = set(
                itertools.chain.from_iterable(self.filesets.get(label, ()) for label in labels)
            )
        else:
            selected_files = self.files()

        with open_zip(
            filename, mode, zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
        ) as zf:

            def write_entry(
                filename,
                arcname,
            ):
                # type: (...) -> None
                zf.write_deterministic(
                    filename=filename,
                    arcname=os.path.relpath(arcname, strip_prefix) if strip_prefix else arcname,
                    deterministic=deterministic,
                    compress=compress and self._compress_by_file.get(arcname, True),
                )

            def get_parent_dir(path):
                # type: (str) -> Optional[str]
                parent_dir = os.path.normpath(os.path.dirname(path))
                if parent_dir and parent_dir != os.curdir:
                    return parent_dir
                return None

            written_dirs = set()

            def maybe_write_parent_dirs(path):
                # type: (str) -> None
                if path == strip_prefix:
                    return
                parent_dir = get_parent_dir(path)
                if parent_dir is None or parent_dir in written_dirs:
                    return
                maybe_write_parent_dirs(parent_dir)
                if parent_dir != strip_prefix:
                    write_entry(filename=os.path.join(self.chroot, parent_dir), arcname=parent_dir)
                written_dirs.add(parent_dir)

            def iter_files():
                # type: () -> Iterator[Tuple[str, str]]
                for path in sorted(selected_files):
                    full_path = os.path.join(self.chroot, path)
                    if os.path.isfile(full_path):
                        if exclude_file(full_path):
                            continue
                        yield full_path, path
                        continue

                    for root, _, files in deterministic_walk(full_path):
                        for f in files:
                            if exclude_file(f):
                                continue
                            abs_path = os.path.join(root, f)
                            rel_path = os.path.join(path, os.path.relpath(abs_path, full_path))
                            yield abs_path, rel_path

            for filename, arcname in iter_files():
                maybe_write_parent_dirs(arcname)
                write_entry(filename, arcname)


def safe_relative_symlink(
    src,
    dst,
):
    # type: (...) -> None
    dst_parent = os.path.dirname(dst)
    safe_mkdir(dst_parent)
    rel_src = os.path.relpath(src, dst_parent)
    safe_symlink(rel_src, dst)


class CopyMode(Enum["CopyMode.Value"]):
    class Value(Enum.Value):
        pass

    COPY = Value("copy")
    LINK = Value("link")
    SYMLINK = Value("symlink")


CopyMode.seal()


def iter_copytree(
    src,
    dst,
    exclude=(),
    copy_mode=CopyMode.LINK,
):
    # type: (...) -> Iterator[Tuple[Text, Text]]
    safe_mkdir(dst)
    link = copy_mode is CopyMode.LINK
    for root, dirs, files in os.walk(src, topdown=True, followlinks=True):
        if src == root:
            dirs[:] = [d for d in dirs if d not in exclude]
            files[:] = [f for f in files if f not in exclude]

        for path, is_dir in itertools.chain(
            zip(dirs, itertools.repeat(True)), zip(files, itertools.repeat(False))
        ):
            src_entry = os.path.join(root, path)
            dst_entry = os.path.join(dst, os.path.relpath(src_entry, src))
            if not is_dir:
                yield src_entry, dst_entry
            try:
                if copy_mode is CopyMode.SYMLINK:
                    safe_relative_symlink(src_entry, dst_entry)
                elif is_dir:
                    os.mkdir(dst_entry)
                else:


                    if link and not os.path.islink(src_entry):
                        try:
                            safe_link(src_entry, dst_entry)
                            continue
                        except OSError as e:
                            if e.errno != errno.EXDEV:
                                raise e
                            link = False
                    shutil.copy(src_entry, dst_entry)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise e

        if copy_mode is CopyMode.SYMLINK:

            return


@contextmanager
def environment_as(**kwargs):
    # type: (**Any) -> Iterator[None]
    existing = {key: os.environ.get(key) for key in kwargs}

    def adjust_environment(mapping):
        for key, value in mapping.items():
            if value is not None:
                os.environ[key] = str(value)
            else:
                os.environ.pop(key, None)

    adjust_environment(kwargs)
    try:
        yield
    finally:
        adjust_environment(existing)
