

from __future__ import absolute_import

import copy
import os.path
import sys
import tarfile
from tarfile import TarInfo

from pex.compatibility import commonpath
from pex.typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from typing import Any, Dict, Optional, Text, TypeVar


class FilterError(tarfile.TarError):
    pass


class AbsolutePathError(FilterError):
    pass


class OutsideDestinationError(FilterError):
    pass


class SpecialFileError(FilterError):
    pass


class AbsoluteLinkError(FilterError):
    pass


class LinkOutsideDestinationError(FilterError):
    pass


_REALPATH_KWARGS = (
    {"strict": getattr(os.path, "ALLOW_MISSING", False)} if sys.version_info[:2] >= (3, 10) else {}
)


if TYPE_CHECKING:
    _Text = TypeVar("_Text", str, Text)


def _realpath(path):
    # type: (_Text) -> _Text
    return os.path.realpath(path, **_REALPATH_KWARGS)


def _get_filtered_attrs(
    member,
    dest_path,
    for_data=True,
):
    # type: (...) -> Dict[str, Any]


    new_attrs = {}
    name = member.name
    dest_path = _realpath(dest_path)


    if name.startswith(("/", os.sep)):
        name = new_attrs["name"] = member.path.lstrip("/" + os.sep)
    if os.path.isabs(name):


        raise AbsolutePathError("member {name!r} has an absolute path".format(name=member.name))

    target_path = _realpath(os.path.join(dest_path, name))
    if commonpath([target_path, dest_path]) != dest_path:
        raise OutsideDestinationError(
            "{name!r} would be extracted to {path!r}, which is outside the destination".format(
                name=member.name, path=target_path
            )
        )

    mode = member.mode
    if mode is not None:

        mode = mode & 0o755
        if for_data:

            if member.isreg() or member.islnk():
                if not mode & 0o100:

                    mode &= ~0o111

                mode |= 0o600
            elif member.isdir() or member.issym():
                if sys.version_info[:2] >= (3, 12):

                    mode = None
                else:

                    pass
            else:

                raise SpecialFileError("{name!r} is a special file".format(name=member.name))
        if mode != member.mode:
            new_attrs["mode"] = mode
    if for_data:
        if sys.version_info[:2] >= (3, 12):

            if member.uid is not None:
                new_attrs["uid"] = None
            if member.gid is not None:
                new_attrs["gid"] = None
            if member.uname is not None:
                new_attrs["uname"] = None
            if member.gname is not None:
                new_attrs["gname"] = None
        else:

            pass


        if member.islnk() or member.issym():
            if os.path.isabs(member.linkname):
                raise AbsoluteLinkError(
                    "{name!r} is a link to an absolute path".format(name=member.name)
                )
            normalized = os.path.normpath(member.linkname)
            if normalized != member.linkname:
                new_attrs["linkname"] = normalized
            if member.issym():
                target_path = os.path.join(dest_path, os.path.dirname(name), member.linkname)
            else:
                target_path = os.path.join(dest_path, member.linkname)
            target_path = _realpath(target_path)
            if commonpath([target_path, dest_path]) != dest_path:
                raise LinkOutsideDestinationError(
                    "{name!r} would link to {path!r}, which is outside the destination".format(
                        name=member.name, path=target_path
                    )
                )
    return new_attrs


def _replace(
    member,
    attrs,
):
    # type: (...) -> TarInfo

    replace = getattr(member, "replace", None)
    if replace:
        attrs["deep"] = False
        return cast(TarInfo, replace(**attrs))

    result = copy.copy(member)
    for attr, value in attrs.items():
        setattr(result, attr, value)
    return result


def _data_filter(
    member,
    dest_path,
):
    # type: (...) -> TarInfo
    new_attrs = _get_filtered_attrs(member, dest_path, True)
    if new_attrs:
        return _replace(member, new_attrs)
    return member


_EXTRACTALL_DATA_FILTER_KWARGS = {"filter": "data"}


class InvalidSourceDistributionError(ValueError):
    pass


def extract_tarball(
    tarball_path,
    dest_dir,
):
    # type: (...) -> _Text

    with tarfile.open(tarball_path) as tf:
        if sys.version_info[:2] >= (3, 12):
            tf.extractall(dest_dir, **_EXTRACTALL_DATA_FILTER_KWARGS)
        else:
            for tar_info in tf:
                tar_info = _data_filter(tar_info, dest_dir)
                tf.extract(tar_info, dest_dir)

    listing = os.listdir(dest_dir)
    if len(listing) != 1:
        raise InvalidSourceDistributionError(
            "Expected one top-level project directory to be extracted from {project}, "
            "found {count}: {listing}".format(
                project=tarball_path, count=len(listing), listing=", ".join(listing)
            )
        )

    project_dir = os.path.join(dest_dir, listing[0])
    if not os.path.isdir(project_dir):
        raise InvalidSourceDistributionError(
            "Expected one top-level project directory to be extracted from {project}, "
            "found file: {path}".format(project=tarball_path, path=listing[0])
        )

    return project_dir
