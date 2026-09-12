from __future__ import annotations

import dataclasses
import re
import urllib.parse
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

if TYPE_CHECKING:
    import sys
    from collections.abc import Collection

    if sys.version_info >= (3, 11):
        from typing import Self
    else:
        from typing_extensions import Self

__all__ = [
    "ArchiveInfo",
    "DirInfo",
    "DirectUrl",
    "DirectUrlValidationError",
    "VcsInfo",
]


def __dir__() -> list[str]:
    return __all__


_T = TypeVar("_T")


class _FromMappingProtocol(Protocol):
    @classmethod
    def _from_dict(cls, d: Mapping[str, Any]) -> Self: ...


_FromMappingProtocolT = TypeVar("_FromMappingProtocolT", bound=_FromMappingProtocol)


def _json_dict_factory(data: list[tuple[str, Any]]) -> dict[str, Any]:
    return {key: value for key, value in data if value is not None}


def _get(d: Mapping[str, Any], expected_type: type[_T], key: str) -> _T | None:
    if (value := d.get(key)) is None:
        return None
    if not isinstance(value, expected_type):
        raise DirectUrlValidationError(
            f"Unexpected type {type(value).__name__} "
            f"(expected {expected_type.__name__})",
            context=key,
        )
    return value


def _get_required(d: Mapping[str, Any], expected_type: type[_T], key: str) -> _T:
    if (value := _get(d, expected_type, key)) is None:
        raise _DirectUrlRequiredKeyError(key)
    return value


def _get_object(
    d: Mapping[str, Any], target_type: type[_FromMappingProtocolT], key: str
) -> _FromMappingProtocolT | None:
    if (value := _get(d, Mapping, key)) is None:
        return None
    try:
        return target_type._from_dict(value)
    except Exception as e:
        raise DirectUrlValidationError(e, context=key) from e


_PEP610_USER_PASS_ENV_VARS_REGEX = re.compile(
    r"^\$\{[A-Za-z0-9-_]+\}(:\$\{[A-Za-z0-9-_]+\})?$"
)


def _strip_auth_from_netloc(netloc: str, safe_user_passwords: Collection[str]) -> str:
    if "@" not in netloc:
        return netloc
    user_pass, netloc_no_user_pass = netloc.split("@", 1)
    if user_pass in safe_user_passwords:
        return netloc
    if _PEP610_USER_PASS_ENV_VARS_REGEX.match(user_pass):
        return netloc
    return netloc_no_user_pass


def _strip_url(url: str, safe_user_passwords: Collection[str]) -> str:
    parsed_url = urllib.parse.urlsplit(url)
    netloc = _strip_auth_from_netloc(parsed_url.netloc, safe_user_passwords)
    return urllib.parse.urlunsplit(
        (
            parsed_url.scheme,
            netloc,
            parsed_url.path,
            parsed_url.query,
            parsed_url.fragment,
        )
    )


class DirectUrlValidationError(Exception):

    context: str | None = None
    message: str

    def __init__(
        self,
        cause: str | Exception,
        *,
        context: str | None = None,
    ) -> None:
        if isinstance(cause, DirectUrlValidationError):
            if cause.context:
                self.context = (
                    f"{context}.{cause.context}" if context else cause.context
                )
            else:
                self.context = context
            self.message = cause.message
        else:
            self.context = context
            self.message = str(cause)

    def __str__(self) -> str:
        if self.context:
            return f"{self.message} in {self.context!r}"
        return self.message


class _DirectUrlRequiredKeyError(DirectUrlValidationError):
    def __init__(self, key: str) -> None:
        super().__init__("Missing required value", context=key)


@dataclasses.dataclass(frozen=True, init=False)
class VcsInfo:
    vcs: str
    commit_id: str
    requested_revision: str | None = None

    def __init__(
        self,
        *,
        vcs: str,
        commit_id: str,
        requested_revision: str | None = None,
    ) -> None:
        object.__setattr__(self, "vcs", vcs)
        object.__setattr__(self, "commit_id", commit_id)
        object.__setattr__(self, "requested_revision", requested_revision)

    @classmethod
    def _from_dict(cls, d: Mapping[str, Any]) -> Self:

        return cls(
            vcs=_get_required(d, str, "vcs"),
            requested_revision=_get(d, str, "requested_revision"),
            commit_id=_get_required(d, str, "commit_id"),
        )


@dataclasses.dataclass(frozen=True, init=False)
class ArchiveInfo:
    hashes: Mapping[str, str] | None = None

    def __init__(
        self,
        *,
        hashes: Mapping[str, str] | None = None,
    ) -> None:
        object.__setattr__(self, "hashes", hashes)

    @classmethod
    def _from_dict(cls, d: Mapping[str, Any]) -> Self:
        hashes = _get(d, Mapping, "hashes")
        if hashes is not None and not all(isinstance(h, str) for h in hashes.values()):
            raise DirectUrlValidationError(
                "Hash values must be strings", context="hashes"
            )
        legacy_hash = _get(d, str, "hash")
        if legacy_hash is not None:
            if "=" not in legacy_hash:
                raise DirectUrlValidationError(
                    "Invalid hash format (expected '<algorithm>=<hash>')",
                    context="hash",
                )
            hash_algorithm, hash_value = legacy_hash.split("=", 1)
            if hashes is None:

                hashes = {hash_algorithm: hash_value}
            else:

                if hash_algorithm not in hashes:
                    raise DirectUrlValidationError(
                        f"Algorithm {hash_algorithm!r} used in hash field "
                        f"is not present in hashes field",
                        context="hashes",
                    )
                if hashes[hash_algorithm] != hash_value:
                    raise DirectUrlValidationError(
                        f"Algorithm {hash_algorithm!r} used in hash field "
                        f"has different value in hashes field",
                        context="hash",
                    )
        return cls(hashes=hashes)


@dataclasses.dataclass(frozen=True, init=False)
class DirInfo:
    editable: bool | None = None

    def __init__(
        self,
        *,
        editable: bool | None = None,
    ) -> None:
        object.__setattr__(self, "editable", editable)

    @classmethod
    def _from_dict(cls, d: Mapping[str, Any]) -> Self:
        return cls(
            editable=_get(d, bool, "editable"),
        )


@dataclasses.dataclass(frozen=True, init=False)
class DirectUrl:

    url: str
    archive_info: ArchiveInfo | None = None
    vcs_info: VcsInfo | None = None
    dir_info: DirInfo | None = None
    subdirectory: str | None = None

    def __init__(
        self,
        *,
        url: str,
        archive_info: ArchiveInfo | None = None,
        vcs_info: VcsInfo | None = None,
        dir_info: DirInfo | None = None,
        subdirectory: str | None = None,
    ) -> None:
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "archive_info", archive_info)
        object.__setattr__(self, "vcs_info", vcs_info)
        object.__setattr__(self, "dir_info", dir_info)
        object.__setattr__(self, "subdirectory", subdirectory)

    @classmethod
    def _from_dict(cls, d: Mapping[str, Any]) -> Self:
        direct_url = cls(
            url=_get_required(d, str, "url"),
            archive_info=_get_object(d, ArchiveInfo, "archive_info"),
            vcs_info=_get_object(d, VcsInfo, "vcs_info"),
            dir_info=_get_object(d, DirInfo, "dir_info"),
            subdirectory=_get(d, str, "subdirectory"),
        )
        if (
            bool(direct_url.vcs_info)
            + bool(direct_url.archive_info)
            + bool(direct_url.dir_info)
        ) != 1:
            raise DirectUrlValidationError(
                "Exactly one of vcs_info, archive_info, dir_info must be present"
            )
        if direct_url.dir_info is not None and not direct_url.url.startswith("file://"):
            raise DirectUrlValidationError(
                "URL scheme must be file:// when dir_info is present",
                context="url",
            )

        return direct_url

    @classmethod
    def from_dict(cls, d: Mapping[str, Any], /) -> Self:
        return cls._from_dict(d)

    def to_dict(
        self,
        *,
        generate_legacy_hash: bool = False,
        strip_user_password: bool = True,
        safe_user_passwords: Collection[str] = ("git",),
    ) -> Mapping[str, Any]:
        res = dataclasses.asdict(self, dict_factory=_json_dict_factory)
        if generate_legacy_hash and self.archive_info and self.archive_info.hashes:
            hash_algorithm, hash_value = next(iter(self.archive_info.hashes.items()))
            res["archive_info"]["hash"] = f"{hash_algorithm}={hash_value}"
        if strip_user_password:
            res["url"] = _strip_url(self.url, safe_user_passwords)
        return res

    def validate(self) -> None:
        self.from_dict(self.to_dict())
