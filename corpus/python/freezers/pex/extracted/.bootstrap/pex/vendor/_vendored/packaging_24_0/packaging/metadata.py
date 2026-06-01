import email.feedparser
import email.header
import email.message
import email.parser
import email.policy
import sys
import typing
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
)

from . import requirements, specifiers, utils, version as version_module

T = typing.TypeVar("T")
if sys.version_info[:2] >= (3, 8):
    from typing import Literal, TypedDict
else:
    if typing.TYPE_CHECKING:
        from typing_extensions import Literal, TypedDict
    else:
        try:
            from typing_extensions import Literal, TypedDict
        except ImportError:

            class Literal:
                def __init_subclass__(*_args, **_kwargs):
                    pass

            class TypedDict:
                def __init_subclass__(*_args, **_kwargs):
                    pass


try:
    ExceptionGroup
except NameError:

    class ExceptionGroup(Exception):

        message: str
        exceptions: List[Exception]

        def __init__(self, message: str, exceptions: List[Exception]) -> None:
            self.message = message
            self.exceptions = exceptions

        def __repr__(self) -> str:
            return f"{self.__class__.__name__}({self.message!r}, {self.exceptions!r})"

else:
    ExceptionGroup = ExceptionGroup


class InvalidMetadata(ValueError):

    field: str
    """The name of the field that contains invalid data."""

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        super().__init__(message)


class RawMetadata(TypedDict, total=False):


    metadata_version: str
    name: str
    version: str
    platforms: List[str]
    summary: str
    description: str
    keywords: List[str]
    home_page: str
    author: str
    author_email: str
    license: str


    supported_platforms: List[str]
    download_url: str
    classifiers: List[str]
    requires: List[str]
    provides: List[str]
    obsoletes: List[str]


    maintainer: str
    maintainer_email: str
    requires_dist: List[str]
    provides_dist: List[str]
    obsoletes_dist: List[str]
    requires_python: str
    requires_external: List[str]
    project_urls: Dict[str, str]


    description_content_type: str
    provides_extra: List[str]


    dynamic: List[str]


_STRING_FIELDS = {
    "author",
    "author_email",
    "description",
    "description_content_type",
    "download_url",
    "home_page",
    "license",
    "maintainer",
    "maintainer_email",
    "metadata_version",
    "name",
    "requires_python",
    "summary",
    "version",
}

_LIST_FIELDS = {
    "classifiers",
    "dynamic",
    "obsoletes",
    "obsoletes_dist",
    "platforms",
    "provides",
    "provides_dist",
    "provides_extra",
    "requires",
    "requires_dist",
    "requires_external",
    "supported_platforms",
}

_DICT_FIELDS = {
    "project_urls",
}


def _parse_keywords(data: str) -> List[str]:
    return [k.strip() for k in data.split(",")]


def _parse_project_urls(data: List[str]) -> Dict[str, str]:
    urls = {}
    for pair in data:


        parts = [p.strip() for p in pair.split(",", 1)]
        parts.extend([""] * (max(0, 2 - len(parts))))


        label, url = parts
        if label in urls:


            raise KeyError("duplicate labels in project urls")
        urls[label] = url

    return urls


def _get_payload(msg: email.message.Message, source: Union[bytes, str]) -> str:


    if isinstance(source, str):
        payload: str = msg.get_payload()
        return payload


    else:
        bpayload: bytes = msg.get_payload(decode=True)
        try:
            return bpayload.decode("utf8", "strict")
        except UnicodeDecodeError:
            raise ValueError("payload in an invalid encoding")


_EMAIL_TO_RAW_MAPPING = {
    "author": "author",
    "author-email": "author_email",
    "classifier": "classifiers",
    "description": "description",
    "description-content-type": "description_content_type",
    "download-url": "download_url",
    "dynamic": "dynamic",
    "home-page": "home_page",
    "keywords": "keywords",
    "license": "license",
    "maintainer": "maintainer",
    "maintainer-email": "maintainer_email",
    "metadata-version": "metadata_version",
    "name": "name",
    "obsoletes": "obsoletes",
    "obsoletes-dist": "obsoletes_dist",
    "platform": "platforms",
    "project-url": "project_urls",
    "provides": "provides",
    "provides-dist": "provides_dist",
    "provides-extra": "provides_extra",
    "requires": "requires",
    "requires-dist": "requires_dist",
    "requires-external": "requires_external",
    "requires-python": "requires_python",
    "summary": "summary",
    "supported-platform": "supported_platforms",
    "version": "version",
}
_RAW_TO_EMAIL_MAPPING = {raw: email for email, raw in _EMAIL_TO_RAW_MAPPING.items()}


def parse_email(data: Union[bytes, str]) -> Tuple[RawMetadata, Dict[str, List[str]]]:
    raw: Dict[str, Union[str, List[str], Dict[str, str]]] = {}
    unparsed: Dict[str, List[str]] = {}

    if isinstance(data, str):
        parsed = email.parser.Parser(policy=email.policy.compat32).parsestr(data)
    else:
        parsed = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(data)


    for name in frozenset(parsed.keys()):


        name = name.lower()


        headers = parsed.get_all(name) or []


        value = []


        valid_encoding = True
        for h in headers:


            assert isinstance(h, (email.header.Header, str))


            if isinstance(h, email.header.Header):


                chunks: List[Tuple[bytes, Optional[str]]] = []
                for bin, encoding in email.header.decode_header(h):
                    try:
                        bin.decode("utf8", "strict")
                    except UnicodeDecodeError:

                        encoding = "latin1"
                        valid_encoding = False
                    else:
                        encoding = "utf8"
                    chunks.append((bin, encoding))


                value.append(str(email.header.make_header(chunks)))

            else:
                value.append(h)


        if not valid_encoding:
            unparsed[name] = value
            continue

        raw_name = _EMAIL_TO_RAW_MAPPING.get(name)
        if raw_name is None:


            unparsed[name] = value
            continue


        if raw_name in _STRING_FIELDS and len(value) == 1:
            raw[raw_name] = value[0]


        elif raw_name in _LIST_FIELDS:
            raw[raw_name] = value


        elif raw_name == "keywords" and len(value) == 1:
            raw[raw_name] = _parse_keywords(value[0])


        elif raw_name == "project_urls":
            try:
                raw[raw_name] = _parse_project_urls(value)
            except KeyError:
                unparsed[name] = value


        else:
            unparsed[name] = value


    try:
        payload = _get_payload(parsed, data)
    except ValueError:
        unparsed.setdefault("description", []).append(
            parsed.get_payload(decode=isinstance(data, bytes))
        )
    else:
        if payload:


            if "description" in raw:
                description_header = cast(str, raw.pop("description"))
                unparsed.setdefault("description", []).extend(
                    [description_header, payload]
                )
            elif "description" in unparsed:
                unparsed["description"].append(payload)
            else:
                raw["description"] = payload


    return cast(RawMetadata, raw), unparsed


_NOT_FOUND = object()


_VALID_METADATA_VERSIONS = ["1.0", "1.1", "1.2", "2.1", "2.2", "2.3"]
_MetadataVersion = Literal["1.0", "1.1", "1.2", "2.1", "2.2", "2.3"]

_REQUIRED_ATTRS = frozenset(["metadata_version", "name", "version"])


class _Validator(Generic[T]):

    name: str
    raw_name: str
    added: _MetadataVersion

    def __init__(
        self,
        *,
        added: _MetadataVersion = "1.0",
    ) -> None:
        self.added = added

    def __set_name__(self, _owner: "Metadata", name: str) -> None:
        self.name = name
        self.raw_name = _RAW_TO_EMAIL_MAPPING[name]

    def __get__(self, instance: "Metadata", _owner: Type["Metadata"]) -> T:


        cache = instance.__dict__
        value = instance._raw.get(self.name)


        if self.name in _REQUIRED_ATTRS or value is not None:
            try:
                converter: Callable[[Any], T] = getattr(self, f"_process_{self.name}")
            except AttributeError:
                pass
            else:
                value = converter(value)

        cache[self.name] = value
        try:
            del instance._raw[self.name]
        except KeyError:
            pass

        return cast(T, value)

    def _invalid_metadata(
        self, msg: str, cause: Optional[Exception] = None
    ) -> InvalidMetadata:
        exc = InvalidMetadata(
            self.raw_name, msg.format_map({"field": repr(self.raw_name)})
        )
        exc.__cause__ = cause
        return exc

    def _process_metadata_version(self, value: str) -> _MetadataVersion:

        if value not in _VALID_METADATA_VERSIONS:
            raise self._invalid_metadata(f"{value!r} is not a valid metadata version")
        return cast(_MetadataVersion, value)

    def _process_name(self, value: str) -> str:
        if not value:
            raise self._invalid_metadata("{field} is a required field")

        try:
            utils.canonicalize_name(value, validate=True)
        except utils.InvalidName as exc:
            raise self._invalid_metadata(
                f"{value!r} is invalid for {{field}}", cause=exc
            )
        else:
            return value

    def _process_version(self, value: str) -> version_module.Version:
        if not value:
            raise self._invalid_metadata("{field} is a required field")
        try:
            return version_module.parse(value)
        except version_module.InvalidVersion as exc:
            raise self._invalid_metadata(
                f"{value!r} is invalid for {{field}}", cause=exc
            )

    def _process_summary(self, value: str) -> str:
        if "\n" in value:
            raise self._invalid_metadata("{field} must be a single line")
        return value

    def _process_description_content_type(self, value: str) -> str:
        content_types = {"text/plain", "text/x-rst", "text/markdown"}
        message = email.message.EmailMessage()
        message["content-type"] = value

        content_type, parameters = (

            message.get_content_type().lower(),
            message["content-type"].params,
        )


        if content_type not in content_types or content_type not in value.lower():
            raise self._invalid_metadata(
                f"{{field}} must be one of {list(content_types)}, not {value!r}"
            )

        charset = parameters.get("charset", "UTF-8")
        if charset != "UTF-8":
            raise self._invalid_metadata(
                f"{{field}} can only specify the UTF-8 charset, not {list(charset)}"
            )

        markdown_variants = {"GFM", "CommonMark"}
        variant = parameters.get("variant", "GFM")
        if content_type == "text/markdown" and variant not in markdown_variants:
            raise self._invalid_metadata(
                f"valid Markdown variants for {{field}} are {list(markdown_variants)}, "
                f"not {variant!r}",
            )
        return value

    def _process_dynamic(self, value: List[str]) -> List[str]:
        for dynamic_field in map(str.lower, value):
            if dynamic_field in {"name", "version", "metadata-version"}:
                raise self._invalid_metadata(
                    f"{value!r} is not allowed as a dynamic field"
                )
            elif dynamic_field not in _EMAIL_TO_RAW_MAPPING:
                raise self._invalid_metadata(f"{value!r} is not a valid dynamic field")
        return list(map(str.lower, value))

    def _process_provides_extra(
        self,
        value: List[str],
    ) -> List[utils.NormalizedName]:
        normalized_names = []
        try:
            for name in value:
                normalized_names.append(utils.canonicalize_name(name, validate=True))
        except utils.InvalidName as exc:
            raise self._invalid_metadata(
                f"{name!r} is invalid for {{field}}", cause=exc
            )
        else:
            return normalized_names

    def _process_requires_python(self, value: str) -> specifiers.SpecifierSet:
        try:
            return specifiers.SpecifierSet(value)
        except specifiers.InvalidSpecifier as exc:
            raise self._invalid_metadata(
                f"{value!r} is invalid for {{field}}", cause=exc
            )

    def _process_requires_dist(
        self,
        value: List[str],
    ) -> List[requirements.Requirement]:
        reqs = []
        try:
            for req in value:
                reqs.append(requirements.Requirement(req))
        except requirements.InvalidRequirement as exc:
            raise self._invalid_metadata(f"{req!r} is invalid for {{field}}", cause=exc)
        else:
            return reqs


class Metadata:

    _raw: RawMetadata

    @classmethod
    def from_raw(cls, data: RawMetadata, *, validate: bool = True) -> "Metadata":
        ins = cls()
        ins._raw = data.copy()

        if validate:
            exceptions: List[Exception] = []
            try:
                metadata_version = ins.metadata_version
                metadata_age = _VALID_METADATA_VERSIONS.index(metadata_version)
            except InvalidMetadata as metadata_version_exc:
                exceptions.append(metadata_version_exc)
                metadata_version = None


            fields_to_check = frozenset(ins._raw) | _REQUIRED_ATTRS

            fields_to_check -= {"metadata_version"}

            for key in fields_to_check:
                try:
                    if metadata_version:


                        try:
                            field_metadata_version = cls.__dict__[key].added
                        except KeyError:
                            exc = InvalidMetadata(key, f"unrecognized field: {key!r}")
                            exceptions.append(exc)
                            continue
                        field_age = _VALID_METADATA_VERSIONS.index(
                            field_metadata_version
                        )
                        if field_age > metadata_age:
                            field = _RAW_TO_EMAIL_MAPPING[key]
                            exc = InvalidMetadata(
                                field,
                                "{field} introduced in metadata version "
                                "{field_metadata_version}, not {metadata_version}",
                            )
                            exceptions.append(exc)
                            continue
                    getattr(ins, key)
                except InvalidMetadata as exc:
                    exceptions.append(exc)

            if exceptions:
                raise ExceptionGroup("invalid metadata", exceptions)

        return ins

    @classmethod
    def from_email(
        cls, data: Union[bytes, str], *, validate: bool = True
    ) -> "Metadata":
        raw, unparsed = parse_email(data)

        if validate:
            exceptions: list[Exception] = []
            for unparsed_key in unparsed:
                if unparsed_key in _EMAIL_TO_RAW_MAPPING:
                    message = f"{unparsed_key!r} has invalid data"
                else:
                    message = f"unrecognized field: {unparsed_key!r}"
                exceptions.append(InvalidMetadata(unparsed_key, message))

            if exceptions:
                raise ExceptionGroup("unparsed", exceptions)

        try:
            return cls.from_raw(raw, validate=validate)
        except ExceptionGroup as exc_group:
            raise ExceptionGroup(
                "invalid or unparsed metadata", exc_group.exceptions
            ) from None

    metadata_version: _Validator[_MetadataVersion] = _Validator()
    """:external:ref:`core-metadata-metadata-version`
    (required; validated to be a valid metadata version)"""
    name: _Validator[str] = _Validator()
    """:external:ref:`core-metadata-name`
    (required; validated using :func:`~packaging.utils.canonicalize_name` and its
    *validate* parameter)"""
    version: _Validator[version_module.Version] = _Validator()
    """:external:ref:`core-metadata-version` (required)"""
    dynamic: _Validator[Optional[List[str]]] = _Validator(
        added="2.2",
    )
    """:external:ref:`core-metadata-dynamic`
    (validated against core metadata field names and lowercased)"""
    platforms: _Validator[Optional[List[str]]] = _Validator()
    """:external:ref:`core-metadata-platform`"""
    supported_platforms: _Validator[Optional[List[str]]] = _Validator(added="1.1")
    """:external:ref:`core-metadata-supported-platform`"""
    summary: _Validator[Optional[str]] = _Validator()
    """:external:ref:`core-metadata-summary` (validated to contain no newlines)"""
    description: _Validator[Optional[str]] = _Validator()
    """:external:ref:`core-metadata-description`"""
    description_content_type: _Validator[Optional[str]] = _Validator(added="2.1")
    """:external:ref:`core-metadata-description-content-type` (validated)"""
    keywords: _Validator[Optional[List[str]]] = _Validator()
    """:external:ref:`core-metadata-keywords`"""
    home_page: _Validator[Optional[str]] = _Validator()
    """:external:ref:`core-metadata-home-page`"""
    download_url: _Validator[Optional[str]] = _Validator(added="1.1")
    """:external:ref:`core-metadata-download-url`"""
    author: _Validator[Optional[str]] = _Validator()
    """:external:ref:`core-metadata-author`"""
    author_email: _Validator[Optional[str]] = _Validator()
    """:external:ref:`core-metadata-author-email`"""
    maintainer: _Validator[Optional[str]] = _Validator(added="1.2")
    """:external:ref:`core-metadata-maintainer`"""
    maintainer_email: _Validator[Optional[str]] = _Validator(added="1.2")
    """:external:ref:`core-metadata-maintainer-email`"""
    license: _Validator[Optional[str]] = _Validator()
    """:external:ref:`core-metadata-license`"""
    classifiers: _Validator[Optional[List[str]]] = _Validator(added="1.1")
    """:external:ref:`core-metadata-classifier`"""
    requires_dist: _Validator[Optional[List[requirements.Requirement]]] = _Validator(
        added="1.2"
    )
    """:external:ref:`core-metadata-requires-dist`"""
    requires_python: _Validator[Optional[specifiers.SpecifierSet]] = _Validator(
        added="1.2"
    )
    """:external:ref:`core-metadata-requires-python`"""


    requires_external: _Validator[Optional[List[str]]] = _Validator(added="1.2")
    """:external:ref:`core-metadata-requires-external`"""
    project_urls: _Validator[Optional[Dict[str, str]]] = _Validator(added="1.2")
    """:external:ref:`core-metadata-project-url`"""


    provides_extra: _Validator[Optional[List[utils.NormalizedName]]] = _Validator(
        added="2.1",
    )
    """:external:ref:`core-metadata-provides-extra`"""
    provides_dist: _Validator[Optional[List[str]]] = _Validator(added="1.2")
    """:external:ref:`core-metadata-provides-dist`"""
    obsoletes_dist: _Validator[Optional[List[str]]] = _Validator(added="1.2")
    """:external:ref:`core-metadata-obsoletes-dist`"""
    requires: _Validator[Optional[List[str]]] = _Validator(added="1.1")
    """``Requires`` (deprecated)"""
    provides: _Validator[Optional[List[str]]] = _Validator(added="1.1")
    """``Provides`` (deprecated)"""
    obsoletes: _Validator[Optional[List[str]]] = _Validator(added="1.1")
    """``Obsoletes`` (deprecated)"""
