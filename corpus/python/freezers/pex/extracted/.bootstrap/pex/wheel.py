

from __future__ import absolute_import

import itertools
import os
import re
from email.message import Message

from pex.dist_metadata import (
    DistMetadata,
    Distribution,
    MetadataFiles,
    MetadataType,
    load_metadata,
    parse_message,
)
from pex.exceptions import production_assert
from pex.orderedset import OrderedSet
from pex.pep_440 import Version
from pex.pep_503 import ProjectName
from pex.third_party.packaging.tags import Tag, parse_tag
from pex.typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from typing import Dict, Iterator, List, Optional, Text, Tuple

    import attr
else:
    from pex.third_party import attr


class WheelMetadataLoadError(ValueError):


@attr.s(frozen=True)
class WHEEL(object):

    @classmethod
    def from_metadata_files(
        cls,
        metadata_files,
        known_tags=(),
    ):
        # type: (...) -> WHEEL

        metadata_bytes = metadata_files.read("WHEEL")
        if not metadata_bytes:
            raise WheelMetadataLoadError(
                "Could not find WHEEL metadata in {wheel}.".format(
                    wheel=metadata_files.render_description(metadata_file_name="WHEEL")
                )
            )


        normalized_metadata = b"".join(
            line for line in metadata_bytes.splitlines(True) if line.strip()
        )

        metadata = parse_message(normalized_metadata)

        try:
            tags = tuple(
                itertools.chain.from_iterable(


                    sorted(parse_tag(tag), key=lambda tag: str(tag))
                    for tag in metadata.get_all("Tag", ())


                    if tag
                )
            )
        except ValueError:


            tags = ()

        if not tags:


            tags = known_tags

        production_assert(
            len(tags) > 0,
            "Should be able to determine wheel tags for wheel with METADATA at "
            "{metadata_location}",
            metadata_location=metadata_files.metadata.location,
        )

        return cls(files=metadata_files, metadata=metadata, tags=tags)

    _CACHE = {}

    @classmethod
    def load(
        cls,
        location,
        known_tags=(),
        project_name=None,
    ):
        # type: (...) -> WHEEL
        wheel = cls._CACHE.get((location, project_name))
        if not wheel:
            metadata_files = load_metadata(
                location, project_name=project_name, restrict_types_to=(MetadataType.DIST_INFO,)
            )
            if not metadata_files:
                raise WheelMetadataLoadError(
                    "Could not find any metadata in {wheel}.".format(wheel=location)
                )
            if not known_tags and location.endswith(".whl"):
                known_tags = parse_tags_from_filename(location)
            wheel = cls.from_metadata_files(metadata_files, known_tags=known_tags)
            cls._CACHE[(location, project_name)] = wheel
            if project_name is None:
                cls._CACHE[(location, wheel.files.metadata.project_name)] = wheel
        return wheel

    @classmethod
    def from_distribution(
        cls,
        distribution,
        platform_tag=None,
    ):
        # type: (...) -> WHEEL
        location = distribution.metadata.files.metadata.path
        project_name = distribution.metadata.project_name
        wheel = cls._CACHE.get((location, project_name))
        if not wheel:


            if location.endswith(".whl"):
                known_tags = parse_tags_from_filename(location)
            elif platform_tag:
                known_tags = (platform_tag,)
            else:
                known_tags = ()
            wheel = cls.from_metadata_files(distribution.metadata.files, known_tags=known_tags)
            cls._CACHE[(location, project_name)] = wheel
        return wheel

    files = attr.ib()
    metadata = attr.ib()
    tags = attr.ib()

    @property
    def root_is_purelib(self):
        # type: () -> bool


        return cast(bool, "true" == self.metadata.get("Root-Is-Purelib"))


@attr.s(frozen=True)
class Wheel(object):
    @staticmethod
    def _source(
        location,
        metadata_files,
    ):
        # type: (...) -> str
        return "{project_name} {version} at {location}".format(
            project_name=metadata_files.metadata.project_name,
            version=metadata_files.metadata.version,
            location=location,
        )

    @classmethod
    def _from_metadata_files(
        cls,
        location,
        metadata_files,
        known_tags,
        wheel=None,
    ):
        # type: (...) -> Wheel

        if wheel:
            metadata = wheel
        else:
            metadata = WHEEL.from_metadata_files(metadata_files, known_tags=known_tags)

        wheel_metadata_dir = os.path.dirname(metadata_files.metadata.rel_path)
        if not wheel_metadata_dir.endswith(".dist-info"):
            raise WheelMetadataLoadError(
                "Expected METADATA file for {source} to be housed in a .dist-info directory, but "
                "was found at {wheel_metadata_path}.".format(
                    source=cls._source(location, metadata_files),
                    wheel_metadata_path=metadata_files.metadata.rel_path,
                )
            )


        metadata_dir = str(wheel_metadata_dir)

        data_dir = re.sub(r"\.dist-info$", ".data", metadata_dir)
        pex_metadata_dir = re.sub(r"\.dist-info$", ".pex-info", metadata_dir)

        return cls(
            location=location,
            metadata_dir=metadata_dir,
            metadata_files=metadata_files,
            metadata=metadata,
            data_dir=data_dir,
            pex_metadata_dir=pex_metadata_dir,
        )

    @classmethod
    def load(
        cls,
        location,
        project_name=None,
        known_tags=(),
    ):
        # type: (...) -> Wheel

        known_tags = known_tags or (
            parse_tags_from_filename(location) if location.endswith(".whl") else ()
        )
        wheel = WHEEL.load(location, project_name=project_name, known_tags=known_tags)
        return cls._from_metadata_files(
            location=location, metadata_files=wheel.files, wheel=wheel, known_tags=known_tags
        )

    @classmethod
    def from_distribution(
        cls,
        distribution,
        platform_tag=None,
    ):
        # type: (...) -> Wheel
        return cls._from_metadata_files(
            location=distribution.location,
            metadata_files=distribution.metadata.files,
            known_tags=(platform_tag,) if platform_tag else (),
        )

    location = attr.ib()
    metadata_dir = attr.ib()
    metadata_files = attr.ib()
    metadata = attr.ib()
    data_dir = attr.ib()
    pex_metadata_dir = attr.ib()

    @property
    def source(self):
        # type: () -> str
        return self._source(self.location, self.metadata_files)

    @property
    def project_name(self):
        # type: () -> ProjectName
        return self.metadata_files.metadata.project_name

    @property
    def version(self):
        # type: () -> Version
        return self.metadata_files.metadata.version

    @property
    def tags(self):
        # type: () -> Tuple[Tag, ...]
        return self.metadata.tags

    @property
    def wheel_prefix(self):
        # type: () -> str


        project_name = re.sub(r"[-_.]+", "_", self.project_name.raw)


        version = self.version.raw.replace("-", "_")

        return "{project_name}-{version}".format(project_name=project_name, version=version)

    @property
    def wheel_file_name(self):
        # type: () -> str

        interpreters = OrderedSet()
        abis = OrderedSet()
        platforms = OrderedSet()
        for tag in self.metadata.tags:
            interpreters.add(tag.interpreter)
            abis.add(tag.abi)
            platforms.add(tag.platform)
        tag = "{interpreters}-{abis}-{platforms}".format(
            interpreters=".".join(interpreters), abis=".".join(abis), platforms=".".join(platforms)
        )
        return "{wheel_prefix}-{tag}.whl".format(wheel_prefix=self.wheel_prefix, tag=tag)

    def iter_compatible_python_versions(self):
        # type: () -> Iterator[Tuple[int, ...]]

        for tag in self.metadata.tags:
            match = re.search(r"\d+(?:_\d+)*", tag.interpreter)
            if not match:
                raise WheelMetadataLoadError(
                    "Invalid interpreter tag for wheel {whl} at {location}: {tag}".format(
                        whl=self.wheel_file_name, location=self.location, tag=tag.interpreter
                    )
                )
            components = match.group().split("_")
            version = []
            if len(components) == 1:
                py_version_nodot = components[0]
                version.append(int(py_version_nodot[0]))
                if len(py_version_nodot) > 1:
                    version.append(int(py_version_nodot[1:]))
            else:
                version.extend(int(component) for component in components)
            yield tuple(version)

    @property
    def root_is_purelib(self):
        # type: () -> bool
        return self.metadata.root_is_purelib

    def dist_metadata(self):
        # type: () -> DistMetadata
        return DistMetadata.from_metadata_files(self.metadata_files)

    def metadata_path(self, *components):
        # type: (*str) -> str
        if not components:
            return self.metadata_dir
        return os.path.join(self.metadata_dir, *components)

    def data_path(self, *components):
        # type: (*str) -> str
        return os.path.join(self.data_dir, *components)

    def pex_metadata_path(self, *components):
        # type: (*str) -> str
        if not components:
            return self.pex_metadata_dir
        return os.path.join(self.pex_metadata_dir, *components)

    def read_pex_metadata(self, *components):
        # type: (*str) -> Optional[bytes]

        location = os.path.join(self.location, self.pex_metadata_path(*components))
        if not os.path.exists(location):
            return None

        with open(location, "rb") as fp:
            return fp.read()


def parse_tags_from_filename(wheel_file_name):
    # type: (Text) -> Tuple[Tag, ...]

    if not wheel_file_name.endswith(".whl"):
        raise ValueError(
            "Can only calculate wheel tags from a filename that ends in .whl per "
            "https://peps.python.org/pep-0427/#file-name-convention, given: {wheel!r}".format(
                wheel=wheel_file_name
            )
        )

    wheel_stem, _ = os.path.splitext(os.path.basename(wheel_file_name))


    wheel_components = wheel_stem.rsplit("-", 3)
    if len(wheel_components) != 4:
        pattern = "`-{python tag}-{abi tag}-{platform tag}.whl`"
        raise ValueError(
            "Can only calculate wheel tags from a filename that ends in {pattern} per "
            "https://peps.python.org/pep-0427/#file-name-convention, given: {wheel!r}".format(
                pattern=pattern, wheel=wheel_file_name
            )
        )

    return tuple(parse_tag("-".join(wheel_components[-3:])))
