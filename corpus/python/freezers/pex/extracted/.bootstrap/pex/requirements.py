

from __future__ import absolute_import

import os
import re
import shlex
import sys
from argparse import ArgumentParser
from contextlib import contextmanager

from pex import attrs, dist_metadata, pex_warnings
from pex.artifact_url import VCS, ArchiveScheme, ArtifactURL, VCSScheme
from pex.compatibility import url_unquote, urlparse
from pex.dist_metadata import (
    MetadataError,
    ProjectNameAndVersion,
    Requirement,
    RequirementParseError,
)
from pex.fetcher import URLFetcher
from pex.orderedset import OrderedSet
from pex.pep_503 import ProjectName
from pex.third_party.packaging.markers import Marker
from pex.third_party.packaging.specifiers import SpecifierSet
from pex.third_party.packaging.version import InvalidVersion, Version
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import FrozenSet, Iterable, Iterator, Match, Optional, Text, Tuple, Union

    import attr
else:
    from pex.third_party import attr


@attr.s(frozen=True)
class LogicalLine(object):
    @classmethod
    def from_str(
        cls,
        text,
        source="<string>",
    ):
        # type: (...) -> LogicalLine
        return LogicalLine(
            raw_text=text,
            processed_text=text.strip(),
            source=source,
            start_line=1,
            end_line=1,
        )

    raw_text = attr.ib()
    processed_text = attr.ib()
    source = attr.ib()
    start_line = attr.ib()
    end_line = attr.ib()

    def render_location(self):
        # type: () -> str
        if self.start_line == self.end_line:
            return "{} line {}".format(self.source, self.start_line)
        return "{} lines {}-{}".format(self.source, self.start_line, self.end_line)


@attr.s(frozen=True)
class Source(object):
    @classmethod
    @contextmanager
    def from_url(
        cls,
        fetcher,
        url,
        is_constraints=False,
    ):
        # type: (...) -> Iterator[Source]
        pex_warnings.warn(
            "Fetching {subject} files via url is deprecated: {url}".format(
                url=url, subject="constraints" if is_constraints else "requirements"
            )
        )
        with fetcher.get_body_iter(url) as lines:
            yield cls(origin=url, is_file=False, is_constraints=is_constraints, lines=lines)

    @classmethod
    @contextmanager
    def from_file(
        cls,
        path,
        is_constraints=False,
    ):
        # type: (...) -> Iterator[Source]
        realpath = os.path.realpath(path)
        with open(realpath) as fp:
            yield cls(origin=realpath, is_file=True, is_constraints=is_constraints, lines=fp)

    @classmethod
    def from_text(
        cls,
        contents,
        origin="<string>",
        is_constraints=False,
    ):
        # type: (...) -> Source
        return cls(
            origin=origin,
            is_file=False,
            is_constraints=is_constraints,
            lines=iter(contents.splitlines(True)),
        )

    origin = attr.ib()
    is_file = attr.ib()
    is_constraints = attr.ib()
    lines = attr.ib()

    @contextmanager
    def resolve(
        self,
        line,
        origin,
        is_constraints=False,
        fetcher=None,
    ):
        # type: (...) -> Iterator[Source]
        def create_parse_error(msg):
            # type: (str) -> ParseError
            return ParseError(
                line,
                "Problem resolving {} file: {}".format(
                    "constraints" if is_constraints else "requirements", msg
                ),
            )

        url = urlparse.urlparse(urlparse.urljoin(self.origin, origin))
        if url.scheme and url.netloc:
            if fetcher is None:
                raise create_parse_error(
                    "The source is a url but no fetcher was supplied to resolve its contents with."
                )
            try:
                with self.from_url(fetcher, origin, is_constraints=is_constraints) as source:
                    yield source
            except OSError as e:
                raise create_parse_error(str(e))
            return

        path = url.path if url.scheme == "file" else origin
        if not os.path.isabs(path) and self.is_file:
            path = os.path.join(os.path.dirname(self.origin), path)
        try:
            with self.from_file(path, is_constraints=is_constraints) as source:
                yield source
        except (IOError, OSError) as e:
            raise create_parse_error(str(e))


@attr.s(frozen=True)
class _ParsedItem(object):
    line = attr.ib()

    def __str__(self):
        # type: () -> str
        return str(self.line.processed_text)


@attr.s(frozen=True)
class _Repo(_ParsedItem):
    location = attr.ib()


@attr.s(frozen=True)
class FindLinks(_Repo):
    pass


@attr.s(frozen=True)
class Index(_Repo):
    pass


@attr.s(frozen=True)
class PyPIRequirement(_ParsedItem):

    requirement = attr.ib()

    @property
    def project_name(self):
        # type: () -> ProjectName
        return self.requirement.project_name

    @property
    def extras(self):
        # type: () -> FrozenSet[str]
        return self.requirement.extras

    @property
    def marker(self):
        # type: () -> Optional[Marker]
        return self.requirement.marker


@attr.s(frozen=True)
class URLRequirement(_ParsedItem):

    url = attr.ib()
    requirement = attr.ib()

    @property
    def project_name(self):
        # type: () -> ProjectName
        return self.requirement.project_name

    @property
    def extras(self):
        # type: () -> FrozenSet[str]
        return self.requirement.extras

    @property
    def marker(self):
        # type: () -> Optional[Marker]
        return self.requirement.marker

    @property
    def filename(self):
        # type: () -> str
        return os.path.basename(self.url.path)

    @property
    def subdirectory(self):
        # type: () -> Optional[str]
        subdirectories = self.url.fragment_parameters.get("subdirectory")
        return subdirectories[-1] if subdirectories else None


@attr.s(frozen=True)
class VCSRequirement(_ParsedItem):

    vcs = attr.ib()
    url = attr.ib()
    requirement = attr.ib()
    commit = attr.ib(default=None)

    @property
    def project_name(self):
        # type: () -> ProjectName
        return self.requirement.project_name

    @property
    def extras(self):
        # type: () -> FrozenSet[str]
        return self.requirement.extras

    @property
    def marker(self):
        # type: () -> Optional[Marker]
        return self.requirement.marker


def parse_requirement_from_project_name_and_specifier(
    project_name,
    extras=None,
    specifier=None,
    marker=None,
    editable=False,
    url=None,
):
    # type: (...) -> Requirement
    requirement_string = "{project_name}{extras}{specifier}".format(
        project_name=project_name,
        extras="[{extras}]".format(extras=", ".join(extras)) if extras else "",
        specifier=specifier or SpecifierSet(),
    )
    if marker:
        requirement_string += ";" + str(marker)
    return attr.evolve(Requirement.parse(requirement_string, editable=editable), url=url)


def parse_requirement_from_dist(
    dist,
    extras=None,
    marker=None,
    editable=False,
):
    # type: (...) -> Requirement
    project_name_and_version = dist_metadata.project_name_and_version(dist)
    if project_name_and_version is None:
        raise ValueError(
            "Failed to find a project name and version from the given wheel path: "
            "{wheel}".format(wheel=dist)
        )
    project_name_and_specifier = ProjectNameAndSpecifier.from_project_name_and_version(
        project_name_and_version
    )
    return parse_requirement_from_project_name_and_specifier(
        project_name_and_specifier.project_name,
        extras=extras,
        specifier=project_name_and_specifier.specifier,
        marker=marker,
        editable=editable,
    )


@attr.s(frozen=True)
class LocalProjectRequirement(_ParsedItem):

    path = attr.ib()
    extras = attr.ib(default=(), converter=attrs.str_tuple_from_iterable)
    marker = attr.ib(default=None)
    editable = attr.ib(default=False)
    project_name = attr.ib(default=None)

    def as_requirement(self, dist=None):
        # type: (Optional[str]) -> Requirement
        if dist is None and self.project_name is None:
            raise ValueError(
                "No distribution was supplied and the local project at {path} has an unknown "
                "project name; so no requirement can be calculated.".format(path=self.path)
            )

        if dist is not None:
            return parse_requirement_from_dist(dist, self.extras, self.marker, self.editable)

        return parse_requirement_from_project_name_and_specifier(
            project_name=str(self.project_name),
            extras=self.extras,
            marker=self.marker,
            editable=self.editable,
            url="file://{path}".format(path=self.path),
        )


if TYPE_CHECKING:
    ParsedRequirement = Union[
        PyPIRequirement, URLRequirement, VCSRequirement, LocalProjectRequirement
    ]


@attr.s(frozen=True)
class Constraint(_ParsedItem):
    requirement = attr.ib()

    @property
    def project_name(self):
        return self.requirement.project_name

    @property
    def marker(self):
        # type: () -> Optional[Marker]
        return self.requirement.marker


class ParseError(Exception):
    def __init__(
        self,
        logical_line,
        msg,
    ):
        # type: (...) -> None
        super(ParseError, self).__init__(
            "{}:\n{}\n{}".format(logical_line.render_location(), logical_line.raw_text, msg)
        )
        self._logical_line = logical_line

    @property
    def logical_line(self):
        # type: () -> LogicalLine
        return self._logical_line


def _strip_requirement_options(line):
    # type: (LogicalLine) -> Tuple[bool, Text]

    processed_text = re.sub(r"^\s*(-e|--editable)\s+", "", line.processed_text)
    editable = processed_text != line.processed_text
    return editable, re.sub(r"\s--(global-option|install-option|hash).*$", "", processed_text)


@attr.s(frozen=True)
class ProjectNameExtrasAndMarker(object):
    project_name = attr.ib()
    extras = attr.ib(default=(), converter=attrs.str_tuple_from_iterable)
    marker = attr.ib(default=None)

    def astuple(self):
        # type: () -> Tuple[Text, Tuple[str, ...], Optional[Marker]]
        return self.project_name, self.extras, self.marker


def _try_parse_fragment_project_name_and_marker(url):
    # type: (ArtifactURL) -> Optional[ProjectNameExtrasAndMarker]
    project_names = url.fragment_parameters.get("egg")
    if not project_names:
        return None

    project_name = project_names[-1]
    try:
        req = Requirement.parse(project_name)
        return ProjectNameExtrasAndMarker(req.name, extras=req.extras, marker=req.marker)
    except (RequirementParseError, ValueError):
        return ProjectNameExtrasAndMarker(project_name)


@attr.s(frozen=True)
class ProjectNameAndSpecifier(object):
    @staticmethod
    def _version_as_specifier(version):
        # type: (Text) -> SpecifierSet
        try:
            return SpecifierSet("=={}".format(Version(version)))
        except InvalidVersion:
            return SpecifierSet("==={}".format(version))

    @classmethod
    def from_project_name_and_version(cls, project_name_and_version):
        # type: (ProjectNameAndVersion) -> ProjectNameAndSpecifier
        return cls(
            project_name=project_name_and_version.project_name,
            specifier=cls._version_as_specifier(project_name_and_version.version),
        )

    project_name = attr.ib()
    specifier = attr.ib()


def _try_parse_project_name_and_specifier_from_path(path):
    # type: (str) -> Optional[ProjectNameAndSpecifier]
    try:
        return ProjectNameAndSpecifier.from_project_name_and_version(
            ProjectNameAndVersion.from_filename(path)
        )
    except MetadataError:
        return None


def _try_parse_pip_local_formats(
    path,
    basepath=None,
):
    # type: (...) -> Optional[ProjectNameExtrasAndMarker]
    project_requirement = os.path.basename(path)


    REQUIREMENT_PARTS_START = (


        r"\[",


        r"!=><~",


        r";",

        r"\s",
    )

    match = re.match(
        r"""
        ^
        (?P<directory_name>[^{REQUIREMENT_PARTS_START}]*)?
        (?P<requirement_parts>.*)?
        $
        """.format(
            REQUIREMENT_PARTS_START="".join(REQUIREMENT_PARTS_START)
        ),
        project_requirement,
        re.VERBOSE,
    )
    if not match:
        return None

    directory_name, requirement_parts = match.groups()
    stripped_path = os.path.join(os.path.dirname(path), directory_name)
    abs_stripped_path = (
        os.path.join(basepath, stripped_path)
        if basepath and not os.path.isabs(stripped_path)
        else os.path.abspath(stripped_path)
    )
    if not os.path.exists(abs_stripped_path):
        return None


    requirement_parts = match.group("requirement_parts")
    if not requirement_parts:
        return ProjectNameExtrasAndMarker(abs_stripped_path)

    project_requirement = "fake_project{}".format(requirement_parts)
    try:
        req = Requirement.parse(project_requirement)
        return ProjectNameExtrasAndMarker(abs_stripped_path, extras=req.extras, marker=req.marker)
    except (RequirementParseError, ValueError):
        return None


def _split_direct_references(processed_text):
    # type: (Text) -> Union[Tuple[Text, Text], Tuple[None, None]]
    match = re.match(
        r"""
        ^
        (?P<requirement>[a-zA-Z0-9]+(?:[-_.]+[a-zA-Z0-9]+)*)
        \s*
        @
        \s*
        (?P<url>.+)?
        $
        """,
        processed_text,
        re.VERBOSE,
    )
    if not match:
        return None, None
    project_name, url = match.groups()
    return project_name, url


def _parse_requirement_line(
    line,
    basepath=None,
):
    # type: (...) -> ParsedRequirement

    basepath = basepath or os.getcwd()

    editable, processed_text = _strip_requirement_options(line)
    project_name, direct_reference_url = _split_direct_references(processed_text)
    parsed_url = ArtifactURL.parse(direct_reference_url or processed_text)


    if isinstance(parsed_url.scheme, (ArchiveScheme.Value, VCSScheme)):
        project_name_extras_and_marker = _try_parse_fragment_project_name_and_marker(parsed_url)
        project_name, extras, marker = (
            project_name_extras_and_marker.astuple()
            if project_name_extras_and_marker
            else (project_name, (), None)
        )
        specifier = None
        if not project_name:
            project_name_and_specifier = _try_parse_project_name_and_specifier_from_path(


                url_unquote(parsed_url.path).rstrip()
            )
            if project_name_and_specifier is not None:
                project_name = project_name_and_specifier.project_name
                specifier = project_name_and_specifier.specifier


        if not marker and parsed_url.parameters:
            marker = Marker(parsed_url.parameters)
        if project_name is None:
            raise ParseError(
                line,
                (
                    "Could not determine a project name for URL requirement {url}, consider using "
                    "#egg=<project name>.".format(url=parsed_url.raw_url)
                ),
            )
        parsed_url_info = parsed_url.url_info._replace(
            params="",


            fragment=parsed_url.fragment(excludes={"egg"}),
        )


        url = parsed_url_info.geturl().rstrip()
        requirement = parse_requirement_from_project_name_and_specifier(
            project_name,
            extras=extras,
            specifier=specifier,
            marker=marker,
            url=url,
        )
        parsed_scheme = parsed_url.scheme
        if isinstance(parsed_scheme, VCSScheme):
            url = parsed_url_info._replace(scheme=parsed_scheme.scheme).geturl()
            _, sep, commit = parsed_url_info.path.rpartition("@")
            return VCSRequirement(
                line, parsed_scheme.vcs, url, requirement, commit=commit if sep else None
            )
        return URLRequirement(line, url=ArtifactURL.parse(url), requirement=requirement)


    local_requirement = parsed_url.url_info._replace(scheme="").geturl()
    project_name_extras_and_marker = _try_parse_pip_local_formats(
        local_requirement, basepath=basepath
    )
    maybe_abs_path, extras, marker = (
        project_name_extras_and_marker.astuple()
        if project_name_extras_and_marker
        else (project_name, (), None)
    )
    if isinstance(maybe_abs_path, str) and any(
        os.path.isfile(os.path.join(maybe_abs_path, *p))
        for p in ((), ("setup.py",), ("pyproject.toml",))
    ):
        archive_or_project_path = os.path.realpath(maybe_abs_path)
        if os.path.isdir(archive_or_project_path):
            return LocalProjectRequirement(
                line,
                archive_or_project_path,
                extras=extras,
                marker=marker,
                editable=editable,
                project_name=ProjectName(project_name) if project_name else None,
            )
        try:
            requirement = parse_requirement_from_dist(
                archive_or_project_path, extras=extras, marker=marker
            )
            return URLRequirement(
                line,
                url=ArtifactURL.parse(archive_or_project_path),
                requirement=requirement,
            )
        except dist_metadata.UnrecognizedDistributionFormat:


            pass


    try:
        return as_parsed_requirement(Requirement.parse(processed_text), line=line)
    except RequirementParseError as e:
        raise ParseError(
            line, "Problem parsing {!r} as a requirement: {}".format(processed_text, e)
        )


def _expand_env_var(line, match):
    # type: (LogicalLine, Match) -> Text
    env_var_name = match.group(1)
    value = os.environ.get(env_var_name)
    if value is None:
        raise ParseError(line, "No value for environment variable ${} is set.".format(env_var_name))
    return value


def _expand_env_vars(line):
    # type: (LogicalLine) -> Text


    def expand_env_var(match):
        # type: (Match) -> Text
        return _expand_env_var(line, match)

    return re.sub(r"\${([A-Za-z0-9_]+)}", expand_env_var, line.processed_text)


def _get_parameter(line):
    # type: (LogicalLine) -> Text
    split_line = line.processed_text.split("=")
    if len(split_line) != 2:
        split_line = line.processed_text.split()
    if len(split_line) != 2:
        raise ParseError(line, "Unrecognized parameter format.")
    return split_line[1]


_REPOS_PARSER = None


def _parse_repos(line):
    # type: (LogicalLine) -> Iterator[Union[FindLinks, Index]]

    try:


        args = shlex.split(line.processed_text)
    except UnicodeEncodeError as e:
        raise ParseError(
            line,
            "Options line has unicode characters which are not supported under Python {version}: "
            "{err}".format(version=".".join(map(str, sys.version[:2])), err=e),
        )

    global _REPOS_PARSER
    if _REPOS_PARSER is not None:
        parser = _REPOS_PARSER
    else:
        parser = ArgumentParser()


        parser.add_argument("-f", "--find-links", dest="find_links", action="append", default=[])
        parser.add_argument("-i", "--index-url", dest="index_url")
        parser.add_argument(
            "--extra-index-url", dest="extra_index_urls", action="append", default=[]
        )
        _REPOS_PARSER = parser

    options, _ = parser.parse_known_args(args)

    for find_links in OrderedSet(options.find_links):
        yield FindLinks(line, location=find_links)

    index_locations = OrderedSet()
    if options.index_url:
        index_locations.add(options.index_url)
    index_locations.update(options.extra_index_urls)

    for index in index_locations:
        yield Index(line, location=index)


def parse_requirements(
    source,
    fetcher=None,
):
    # type: (...) -> Iterator[Union[ParsedRequirement, Constraint, FindLinks, Index]]


    start_line = 0
    line_buffer = []
    logical_line_buffer = []

    for line_no, line in enumerate(source.lines, start=1):
        if start_line == 0:
            start_line = line_no
        line_buffer.append(line)
        stripped_line = line.strip()


        if re.search(r"(^|[^\\])\\$", stripped_line):
            logical_line_buffer.append(stripped_line[:-1])
            continue

        end_line = line_no
        logical_line_buffer.append(stripped_line)


        logical_line_stripped = re.sub(r"(^|\s+)#.*$", "", "".join(logical_line_buffer))
        logical_line = LogicalLine(
            raw_text="".join(line_buffer),
            processed_text=logical_line_stripped,
            source=source.origin,
            start_line=start_line,
            end_line=end_line,
        )
        logical_line = attr.evolve(logical_line, processed_text=_expand_env_vars(logical_line))
        try:

            processed_text = logical_line.processed_text
            requirement_file = processed_text.startswith(("-r", "--requirement"))
            constraint_file = not requirement_file and processed_text.startswith(
                ("-c", "--constraint")
            )
            if requirement_file or constraint_file:
                relpath = _get_parameter(logical_line)
                with source.resolve(
                    line=logical_line,
                    origin=relpath,
                    is_constraints=constraint_file,
                    fetcher=fetcher,
                ) as other_source:
                    for requirement in parse_requirements(other_source, fetcher=fetcher):
                        yield requirement
                continue


            if not processed_text:
                continue

            if processed_text.startswith("-") and not re.match(

                r"^(?:-e|--editable)\s.*",
                processed_text,
            ):
                for repo in _parse_repos(logical_line):
                    yield repo
                continue


            requirement = _parse_requirement_line(
                logical_line, basepath=os.path.dirname(source.origin) if source.is_file else None
            )
            if source.is_constraints:
                if (
                    not isinstance(requirement, (PyPIRequirement, URLRequirement, VCSRequirement))
                    or requirement.requirement.extras
                ):
                    raise ParseError(
                        logical_line,
                        "Constraint files do not support local project requirements and they "
                        "do not support requirements with extras; see:"
                        "https://pip.pypa.io/en/stable/user_guide/#constraints-files. If you are "
                        "using --pip-version vendored or a very old --pip-version, search for 'We "
                        "are also changing our support for Constraints Files' here: "
                        "https://pip.pypa.io/en/stable/user_guide/"
                        "#changes-to-the-pip-dependency-resolver-in-20-3-2020.",
                    )
                yield Constraint(logical_line, requirement.requirement)
            else:
                yield requirement
        finally:
            start_line = 0
            del line_buffer[:]
            del logical_line_buffer[:]


def parse_requirement_file(
    location,
    is_constraints=False,
    fetcher=None,
):
    # type: (...) -> Iterator[Union[ParsedRequirement, Constraint, FindLinks, Index]]
    def open_source():
        url = urlparse.urlparse(location)
        if url.scheme and url.netloc:
            if fetcher is None:
                raise ValueError(
                    "The location is a url but no fetcher was supplied to resolve its contents "
                    "with."
                )
            return Source.from_url(fetcher=fetcher, url=location, is_constraints=is_constraints)

        path = url.path if url.scheme == "file" else location
        return Source.from_file(path=path, is_constraints=is_constraints)

    with open_source() as source:
        for req_info in parse_requirements(source, fetcher=fetcher):
            yield req_info


def parse_requirement_string(requirement):
    # type: (Text) -> ParsedRequirement
    return _parse_requirement_line(LogicalLine.from_str(requirement))


def parse_requirement_strings(requirements):
    # type: (Iterable[Text]) -> Iterator[ParsedRequirement]
    for requirement in requirements:
        yield parse_requirement_string(requirement)


def as_parsed_requirement(
    requirement,
    line=None,
):
    # type: (...) -> ParsedRequirement

    requirement_str = str(requirement)
    logical_line = line or LogicalLine.from_str(requirement_str, source="<parsed requirement>")
    if not requirement.url:
        return PyPIRequirement(line=logical_line, requirement=requirement)

    url = ArtifactURL.parse(requirement.url)
    if isinstance(url.scheme, VCSScheme):
        vcs_scheme = url.scheme
        normalized_url = url.url_info._replace(scheme=vcs_scheme.scheme)
        _, sep, commit = normalized_url.path.rpartition("@")
        return VCSRequirement(
            line=logical_line,
            vcs=vcs_scheme.vcs,
            url=normalized_url.geturl(),
            requirement=requirement,
            commit=commit,
        )

    if url.scheme == "file" and os.path.isdir(url.path):
        return LocalProjectRequirement(
            line=logical_line,
            path=url.path,
            extras=tuple(requirement.extras),
            marker=requirement.marker,
            editable=requirement.editable,
            project_name=requirement.project_name,
        )

    return URLRequirement(line=logical_line, url=url, requirement=requirement)
