

from __future__ import annotations

import logging
import operator
import platform
import re
import struct
import subprocess
import sys
import sysconfig
from importlib.machinery import EXTENSION_SUFFIXES
from typing import (
    TYPE_CHECKING,
    Iterable,
    Iterator,
    Sequence,
    Tuple,
    TypeVar,
    cast,
)

from . import _manylinux, _musllinux

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from typing import AbstractSet


__all__ = [
    "INTERPRETER_SHORT_NAMES",
    "AppleVersion",
    "PythonVersion",
    "Tag",
    "UnsortedTagsError",
    "android_platforms",
    "compatible_tags",
    "cpython_tags",
    "create_compatible_tags_selector",
    "generic_tags",
    "interpreter_name",
    "interpreter_version",
    "ios_platforms",
    "mac_platforms",
    "parse_tag",
    "platform_tags",
    "sys_tags",
]


def __dir__() -> list[str]:
    return __all__


logger = logging.getLogger(__name__)

PythonVersion = Sequence[int]
AppleVersion = Tuple[int, int]
_T = TypeVar("_T")

INTERPRETER_SHORT_NAMES: dict[str, str] = {
    "python": "py",
    "cpython": "cp",
    "pypy": "pp",
    "ironpython": "ip",
    "jython": "jy",
}


def _compute_32_bit_interpreter() -> bool:
    return struct.calcsize("P") == 4


_32_BIT_INTERPRETER = _compute_32_bit_interpreter()


class UnsortedTagsError(ValueError):


class Tag:

    __slots__ = ["_abi", "_hash", "_interpreter", "_platform"]

    def __init__(self, interpreter: str, abi: str, platform: str) -> None:
        self._interpreter = interpreter.lower()
        self._abi = abi.lower()
        self._platform = platform.lower()


        self._hash = hash((self._interpreter, self._abi, self._platform))

    @property
    def interpreter(self) -> str:
        return self._interpreter

    @property
    def abi(self) -> str:
        return self._abi

    @property
    def platform(self) -> str:
        return self._platform

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Tag):
            return NotImplemented

        return (
            (self._hash == other._hash)
            and (self._platform == other._platform)
            and (self._abi == other._abi)
            and (self._interpreter == other._interpreter)
        )

    def __hash__(self) -> int:
        return self._hash

    def __str__(self) -> str:
        return f"{self._interpreter}-{self._abi}-{self._platform}"

    def __repr__(self) -> str:
        return f"<{self} @ {id(self)}>"

    def __getstate__(self) -> tuple[str, str, str]:


        return (self._interpreter, self._abi, self._platform)

    def __setstate__(self, state: object) -> None:
        if isinstance(state, tuple):
            if len(state) == 3 and all(isinstance(s, str) for s in state):

                self._interpreter, self._abi, self._platform = state
                self._hash = hash((self._interpreter, self._abi, self._platform))
                return
            if len(state) == 2 and isinstance(state[1], dict):

                _, slots = state
                try:
                    interpreter = slots["_interpreter"]
                    abi = slots["_abi"]
                    platform = slots["_platform"]
                except KeyError:
                    raise TypeError(f"Cannot restore Tag from {state!r}") from None
                if not all(
                    isinstance(value, str) for value in (interpreter, abi, platform)
                ):
                    raise TypeError(f"Cannot restore Tag from {state!r}")
                self._interpreter = interpreter.lower()
                self._abi = abi.lower()
                self._platform = platform.lower()
                self._hash = hash((self._interpreter, self._abi, self._platform))
                return
        raise TypeError(f"Cannot restore Tag from {state!r}")


def parse_tag(tag: str, *, validate_order: bool = False) -> frozenset[Tag]:
    tags = set()
    interpreters, abis, platforms = tag.split("-")
    if validate_order:
        for component in (interpreters, abis, platforms):
            parts = component.split(".")
            if parts != sorted(parts):
                raise UnsortedTagsError(
                    f"Tag component {component!r} is not in sorted order per PEP 425"
                )
    for interpreter in interpreters.split("."):
        for abi in abis.split("."):
            for platform_ in platforms.split("."):
                tags.add(Tag(interpreter, abi, platform_))
    return frozenset(tags)


def _get_config_var(name: str, warn: bool = False) -> int | str | None:
    value: int | str | None = sysconfig.get_config_var(name)
    if value is None and warn:
        logger.debug(
            "Config variable '%s' is unset, Python ABI tag may be incorrect", name
        )
    return value


def _normalize_string(string: str) -> str:
    return string.replace(".", "_").replace("-", "_").replace(" ", "_")


def _is_threaded_cpython(abis: list[str]) -> bool:
    if len(abis) == 0:
        return False

    m = re.match(r"cp\d+(.*)", abis[0])
    if not m:
        return False
    abiflags = m.group(1)
    return "t" in abiflags


def _abi3_applies(python_version: PythonVersion, threading: bool) -> bool:
    return len(python_version) > 1 and tuple(python_version) >= (3, 2) and not threading


def _abi3t_applies(python_version: PythonVersion, threading: bool) -> bool:
    return len(python_version) > 1 and tuple(python_version) >= (3, 2) and threading


def _cpython_abis(py_version: PythonVersion, warn: bool = False) -> list[str]:
    py_version = tuple(py_version)
    abis = []
    version = _version_nodot(py_version[:2])
    threading = debug = pymalloc = ucs4 = ""
    with_debug = _get_config_var("Py_DEBUG", warn)
    has_refcount = hasattr(sys, "gettotalrefcount")


    has_ext = "_d.pyd" in EXTENSION_SUFFIXES
    if with_debug or (with_debug is None and (has_refcount or has_ext)):
        debug = "d"
    if py_version >= (3, 13) and _get_config_var("Py_GIL_DISABLED", warn):
        threading = "t"
    if py_version < (3, 8):
        with_pymalloc = _get_config_var("WITH_PYMALLOC", warn)
        if with_pymalloc or with_pymalloc is None:
            pymalloc = "m"
        if py_version < (3, 3):
            unicode_size = _get_config_var("Py_UNICODE_SIZE", warn)
            if unicode_size == 4 or (
                unicode_size is None and sys.maxunicode == 0x10FFFF
            ):
                ucs4 = "u"
    elif debug:


        abis.append(f"cp{version}{threading}")
    abis.insert(0, f"cp{version}{threading}{debug}{pymalloc}{ucs4}")
    return abis


def cpython_tags(
    python_version: PythonVersion | None = None,
    abis: Iterable[str] | None = None,
    platforms: Iterable[str] | None = None,
    *,
    warn: bool = False,
) -> Iterator[Tag]:
    if not python_version:
        python_version = sys.version_info[:2]

    interpreter = f"cp{_version_nodot(python_version[:2])}"

    if abis is None:
        abis = _cpython_abis(python_version, warn) if len(python_version) > 1 else []
    abis = list(abis)

    for explicit_abi in ("abi3", "none"):
        try:
            abis.remove(explicit_abi)
        except ValueError:
            pass

    platforms = list(platforms or platform_tags())
    for abi in abis:
        for platform_ in platforms:
            yield Tag(interpreter, abi, platform_)

    threading = _is_threaded_cpython(abis)
    use_abi3 = _abi3_applies(python_version, threading)
    use_abi3t = _abi3t_applies(python_version, threading)

    if use_abi3:
        yield from (Tag(interpreter, "abi3", platform_) for platform_ in platforms)
    if use_abi3t:
        yield from (Tag(interpreter, "abi3t", platform_) for platform_ in platforms)

    yield from (Tag(interpreter, "none", platform_) for platform_ in platforms)

    if use_abi3 or use_abi3t:
        for minor_version in range(python_version[1] - 1, 1, -1):
            for platform_ in platforms:
                version = _version_nodot((python_version[0], minor_version))
                interpreter = f"cp{version}"
                if use_abi3:
                    yield Tag(interpreter, "abi3", platform_)
                if use_abi3t:


                    yield Tag(interpreter, "abi3t", platform_)


def _generic_abi() -> list[str]:


    ext_suffix = _get_config_var("EXT_SUFFIX", warn=True)
    if not isinstance(ext_suffix, str) or ext_suffix[0] != ".":
        raise SystemError("invalid sysconfig.get_config_var('EXT_SUFFIX')")
    parts = ext_suffix.split(".")
    if len(parts) < 3:

        return _cpython_abis(sys.version_info[:2])
    soabi = parts[1]
    if soabi.startswith("cpython"):

        abi = "cp" + soabi.split("-")[1]
    elif soabi.startswith("cp"):

        abi = soabi.split("-")[0]
    elif soabi.startswith("pypy"):
        abi = "-".join(soabi.split("-")[:2])
    elif soabi.startswith("graalpy"):
        abi = "-".join(soabi.split("-")[:3])
    elif soabi:

        abi = soabi
    else:
        return []
    return [_normalize_string(abi)]


def generic_tags(
    interpreter: str | None = None,
    abis: Iterable[str] | None = None,
    platforms: Iterable[str] | None = None,
    *,
    warn: bool = False,
) -> Iterator[Tag]:
    if not interpreter:
        interp_name = interpreter_name()
        interp_version = interpreter_version(warn=warn)
        interpreter = f"{interp_name}{interp_version}"
    abis = _generic_abi() if abis is None else list(abis)
    platforms = list(platforms or platform_tags())
    if "none" not in abis:
        abis.append("none")
    for abi in abis:
        for platform_ in platforms:
            yield Tag(interpreter, abi, platform_)


def _py_interpreter_range(py_version: PythonVersion) -> Iterator[str]:
    if len(py_version) > 1:
        yield f"py{_version_nodot(py_version[:2])}"
    yield f"py{py_version[0]}"
    if len(py_version) > 1:
        for minor in range(py_version[1] - 1, -1, -1):
            yield f"py{_version_nodot((py_version[0], minor))}"


def compatible_tags(
    python_version: PythonVersion | None = None,
    interpreter: str | None = None,
    platforms: Iterable[str] | None = None,
) -> Iterator[Tag]:
    if not python_version:
        python_version = sys.version_info[:2]
    platforms = list(platforms or platform_tags())
    for version in _py_interpreter_range(python_version):
        for platform_ in platforms:
            yield Tag(version, "none", platform_)
    if interpreter:
        yield Tag(interpreter, "none", "any")
    for version in _py_interpreter_range(python_version):
        yield Tag(version, "none", "any")


def _mac_arch(arch: str, is_32bit: bool = _32_BIT_INTERPRETER) -> str:
    if not is_32bit:
        return arch

    if arch.startswith("ppc"):
        return "ppc"

    return "i386"


def _mac_binary_formats(version: AppleVersion, cpu_arch: str) -> list[str]:
    formats = [cpu_arch]
    if cpu_arch == "x86_64":
        if version < (10, 4):
            return []
        formats.extend(["intel", "fat64", "fat32"])

    elif cpu_arch == "i386":
        if version < (10, 4):
            return []
        formats.extend(["intel", "fat32", "fat"])

    elif cpu_arch == "ppc64":

        if version > (10, 5) or version < (10, 4):
            return []
        formats.append("fat64")

    elif cpu_arch == "ppc":
        if version > (10, 6):
            return []
        formats.extend(["fat32", "fat"])

    if cpu_arch in {"arm64", "x86_64"}:
        formats.append("universal2")

    if cpu_arch in {"x86_64", "i386", "ppc64", "ppc", "intel"}:
        formats.append("universal")

    return formats


def mac_platforms(
    version: AppleVersion | None = None, arch: str | None = None
) -> Iterator[str]:
    version_str, _, cpu_arch = platform.mac_ver()
    if version is None:
        version = cast("AppleVersion", tuple(map(int, version_str.split(".")[:2])))
        if version == (10, 16):


            version_str = subprocess.run(
                [
                    sys.executable,
                    "-sS",
                    "-c",
                    "import platform; print(platform.mac_ver()[0])",
                ],
                check=True,
                env={"SYSTEM_VERSION_COMPAT": "0"},
                stdout=subprocess.PIPE,
                text=True,
            ).stdout
            version = cast("AppleVersion", tuple(map(int, version_str.split(".")[:2])))

    if arch is None:
        arch = _mac_arch(cpu_arch)

    if (10, 0) <= version < (11, 0):


        major_version = 10
        for minor_version in range(version[1], -1, -1):
            compat_version = major_version, minor_version
            binary_formats = _mac_binary_formats(compat_version, arch)
            for binary_format in binary_formats:
                yield f"macosx_{major_version}_{minor_version}_{binary_format}"

    if version >= (11, 0):


        minor_version = 0
        for major_version in range(version[0], 10, -1):
            compat_version = major_version, minor_version
            binary_formats = _mac_binary_formats(compat_version, arch)
            for binary_format in binary_formats:
                yield f"macosx_{major_version}_{minor_version}_{binary_format}"

    if version >= (11, 0):


        major_version = 10
        if arch == "x86_64":
            for minor_version in range(16, 3, -1):
                compat_version = major_version, minor_version
                binary_formats = _mac_binary_formats(compat_version, arch)
                for binary_format in binary_formats:
                    yield f"macosx_{major_version}_{minor_version}_{binary_format}"
        else:
            for minor_version in range(16, 3, -1):
                compat_version = major_version, minor_version
                binary_format = "universal2"
                yield f"macosx_{major_version}_{minor_version}_{binary_format}"


def ios_platforms(
    version: AppleVersion | None = None, multiarch: str | None = None
) -> Iterator[str]:
    if version is None:


        _, release, _, _ = platform.ios_ver()
        version = cast("AppleVersion", tuple(map(int, release.split(".")[:2])))

    if multiarch is None:
        multiarch = sys.implementation._multiarch
    multiarch = multiarch.replace("-", "_")

    ios_platform_template = "ios_{major}_{minor}_{multiarch}"


    if version[0] < 12:
        return


    yield ios_platform_template.format(
        major=version[0], minor=version[1], multiarch=multiarch
    )


    for minor in range(version[1] - 1, -1, -1):
        yield ios_platform_template.format(
            major=version[0], minor=minor, multiarch=multiarch
        )

    for major in range(version[0] - 1, 11, -1):
        for minor in range(9, -1, -1):
            yield ios_platform_template.format(
                major=major, minor=minor, multiarch=multiarch
            )


def android_platforms(
    api_level: int | None = None, abi: str | None = None
) -> Iterator[str]:
    if platform.system() != "Android" and (api_level is None or abi is None):
        raise TypeError(
            "on non-Android platforms, the api_level and abi arguments are required"
        )

    if api_level is None:
        # Python 3.13 was the first version to return platform.system() == "Android",

        api_level = platform.android_ver().api_level

    if abi is None:
        abi = sysconfig.get_platform().split("-")[-1]
    abi = _normalize_string(abi)


    min_api_level = 16
    for ver in range(api_level, min_api_level - 1, -1):
        yield f"android_{ver}_{abi}"


def _linux_platforms(is_32bit: bool = _32_BIT_INTERPRETER) -> Iterator[str]:
    linux = _normalize_string(sysconfig.get_platform())
    if not linux.startswith("linux_"):

        yield linux
        return
    if is_32bit:
        if linux == "linux_x86_64":
            linux = "linux_i686"
        elif linux == "linux_aarch64":
            linux = "linux_armv8l"
    _, arch = linux.split("_", 1)
    archs = {"armv8l": ["armv8l", "armv7l"]}.get(arch, [arch])
    yield from _manylinux.platform_tags(archs)
    yield from _musllinux.platform_tags(archs)
    for arch in archs:
        yield f"linux_{arch}"


def _emscripten_platforms() -> Iterator[str]:
    pyemscripten_platform_version = sysconfig.get_config_var(
        "PYEMSCRIPTEN_PLATFORM_VERSION"
    )
    if pyemscripten_platform_version:
        yield f"pyemscripten_{pyemscripten_platform_version}_wasm32"
    yield from _generic_platforms()


def _generic_platforms() -> Iterator[str]:
    yield _normalize_string(sysconfig.get_platform())


def platform_tags() -> Iterator[str]:
    if platform.system() == "Darwin":
        return mac_platforms()
    elif platform.system() == "iOS":
        return ios_platforms()
    elif platform.system() == "Android":
        return android_platforms()
    elif platform.system() == "Linux":
        return _linux_platforms()
    elif platform.system() == "Emscripten":
        return _emscripten_platforms()
    else:
        return _generic_platforms()


def interpreter_name() -> str:
    name = sys.implementation.name
    return INTERPRETER_SHORT_NAMES.get(name) or name


def interpreter_version(*, warn: bool = False) -> str:
    version = _get_config_var("py_version_nodot", warn=warn)
    return str(version) if version else _version_nodot(sys.version_info[:2])


def _version_nodot(version: PythonVersion) -> str:
    return "".join(map(str, version))


def sys_tags(*, warn: bool = False) -> Iterator[Tag]:

    interp_name = interpreter_name()
    if interp_name == "cp":
        yield from cpython_tags(warn=warn)
    else:
        yield from generic_tags()

    if interp_name == "pp":
        interp = "pp3"
    elif interp_name == "cp":
        interp = "cp" + interpreter_version(warn=warn)
    else:
        interp = None
    yield from compatible_tags(interpreter=interp)


def create_compatible_tags_selector(
    tags: Iterable[Tag],
) -> Callable[[Iterable[tuple[_T, AbstractSet[Tag]]]], Iterator[_T]]:
    tag_ranks: dict[Tag, int] = {}
    for rank, tag in enumerate(tags):
        tag_ranks.setdefault(tag, rank)
    supported_tags = tag_ranks.keys()

    def selector(
        tagged_things: Iterable[tuple[_T, AbstractSet[Tag]]],
    ) -> Iterator[_T]:
        ranked_things: list[tuple[_T, int]] = []
        for thing, thing_tags in tagged_things:
            supported_thing_tags = thing_tags & supported_tags
            if supported_thing_tags:
                thing_rank = min(tag_ranks[t] for t in supported_thing_tags)
                ranked_things.append((thing, thing_rank))
        return iter(
            thing for thing, _ in sorted(ranked_things, key=operator.itemgetter(1))
        )

    return selector
