

import logging
import platform
import sys
import sysconfig
from importlib.machinery import EXTENSION_SUFFIXES
from typing import (
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
    cast,
)

from . import _manylinux, _musllinux

logger = logging.getLogger(__name__)

PythonVersion = Sequence[int]
MacVersion = Tuple[int, int]

INTERPRETER_SHORT_NAMES: Dict[str, str] = {
    "python": "py",
    "cpython": "cp",
    "pypy": "pp",
    "ironpython": "ip",
    "jython": "jy",
}


_32_BIT_INTERPRETER = sys.maxsize <= 2 ** 32


class Tag:

    __slots__ = ["_interpreter", "_abi", "_platform", "_hash"]

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


def parse_tag(tag: str) -> FrozenSet[Tag]:
    tags = set()
    interpreters, abis, platforms = tag.split("-")
    for interpreter in interpreters.split("."):
        for abi in abis.split("."):
            for platform_ in platforms.split("."):
                tags.add(Tag(interpreter, abi, platform_))
    return frozenset(tags)


def _get_config_var(name: str, warn: bool = False) -> Union[int, str, None]:
    value = sysconfig.get_config_var(name)
    if value is None and warn:
        logger.debug(
            "Config variable '%s' is unset, Python ABI tag may be incorrect", name
        )
    return value


def _normalize_string(string: str) -> str:
    return string.replace(".", "_").replace("-", "_")


def _abi3_applies(python_version: PythonVersion) -> bool:
    return len(python_version) > 1 and tuple(python_version) >= (3, 2)


def _cpython_abis(py_version: PythonVersion, warn: bool = False) -> List[str]:
    py_version = tuple(py_version)
    abis = []
    version = _version_nodot(py_version[:2])
    debug = pymalloc = ucs4 = ""
    with_debug = _get_config_var("Py_DEBUG", warn)
    has_refcount = hasattr(sys, "gettotalrefcount")


    has_ext = "_d.pyd" in EXTENSION_SUFFIXES
    if with_debug or (with_debug is None and (has_refcount or has_ext)):
        debug = "d"
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


        abis.append(f"cp{version}")
    abis.insert(
        0,
        "cp{version}{debug}{pymalloc}{ucs4}".format(
            version=version, debug=debug, pymalloc=pymalloc, ucs4=ucs4
        ),
    )
    return abis


def cpython_tags(
    python_version: Optional[PythonVersion] = None,
    abis: Optional[Iterable[str]] = None,
    platforms: Optional[Iterable[str]] = None,
    *,
    warn: bool = False,
) -> Iterator[Tag]:
    if not python_version:
        python_version = sys.version_info[:2]

    interpreter = f"cp{_version_nodot(python_version[:2])}"

    if abis is None:
        if len(python_version) > 1:
            abis = _cpython_abis(python_version, warn)
        else:
            abis = []
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
    if _abi3_applies(python_version):
        yield from (Tag(interpreter, "abi3", platform_) for platform_ in platforms)
    yield from (Tag(interpreter, "none", platform_) for platform_ in platforms)

    if _abi3_applies(python_version):
        for minor_version in range(python_version[1] - 1, 1, -1):
            for platform_ in platforms:
                interpreter = "cp{version}".format(
                    version=_version_nodot((python_version[0], minor_version))
                )
                yield Tag(interpreter, "abi3", platform_)


def _generic_abi() -> Iterator[str]:
    abi = sysconfig.get_config_var("SOABI")
    if abi:
        yield _normalize_string(abi)


def generic_tags(
    interpreter: Optional[str] = None,
    abis: Optional[Iterable[str]] = None,
    platforms: Optional[Iterable[str]] = None,
    *,
    warn: bool = False,
) -> Iterator[Tag]:
    if not interpreter:
        interp_name = interpreter_name()
        interp_version = interpreter_version(warn=warn)
        interpreter = "".join([interp_name, interp_version])
    if abis is None:
        abis = _generic_abi()
    platforms = list(platforms or platform_tags())
    abis = list(abis)
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
    python_version: Optional[PythonVersion] = None,
    interpreter: Optional[str] = None,
    platforms: Optional[Iterable[str]] = None,
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


def _mac_binary_formats(version: MacVersion, cpu_arch: str) -> List[str]:
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
    version: Optional[MacVersion] = None, arch: Optional[str] = None
) -> Iterator[str]:
    version_str, _, cpu_arch = platform.mac_ver()
    if version is None:
        version = cast("MacVersion", tuple(map(int, version_str.split(".")[:2])))
    else:
        version = version
    if arch is None:
        arch = _mac_arch(cpu_arch)
    else:
        arch = arch

    if (10, 0) <= version and version < (11, 0):


        for minor_version in range(version[1], -1, -1):
            compat_version = 10, minor_version
            binary_formats = _mac_binary_formats(compat_version, arch)
            for binary_format in binary_formats:
                yield "macosx_{major}_{minor}_{binary_format}".format(
                    major=10, minor=minor_version, binary_format=binary_format
                )

    if version >= (11, 0):


        for major_version in range(version[0], 10, -1):
            compat_version = major_version, 0
            binary_formats = _mac_binary_formats(compat_version, arch)
            for binary_format in binary_formats:
                yield "macosx_{major}_{minor}_{binary_format}".format(
                    major=major_version, minor=0, binary_format=binary_format
                )

    if version >= (11, 0):


        if arch == "x86_64":
            for minor_version in range(16, 3, -1):
                compat_version = 10, minor_version
                binary_formats = _mac_binary_formats(compat_version, arch)
                for binary_format in binary_formats:
                    yield "macosx_{major}_{minor}_{binary_format}".format(
                        major=compat_version[0],
                        minor=compat_version[1],
                        binary_format=binary_format,
                    )
        else:
            for minor_version in range(16, 3, -1):
                compat_version = 10, minor_version
                binary_format = "universal2"
                yield "macosx_{major}_{minor}_{binary_format}".format(
                    major=compat_version[0],
                    minor=compat_version[1],
                    binary_format=binary_format,
                )


def _linux_platforms(is_32bit: bool = _32_BIT_INTERPRETER) -> Iterator[str]:
    linux = _normalize_string(sysconfig.get_platform())
    if is_32bit:
        if linux == "linux_x86_64":
            linux = "linux_i686"
        elif linux == "linux_aarch64":
            linux = "linux_armv7l"
    _, arch = linux.split("_", 1)
    yield from _manylinux.platform_tags(linux, arch)
    yield from _musllinux.platform_tags(arch)
    yield linux


def _generic_platforms() -> Iterator[str]:
    yield _normalize_string(sysconfig.get_platform())


def platform_tags() -> Iterator[str]:
    if platform.system() == "Darwin":
        return mac_platforms()
    elif platform.system() == "Linux":
        return _linux_platforms()
    else:
        return _generic_platforms()


def interpreter_name() -> str:
    name = sys.implementation.name
    return INTERPRETER_SHORT_NAMES.get(name) or name


def interpreter_version(*, warn: bool = False) -> str:
    version = _get_config_var("py_version_nodot", warn=warn)
    if version:
        version = str(version)
    else:
        version = _version_nodot(sys.version_info[:2])
    return version


def _version_nodot(version: PythonVersion) -> str:
    return "".join(map(str, version))


def sys_tags(*, warn: bool = False) -> Iterator[Tag]:

    interp_name = interpreter_name()
    if interp_name == "cp":
        yield from cpython_tags(warn=warn)
    else:
        yield from generic_tags()

    if interp_name == "pp":
        yield from compatible_tags(interpreter="pp3")
    else:
        yield from compatible_tags()
