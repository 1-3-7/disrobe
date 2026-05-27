import collections
import functools
import os
import re
import struct
import sys
import warnings
from typing import IO, Dict, Iterator, NamedTuple, Optional, Tuple


# Python does not provide platform information at sufficient granularity to


class _ELFFileHeader:

    class _InvalidELFFileHeader(ValueError):

    ELF_MAGIC_NUMBER = 0x7F454C46
    ELFCLASS32 = 1
    ELFCLASS64 = 2
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2
    EM_386 = 3
    EM_S390 = 22
    EM_ARM = 40
    EM_X86_64 = 62
    EF_ARM_ABIMASK = 0xFF000000
    EF_ARM_ABI_VER5 = 0x05000000
    EF_ARM_ABI_FLOAT_HARD = 0x00000400

    def __init__(self, file: IO[bytes]) -> None:
        def unpack(fmt: str) -> int:
            try:
                data = file.read(struct.calcsize(fmt))
                result: Tuple[int, ...] = struct.unpack(fmt, data)
            except struct.error:
                raise _ELFFileHeader._InvalidELFFileHeader()
            return result[0]

        self.e_ident_magic = unpack(">I")
        if self.e_ident_magic != self.ELF_MAGIC_NUMBER:
            raise _ELFFileHeader._InvalidELFFileHeader()
        self.e_ident_class = unpack("B")
        if self.e_ident_class not in {self.ELFCLASS32, self.ELFCLASS64}:
            raise _ELFFileHeader._InvalidELFFileHeader()
        self.e_ident_data = unpack("B")
        if self.e_ident_data not in {self.ELFDATA2LSB, self.ELFDATA2MSB}:
            raise _ELFFileHeader._InvalidELFFileHeader()
        self.e_ident_version = unpack("B")
        self.e_ident_osabi = unpack("B")
        self.e_ident_abiversion = unpack("B")
        self.e_ident_pad = file.read(7)
        format_h = "<H" if self.e_ident_data == self.ELFDATA2LSB else ">H"
        format_i = "<I" if self.e_ident_data == self.ELFDATA2LSB else ">I"
        format_q = "<Q" if self.e_ident_data == self.ELFDATA2LSB else ">Q"
        format_p = format_i if self.e_ident_class == self.ELFCLASS32 else format_q
        self.e_type = unpack(format_h)
        self.e_machine = unpack(format_h)
        self.e_version = unpack(format_i)
        self.e_entry = unpack(format_p)
        self.e_phoff = unpack(format_p)
        self.e_shoff = unpack(format_p)
        self.e_flags = unpack(format_i)
        self.e_ehsize = unpack(format_h)
        self.e_phentsize = unpack(format_h)
        self.e_phnum = unpack(format_h)
        self.e_shentsize = unpack(format_h)
        self.e_shnum = unpack(format_h)
        self.e_shstrndx = unpack(format_h)


def _get_elf_header() -> Optional[_ELFFileHeader]:
    try:
        with open(sys.executable, "rb") as f:
            elf_header = _ELFFileHeader(f)
    except (OSError, TypeError, _ELFFileHeader._InvalidELFFileHeader):
        return None
    return elf_header


def _is_linux_armhf() -> bool:


    elf_header = _get_elf_header()
    if elf_header is None:
        return False
    result = elf_header.e_ident_class == elf_header.ELFCLASS32
    result &= elf_header.e_ident_data == elf_header.ELFDATA2LSB
    result &= elf_header.e_machine == elf_header.EM_ARM
    result &= (
        elf_header.e_flags & elf_header.EF_ARM_ABIMASK
    ) == elf_header.EF_ARM_ABI_VER5
    result &= (
        elf_header.e_flags & elf_header.EF_ARM_ABI_FLOAT_HARD
    ) == elf_header.EF_ARM_ABI_FLOAT_HARD
    return result


def _is_linux_i686() -> bool:
    elf_header = _get_elf_header()
    if elf_header is None:
        return False
    result = elf_header.e_ident_class == elf_header.ELFCLASS32
    result &= elf_header.e_ident_data == elf_header.ELFDATA2LSB
    result &= elf_header.e_machine == elf_header.EM_386
    return result


def _have_compatible_abi(arch: str) -> bool:
    if arch == "armv7l":
        return _is_linux_armhf()
    if arch == "i686":
        return _is_linux_i686()
    return arch in {"x86_64", "aarch64", "ppc64", "ppc64le", "s390x"}


_LAST_GLIBC_MINOR: Dict[int, int] = collections.defaultdict(lambda: 50)


class _GLibCVersion(NamedTuple):
    major: int
    minor: int


def _glibc_version_string_confstr() -> Optional[str]:


    try:

        version_string = os.confstr("CS_GNU_LIBC_VERSION")
        assert version_string is not None
        _, version = version_string.split()
    except (AssertionError, AttributeError, OSError, ValueError):

        return None
    return version


def _glibc_version_string_ctypes() -> Optional[str]:
    try:
        import ctypes
    except ImportError:
        return None


    try:
        process_namespace = ctypes.CDLL(None)
    except OSError:
        return None

    try:
        gnu_get_libc_version = process_namespace.gnu_get_libc_version
    except AttributeError:


        return None


    gnu_get_libc_version.restype = ctypes.c_char_p
    version_str: str = gnu_get_libc_version()

    if not isinstance(version_str, str):
        version_str = version_str.decode("ascii")

    return version_str


def _glibc_version_string() -> Optional[str]:
    return _glibc_version_string_confstr() or _glibc_version_string_ctypes()


def _parse_glibc_version(version_str: str) -> Tuple[int, int]:
    m = re.match(r"(?P<major>[0-9]+)\.(?P<minor>[0-9]+)", version_str)
    if not m:
        warnings.warn(
            "Expected glibc version with 2 components major.minor,"
            " got: %s" % version_str,
            RuntimeWarning,
        )
        return -1, -1
    return int(m.group("major")), int(m.group("minor"))


@functools.lru_cache()
def _get_glibc_version() -> Tuple[int, int]:
    version_str = _glibc_version_string()
    if version_str is None:
        return (-1, -1)
    return _parse_glibc_version(version_str)


def _is_compatible(name: str, arch: str, version: _GLibCVersion) -> bool:
    sys_glibc = _get_glibc_version()
    if sys_glibc < version:
        return False

    try:
        import _manylinux
    except ImportError:
        return True
    if hasattr(_manylinux, "manylinux_compatible"):
        result = _manylinux.manylinux_compatible(version[0], version[1], arch)
        if result is not None:
            return bool(result)
        return True
    if version == _GLibCVersion(2, 5):
        if hasattr(_manylinux, "manylinux1_compatible"):
            return bool(_manylinux.manylinux1_compatible)
    if version == _GLibCVersion(2, 12):
        if hasattr(_manylinux, "manylinux2010_compatible"):
            return bool(_manylinux.manylinux2010_compatible)
    if version == _GLibCVersion(2, 17):
        if hasattr(_manylinux, "manylinux2014_compatible"):
            return bool(_manylinux.manylinux2014_compatible)
    return True


_LEGACY_MANYLINUX_MAP = {

    (2, 17): "manylinux2014",

    (2, 12): "manylinux2010",

    (2, 5): "manylinux1",
}


def platform_tags(linux: str, arch: str) -> Iterator[str]:
    if not _have_compatible_abi(arch):
        return

    too_old_glibc2 = _GLibCVersion(2, 16)
    if arch in {"x86_64", "i686"}:

        too_old_glibc2 = _GLibCVersion(2, 4)
    current_glibc = _GLibCVersion(*_get_glibc_version())
    glibc_max_list = [current_glibc]


    for glibc_major in range(current_glibc.major - 1, 1, -1):
        glibc_minor = _LAST_GLIBC_MINOR[glibc_major]
        glibc_max_list.append(_GLibCVersion(glibc_major, glibc_minor))
    for glibc_max in glibc_max_list:
        if glibc_max.major == too_old_glibc2.major:
            min_minor = too_old_glibc2.minor
        else:

            min_minor = -1
        for glibc_minor in range(glibc_max.minor, min_minor, -1):
            glibc_version = _GLibCVersion(glibc_max.major, glibc_minor)
            tag = "manylinux_{}_{}".format(*glibc_version)
            if _is_compatible(tag, arch, glibc_version):
                yield linux.replace("linux", tag)

            if glibc_version in _LEGACY_MANYLINUX_MAP:
                legacy_tag = _LEGACY_MANYLINUX_MAP[glibc_version]
                if _is_compatible(legacy_tag, arch, glibc_version):
                    yield linux.replace("linux", legacy_tag)
