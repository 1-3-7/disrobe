

from __future__ import absolute_import

from pex.interpreter_implementation import InterpreterImplementation
from pex.platforms import Platform
from pex.third_party.packaging import markers
from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Dict, Optional

    import attr
else:
    from pex.third_party import attr


def _convert_non_pep_440_dev_versions(python_full_version):
    # type: (Optional[str]) -> Optional[str]


    if python_full_version and python_full_version.endswith("+"):
        return python_full_version + "local"

    return python_full_version


@attr.s(frozen=True)
class MarkerEnvironment(object):

    @classmethod
    def default(cls):
        # type: () -> MarkerEnvironment
        return cls(**markers.default_environment())

    @classmethod
    def from_platform(cls, platform):
        # type: (Platform) -> MarkerEnvironment

        major_version = platform.version_info[0]

        implementation_name = None
        implementation_version = None

        if major_version == 2:
            # Python 2 does not expose the `sys.implementation` object which these values are


            implementation_name = ""
            implementation_version = "0"
        elif platform.impl == "cp":
            implementation_name = "cpython"
        elif platform.impl == "pp":
            implementation_name = "pypy"

        os_name = None
        platform_machine = None
        platform_system = None
        sys_platform = None

        if "linux" in platform.platform:
            os_name = "posix"
            if platform.platform.startswith(
                ("linux_", "manylinux1_", "manylinux2010_", "manylinux2014_")
            ):


                platform_machine = platform.platform.split("_", 1)[-1]
            else:


                platform_machine = platform.platform.split("_", 3)[-1]
            platform_system = "Linux"
            sys_platform = "linux2" if major_version == 2 else "linux"
        elif "mac" in platform.platform:
            os_name = "posix"


            platform_machine = platform.platform.split("_", 3)[-1]
            platform_system = "Darwin"
            sys_platform = "darwin"
        elif "win" in platform.platform:
            os_name = "nt"


            platform_machine = platform.platform.split("_", 2)[-1]
            platform_system = "Windows"
            sys_platform = "win32"

        platform_python_implementation = None
        for implementation in InterpreterImplementation.values():
            if implementation.abbr == platform.impl:
                platform_python_implementation = implementation.value

        python_version = ".".join(map(str, platform.version_info[:2]))

        python_full_version = None
        if len(platform.version_info) == 3:
            python_full_version = ".".join(map(str, platform.version_info))

        return cls(
            implementation_name=implementation_name,
            implementation_version=implementation_version,
            os_name=os_name,
            platform_machine=platform_machine,
            platform_python_implementation=platform_python_implementation,
            platform_release=None,
            platform_system=platform_system,
            platform_version=None,
            python_full_version=python_full_version,
            python_version=python_version,
            sys_platform=sys_platform,
        )

    implementation_name = attr.ib(default=None)
    implementation_version = attr.ib(default=None)
    os_name = attr.ib(default=None)
    platform_machine = attr.ib(default=None)
    platform_python_implementation = attr.ib(default=None)
    platform_release = attr.ib(default=None)
    platform_system = attr.ib(default=None)
    platform_version = attr.ib(default=None)
    python_full_version = attr.ib(
        default=None, converter=_convert_non_pep_440_dev_versions
    )
    python_version = attr.ib(default=None)
    sys_platform = attr.ib(default=None)

    def as_dict(self):
        # type: () -> Dict[str, str]
        return attr.asdict(self, filter=lambda _attribute, value: value is not None)
