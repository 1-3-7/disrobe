

from __future__ import absolute_import, print_function

import itertools
import os
import shlex
from textwrap import dedent

from pex import dist_metadata, variables
from pex.compatibility import shlex_quote
from pex.dist_metadata import Distribution
from pex.interpreter import PythonInterpreter
from pex.interpreter_constraints import InterpreterConstraints, iter_compatible_versions
from pex.interpreter_implementation import InterpreterImplementation
from pex.layout import Layout
from pex.orderedset import OrderedSet
from pex.os import WINDOWS
from pex.pep_440 import Version
from pex.pex_info import PexInfo
from pex.targets import Targets
from pex.third_party.packaging.specifiers import SpecifierSet
from pex.typing import TYPE_CHECKING
from pex.version import __version__

if TYPE_CHECKING:
    from typing import Iterable, List, Optional, Tuple

    import attr
else:
    from pex.third_party import attr


@attr.s(frozen=True)
class PythonBinaryName(object):
    implementation = attr.ib()
    version = attr.ib()

    def render(self, version_components=2):
        # type: (int) -> str
        return self.implementation.calculate_binary_name(self.version[:version_components])


def _calculate_applicable_binary_names(
    targets,
    interpreter_constraints,
):
    # type: (...) -> Iterable[str]


    ic_majors_minors = OrderedSet()
    if interpreter_constraints:
        ic_majors_minors.update(
            PythonBinaryName(implementation=implementation, version=version)
            for interpreter_constraint in interpreter_constraints
            for version in iter_compatible_versions(
                requires_python=[interpreter_constraint.specifier]
            )
            for implementation in (
                (interpreter_constraint.implementation,)
                if interpreter_constraint.implementation
                else tuple(
                    implementation
                    for implementation in InterpreterImplementation.values()
                    if implementation.applies(version)
                )
            )
        )


    only_explicit = len(ic_majors_minors) > 0

    names = OrderedSet()

    for target in targets.unique_targets(only_explicit=only_explicit):
        if target.implementation and target.python_version is not None:
            names.add(
                PythonBinaryName(
                    implementation=target.implementation, version=target.python_version
                )
            )


    names.update(ic_majors_minors)


    pex_requires_python_override = os.environ.get("_PEX_REQUIRES_PYTHON", None)
    if pex_requires_python_override:
        pex_requires_python = SpecifierSet(pex_requires_python_override)
    else:
        pex_requires_python = SpecifierSet(">=2.7")
        dist = dist_metadata.find_distribution("pex")
        if dist and dist.metadata.version == Version(__version__):
            pex_requires_python = dist.metadata.requires_python
    pex_supported_python_versions = tuple(
        reversed(list(iter_compatible_versions(requires_python=[pex_requires_python])))
    )


    names.update(
        PythonBinaryName(implementation=implementation, version=version)
        for version in pex_supported_python_versions
        for implementation in (
            InterpreterImplementation.CPYTHON,
            InterpreterImplementation.CPYTHON_FREE_THREADED,
        )
        if implementation.applies(version)
    )
    names.update(
        PythonBinaryName(implementation=InterpreterImplementation.PYPY, version=version)
        for version in pex_supported_python_versions
        if InterpreterImplementation.PYPY.applies(version)
    )


    return OrderedSet(
        itertools.chain(
            (name.render(version_components=2) for name in names),
            (name.render(version_components=1) for name in names),
            (name.render(version_components=0) for name in names),
        )
    )


def create_sh_boot_script(
    pex_name,
    pex_info,
    targets,
    interpreter,
    python_shebang=None,
    layout=Layout.ZIPAPP,
):
    # type: (...) -> str
    python = ""
    python_args = list(pex_info.inject_python_args)
    if python_shebang:
        shebang = python_shebang[2:] if python_shebang.startswith("#!") else python_shebang

        args = list(
            itertools.dropwhile(
                lambda word: not PythonInterpreter.matches_binary_name(word),
                shlex.split(shebang, posix=not WINDOWS),
            )
        )
        python = args[0]
        python_args.extend(args[1:])
    venv_python_args = python_args[:]
    if pex_info.venv_hermetic_scripts:
        venv_python_args.append(interpreter.hermetic_args)

    python_names = tuple(
        _calculate_applicable_binary_names(
            targets=targets,
            interpreter_constraints=pex_info.interpreter_constraints,
        )
    )

    venv_dir = pex_info.raw_venv_dir(pex_file=pex_name, interpreter=interpreter)
    if venv_dir:
        pex_installed_path = venv_dir.path
    else:
        pex_hash = pex_info.pex_hash
        if pex_hash is None:
            raise ValueError("Expected pex_hash to be set already in PEX-INFO.")
        pex_installed_path = variables.unzip_dir(
            pex_info.raw_pex_root, pex_hash, expand_pex_root=False
        )


    vars_for_no_fast_path = [

        "PEX_IGNORE_RCFILES",


        "PEX_VENV",


        "PEX_PYTHON",
        "PEX_PYTHON_PATH",
        "PEX_PATH",


        "PEX_TOOLS",


    ]

    return dedent(
        """\
        # N.B.: This script should stick to syntax defined for POSIX `sh` and avoid non-builtins.
        # See: https://pubs.opengroup.org/onlinepubs/9699919799/idx/shell.html
        set -eu

        VENV="{venv}"
        VENV_PYTHON_ARGS="{venv_python_args}"

        # N.B.: This ensures tilde-expansion of the DEFAULT_PEX_ROOT value.
        DEFAULT_PEX_ROOT="$(echo {pex_root})"

        DEFAULT_PYTHON="{python}"
        PYTHON_ARGS="{python_args}"

        PEX_ROOT="${{PEX_ROOT:-${{DEFAULT_PEX_ROOT}}}}"
        INSTALLED_PEX="${{PEX_ROOT}}/{pex_installed_relpath}"

        if [ -n "${{VENV}}" -a -x "${{INSTALLED_PEX}}" -a {check_no_fast_path} ]; then
            # We're a --venv execution mode PEX installed under the PEX_ROOT and the venv
            # interpreter to use is embedded in the shebang of our venv pex script; so just
            # execute that script directly... except if we're executing in a non-default manner,
            # where we'll likely need to execute PEX code.
            export PEX="{pex}"
            exec "${{INSTALLED_PEX}}/bin/python" ${{VENV_PYTHON_ARGS}} "${{INSTALLED_PEX}}" \\
                "$@"
        fi

        find_python() {{
            for python in \\
        {pythons} \\
            ; do
                if command -v "${{python}}" 2>/dev/null; then
                    return
                fi
            done
        }}

        if [ -x "${{DEFAULT_PYTHON}}" ]; then
            python_exe="${{DEFAULT_PYTHON}}"
        else
            python_exe="$(find_python)"
        fi
        if [ -n "${{python_exe}}" ]; then
            if [ -n "${{PEX_VERBOSE:-}}" ]; then
                echo >&2 "$0 used /bin/sh boot to select python: ${{python_exe}} for re-exec..."
            fi
            if [ -z "${{VENV}}" -a -e "${{INSTALLED_PEX}}" ]; then
                # We're a --zipapp execution mode PEX installed under the PEX_ROOT with a
                # __main__.py in our top-level directory; so execute Python against that
                # directory.
                export __PEX_EXE__="{pex}"
                exec "${{python_exe}}" ${{PYTHON_ARGS}} "${{INSTALLED_PEX}}" "$@"
            else
                # The slow path: this PEX zipapp is not installed yet. Run the PEX zipapp so it
                # can install itself, rebuilding its fast path layout under the PEX_ROOT.
                if [ -n "${{PEX_VERBOSE:-}}" ]; then
                    echo >&2 "Running zipapp pex to lay itself out under PEX_ROOT."
                fi
                exec "${{python_exe}}" ${{PYTHON_ARGS}} "$0" "$@"
            fi
        fi

        echo >&2 "Failed to find any of these python binaries on the PATH:"
        for python in \\
        {pythons} \\
        ; do
            echo >&2 "${{python}}"
        done
        echo >&2 'Either adjust your $PATH which is currently:'
        echo >&2 "${{PATH}}"
        echo >&2 -n "Or else install an appropriate Python that provides one of the binaries in "
        echo >&2 "this list."
        exit 1
        """
    ).format(
        venv="1" if pex_info.venv else "",
        python=python,
        python_args=" ".join(shlex_quote(python_arg) for python_arg in python_args),
        pythons=" \\\n".join('"{python}"'.format(python=python) for python in python_names),
        pex_root=pex_info.raw_pex_root,
        pex_installed_relpath=os.path.relpath(pex_installed_path, pex_info.raw_pex_root),
        venv_python_args=" ".join(
            shlex_quote(venv_python_arg) for venv_python_arg in venv_python_args
        ),
        pex="$0" if layout is Layout.ZIPAPP else '$(dirname "$0")',
        check_no_fast_path=" -a ".join(
            '-z "${{{env_var_name}:-}}"'.format(env_var_name=name) for name in vars_for_no_fast_path
        ),
    )
