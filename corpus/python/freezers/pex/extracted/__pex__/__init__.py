

import os
import sys

TYPE_CHECKING = False

if TYPE_CHECKING:
    from typing import Any, List, NoReturn, Optional, Tuple


if sys.version_info >= (3, 10):

    def orig_argv():
        # type: () -> Optional[List[str]]
        return sys.orig_argv

else:
    try:
        import ctypes


        from ctypes import pythonapi

        def orig_argv():
            # type: () -> Optional[List[str]]


            argv = ctypes.POINTER(
                ctypes.c_char_p if sys.version_info[0] == 2 else ctypes.c_wchar_p
            )()

            argc = ctypes.c_int()
            pythonapi.Py_GetArgcArgv(ctypes.byref(argc), ctypes.byref(argv))


            return [argv[i] for i in range(argc.value)]

    except ImportError:

        def orig_argv():
            # type: () -> Optional[List[str]]
            return None


def __re_exec__(
    python,
    python_args,
    *extra_python_args
):
    # type: (...) -> NoReturn

    from pex.os import safe_execv

    argv = [python]
    argv.extend(python_args)
    argv.extend(extra_python_args)

    safe_execv(argv + sys.argv[1:])


__SHOULD_EXECUTE__ = __name__ == "__main__"


def __entry_point_from_filename__(filename):
    # type: (str) -> str


    entry_point = os.path.dirname(filename)
    if __SHOULD_EXECUTE__:
        return entry_point
    return os.path.dirname(entry_point)


__INSTALLED_FROM__ = "__PEX_EXE__"


def __ensure_pex_installed__(
    pex,
    pex_root,
    pex_hash,
    python_args,
):
    # type: (...) -> Optional[str]

    from pex.layout import ensure_installed
    from pex.tracer import TRACER

    installed_location = ensure_installed(pex=pex, pex_root=pex_root, pex_hash=pex_hash)
    if not __SHOULD_EXECUTE__ or pex == installed_location:
        return installed_location


    os.environ[__INSTALLED_FROM__] = pex

    TRACER.log(
        "Executing installed PEX for {pex} at {installed_location}".format(
            pex=pex, installed_location=installed_location
        )
    )
    __re_exec__(sys.executable, python_args, installed_location)


def __maybe_run_venv__(
    pex,
    pex_root,
    pex_hash,
    has_interpreter_constraints,
    pex_path,
    python_args,
):
    # type: (...) -> Optional[str]

    from pex.os import is_exe
    from pex.tracer import TRACER
    from pex.variables import venv_dir

    venv_root_dir = venv_dir(
        pex_root=pex_root,
        pex_hash=pex_hash,
        has_interpreter_constraints=has_interpreter_constraints,
        pex_file=pex,
        pex_path=pex_path,
    )
    venv_pex = os.path.join(venv_root_dir, "pex")
    if not __SHOULD_EXECUTE__ or not is_exe(venv_pex):


        return venv_root_dir

    TRACER.log("Executing venv PEX for {pex} at {venv_pex}".format(pex=pex, venv_pex=venv_pex))
    with open(venv_pex) as fp:
        shebang = fp.readline()
    venv_python, _, extra_python_args = shebang[2:].strip().partition(" ")
    if extra_python_args:
        __re_exec__(venv_python, python_args, extra_python_args, venv_pex)
    else:
        __re_exec__(venv_python, python_args, venv_pex)


def boot(
    bootstrap_dir,
    pex_root,
    pex_hash,
    hermetic_boot,
    has_interpreter_constraints,
    pex_path,
    is_venv,
    inject_python_args,
):
    # type: (...) -> Tuple[Any, bool, bool]

    entry_point = None
    __file__ = globals().get("__file__")
    __loader__ = globals().get("__loader__")
    if __file__ is not None and os.path.exists(__file__):
        entry_point = __entry_point_from_filename__(__file__)
    elif __loader__ is not None:
        if hasattr(__loader__, "archive"):
            entry_point = __loader__.archive
        elif hasattr(__loader__, "get_filename"):


            entry_point = __entry_point_from_filename__(__loader__.get_filename())

    if entry_point is None:
        sys.stderr.write("Could not launch python executable!\\n")
        return 2, True, False

    python_args = list(inject_python_args)
    orig_args = orig_argv()
    if orig_args is not None:
        orig_python_args = []
        for index, arg in enumerate(orig_args[1:], start=1):
            if os.path.exists(arg) and os.path.samefile(entry_point, arg):
                orig_python_args = orig_args[1:index]
                break
        python_args.extend(orig_python_args)


        if (
            "PYTHONPATH" in os.environ
            and __SHOULD_EXECUTE__
            and hermetic_boot
            and os.environ.get("PEX_INHERIT_PATH", "false") == "false"
        ):
            re_exec = False
            if sys.version_info[:2] >= (3, 4):
                if "-I" not in orig_python_args:
                    python_args.append("-I")
                    re_exec = True
            else:
                has_hermetic_args = (
                    ("-s" in orig_python_args and "-E" in orig_python_args)
                    or "-sE" in orig_python_args
                    or "-Es" in orig_python_args
                )
                if not has_hermetic_args:
                    python_args.append("-sE")
                    re_exec = True
            if re_exec:
                args = [sys.executable]
                args.extend(python_args)
                args.append(entry_point)
                args.extend(sys.argv[1:])
                if os.name == "nt":
                    import subprocess

                    sys.exit(subprocess.call(args=args))
                else:
                    os.execv(args[0], args)

    installed_from = os.environ.pop(__INSTALLED_FROM__, None)
    if installed_from:
        if os.path.isfile(installed_from):
            sys.argv[0] = installed_from
        else:
            pex_exe = os.path.join(installed_from, "pex")
            if os.path.isfile(pex_exe):
                sys.argv[0] = pex_exe

    overridden_pex = os.environ.get("__PEX_EXE__", None)
    sys.path[0] = os.path.abspath(sys.path[0])
    sys.path.insert(0, os.path.abspath(os.path.join(overridden_pex or entry_point, bootstrap_dir)))

    overridden_entry_point = os.environ.get("__PEX_ENTRY_POINT__", None)
    if overridden_entry_point and overridden_entry_point != entry_point:


        __re_exec__(sys.executable, python_args, overridden_entry_point)

    venv_dir = None
    if not installed_from:
        os.environ["PEX"] = os.path.realpath(entry_point)
        from pex.variables import ENV, Variables

        pex_root = Variables.PEX_ROOT.value_or(ENV, pex_root)

        if not ENV.PEX_TOOLS and Variables.PEX_VENV.value_or(ENV, is_venv):
            venv_dir = __maybe_run_venv__(
                pex=entry_point,
                pex_root=pex_root,
                pex_hash=pex_hash,
                has_interpreter_constraints=has_interpreter_constraints,
                pex_path=ENV.PEX_PATH or pex_path,
                python_args=python_args,
            )
        entry_point = __ensure_pex_installed__(
            pex=entry_point, pex_root=pex_root, pex_hash=pex_hash, python_args=python_args
        )
        if entry_point is None:

            return 0, True, False
    else:
        os.environ["PEX"] = os.path.realpath(installed_from)

    from pex.globals import Globals
    from pex.pex_bootstrapper import bootstrap_pex

    result = bootstrap_pex(
        entry_point, python_args=python_args, execute=__SHOULD_EXECUTE__, venv_dir=venv_dir
    )
    should_exit = __SHOULD_EXECUTE__ and "PYTHONINSPECT" not in os.environ
    is_globals = isinstance(result, Globals)
    return result, should_exit, is_globals


result, should_exit, is_globals = boot(
    bootstrap_dir='.bootstrap',
    pex_root='~\\AppData\\Local\\pex\\Cache',
    pex_hash='deea4c899518782efb3b5a11257bd840b8246152',
    hermetic_boot=True,
    has_interpreter_constraints=False,
    pex_path=(),
    is_venv=False,
    inject_python_args=(),
)
if should_exit:
    sys.exit(0 if is_globals else result)
elif is_globals:
    globals().update(result)
