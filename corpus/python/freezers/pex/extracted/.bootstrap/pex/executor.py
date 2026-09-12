

from __future__ import absolute_import

import errno
import os

from pex.compatibility import PY2, string
from pex.tracer import TRACER

if os.name == "posix" and PY2:
    try:

        import subprocess32 as subprocess
    except ImportError:
        TRACER.log(
            "Please build pex with the subprocess32 module for more reliable requirement "
            "installation and interpreter execution."
        )
        import subprocess
else:
    import subprocess


class Executor(object):

    class ExecutionError(Exception):

        def __init__(self, msg, cmd, exc=None):
            super(Executor.ExecutionError, self).__init__(
                "%s while trying to execute `%s`" % (msg, cmd)
            )
            self.executable = cmd.split()[0] if isinstance(cmd, string) else cmd[0]
            self.cmd = cmd
            self.exc = exc

    class NonZeroExit(ExecutionError):

        def __init__(self, cmd, exit_code, stdout, stderr):
            super(Executor.NonZeroExit, self).__init__(
                "received exit code %s during execution of `%s`" % (exit_code, cmd), cmd
            )
            self.exit_code = exit_code
            self.stdout = stdout
            self.stderr = stderr

    class ExecutableNotFound(ExecutionError):

        def __init__(self, cmd, exc):
            super(Executor.ExecutableNotFound, self).__init__(
                "caught %r while trying to execute `%s`" % (exc, cmd), cmd
            )
            self.exc = exc

    @classmethod
    def open_process(cls, cmd, **kwargs):
        assert len(cmd) > 0, "cannot execute an empty command!"

        try:
            return subprocess.Popen(cmd, **kwargs)
        except (IOError, OSError) as e:
            if e.errno == errno.ENOENT:
                raise cls.ExecutableNotFound(cmd, e)
            else:
                raise cls.ExecutionError(repr(e), cmd, e)

    @classmethod
    def execute(cls, cmd, stdin_payload=None, **kwargs):
        process = cls.open_process(
            cmd=cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs
        )
        stdout_raw, stderr_raw = process.communicate(input=stdin_payload)

        stdout = stdout_raw.decode("utf-8") if stdout_raw is not None else stdout_raw
        stderr = stderr_raw.decode("utf-8") if stderr_raw is not None else stderr_raw

        if process.returncode != 0:
            raise cls.NonZeroExit(cmd, process.returncode, stdout, stderr)

        return stdout, stderr
