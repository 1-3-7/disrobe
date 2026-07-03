

from __future__ import absolute_import

import errno
import functools
import multiprocessing
import os
import subprocess
import time
from abc import abstractmethod
from collections import defaultdict
from contextlib import contextmanager
from threading import BoundedSemaphore, Event, Thread

from pex.common import pluralize
from pex.compatibility import Queue, cpu_count
from pex.tracer import TRACER
from pex.typing import TYPE_CHECKING, Generic

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        DefaultDict,
        Iterable,
        Iterator,
        List,
        Optional,
        Protocol,
        Text,
        Tuple,
        TypeVar,
        Union,
    )

    import attr

    _I = TypeVar("_I")
    _O = TypeVar("_O")
    _T = TypeVar("_T")
    _S = TypeVar("_S")
    _SE = TypeVar("_SE")
    _JE = TypeVar("_JE")
else:
    from pex.third_party import attr


class Job(object):

    class Error(Exception):

        def __init__(
            self,
            pid,
            command,
            exitcode,
            stderr,
            message,
            context=None,
        ):
            # type: (...) -> None
            super(Job.Error, self).__init__(
                "{ctx}: {msg}".format(ctx=context, msg=message) if context else message
            )
            self.pid = pid
            self.command = command
            self.exitcode = exitcode
            self.stderr = stderr
            self._context = context

        def contextualized_stderr(self):
            # type: () -> Iterator[Text]
            if self.stderr:
                for line in self.stderr.splitlines():
                    if not self._context:
                        yield line
                    else:
                        yield "{ctx}: {line}".format(ctx=self._context, line=line)

    def __init__(
        self,
        command,
        process,
        finalizer=None,
        context=None,
    ):
        # type: (...) -> None
        self._command = tuple(command)
        self._process = process
        self._finalizer = finalizer
        self._context = context

    def wait(self):
        # type: () -> None
        try:
            _, stderr = self._process.communicate()
            self._check_returncode(stderr)
        finally:
            self._finalize_job()

    def communicate(self, input=None):
        # type: (Optional[bytes]) -> Tuple[bytes, bytes]
        try:
            stdout, stderr = self._process.communicate(input=input)
            self._check_returncode(stderr)
            return stdout, stderr
        finally:
            self._finalize_job()

    def kill(self):
        # type: () -> None
        try:
            self._process.kill()
        except OSError as e:
            if e.errno != errno.ESRCH:
                raise e
        finally:
            self._finalize_job()

    def create_error(
        self,
        msg,
        stderr=None,
    ):
        # type: (...) -> Job.Error
        err = None
        if stderr:
            err = stderr.decode("utf-8")
            msg += "\nSTDERR:\n{}".format(err)
        raise self.Error(
            pid=self._process.pid,
            command=self._command,
            exitcode=self._process.returncode,
            stderr=err,
            message=msg,
            context=self._context,
        )

    def _finalize_job(self):
        if self._finalizer is not None:
            self._finalizer(self._process.returncode)
            self._finalizer = None

    def _check_returncode(self, stderr=None):
        # type: (Optional[bytes]) -> None
        if self._process.returncode != 0:
            msg = "Executing {} failed with {}".format(
                " ".join(self._command), self._process.returncode
            )
            raise self.create_error(msg, stderr=stderr)

    def __str__(self):
        # type: () -> str
        return "pid: {pid} -> {command}".format(
            pid=self._process.pid, command=" ".join(self._command)
        )


class SpawnedJob(Generic["_T"]):

    @classmethod
    def completed(cls, result):
        # type: (_T) -> SpawnedJob[_T]

        class Completed(SpawnedJob):
            def await_result(self):
                # type: () -> _T
                return result

            def kill(self):
                # type: () -> None
                pass

            def __repr__(self):
                # type: () -> str
                return "SpawnedJob.completed({!r})".format(result)

        return Completed()

    @classmethod
    def wait(
        cls,
        job,
        result,
    ):
        # type: (...) -> SpawnedJob[_T]
        return cls.and_then(job, lambda: result)

    @classmethod
    def and_then(
        cls,
        job,
        result_func,
    ):
        # type: (...) -> SpawnedJob[_T]

        class AndThen(SpawnedJob):
            def await_result(self):
                # type: () -> _T
                job.wait()
                return result_func()

            def kill(self):
                # type: () -> None
                job.kill()

            def __repr__(self):
                # type: () -> str
                return "SpawnedJob.and_then({!r})".format(job)

        return AndThen()

    @classmethod
    def stdout(
        cls,
        job,
        result_func,
        input=None,
    ):
        # type: (...) -> SpawnedJob[_T]

        class Stdout(SpawnedJob):
            def await_result(self):
                # type: () -> _T
                stdout, _ = job.communicate(input=input)
                return result_func(stdout)

            def kill(self):
                # type: () -> None
                job.kill()

            def __repr__(self):
                # type: () -> str
                return "SpawnedJob.stdout({!r})".format(job)

        return Stdout()

    @classmethod
    def file(
        cls,
        job,
        output_file,
        result_func,
        input=None,
    ):
        # type: (...) -> SpawnedJob[_T]

        def _read_file(stderr=None):
            # type: (Optional[bytes]) -> bytes
            try:
                with open(output_file, "rb") as fp:
                    return fp.read()
            except (OSError, IOError) as e:
                raise job.create_error(
                    "Expected job to create file {output_file!r} but it did not exist or could not "
                    "be read: {err}".format(output_file=output_file, err=e),
                    stderr=stderr,
                )

        class File(SpawnedJob):
            def await_result(self):
                # type: () -> _T
                _, stderr = job.communicate(input=input)
                return result_func(_read_file(stderr=stderr))

            def kill(self):
                # type: () -> None
                job.kill()

            def __repr__(self):
                # type: () -> str
                return "SpawnedJob.file({job!r}, output_file={output_file!r})".format(
                    job=job, output_file=output_file
                )

        return File()

    def await_result(self):
        # type: () -> _T
        raise NotImplementedError()

    def kill(self):
        # type: () -> None
        raise NotImplementedError()

    def map(self, func):
        # type: (Callable[[_T], _S]) -> SpawnedJob[_S]

        class Map(SpawnedJob):
            def await_result(me):
                # type: () -> _S
                return func(self.await_result())

            def kill(me):
                # type: () -> None
                self.kill()

            def __repr__(me):
                # type: () -> str
                return "{job}.map({func})".format(job=self, func=func)

        return Map()

    def or_else(self, func):
        # type: (Callable[[Job.Error], SpawnedJob[_T]]) -> SpawnedJob[_T]

        class OrElse(SpawnedJob):
            def await_result(me):
                # type: () -> _T
                try:
                    return self.await_result()
                except Job.Error as e:
                    return func(e).await_result()

            def kill(me):
                # type: () -> None
                self.kill()

            def __repr__(me):
                # type: () -> str
                return "{job}.or_else({func})".format(job=self, func=func)

        return OrElse()


_CPU_COUNT = cpu_count() or 2
_ABSOLUTE_MAX_JOBS = _CPU_COUNT * 2


DEFAULT_MAX_JOBS = _CPU_COUNT
"""The default maximum number of parallel jobs PEX should use."""


def _sanitize_max_jobs(max_jobs=None):
    # type: (Optional[int]) -> int
    if max_jobs is None or max_jobs <= 0:
        return DEFAULT_MAX_JOBS
    else:
        return min(max_jobs, _ABSOLUTE_MAX_JOBS)


class ErrorHandler(Generic["_I", "_SE", "_JE"]):

    @classmethod
    def spawn_error_message(
        cls,
        item,
        exception,
    ):
        # type: (...) -> str
        return "Failed to spawn a job for {item}: {exception}".format(
            item=item, exception=exception
        )

    @classmethod
    def job_error_message(
        cls,
        _item,
        job_error,
    ):
        # type: (...) -> str
        return "pid {pid} -> {command} exited with {exitcode} and STDERR:\n{stderr}".format(
            pid=job_error.pid,
            command=" ".join(job_error.command),
            exitcode=job_error.exitcode,
            stderr="\n".join(job_error.contextualized_stderr()),
        )

    @abstractmethod
    def handle_spawn_error(
        self,
        item,
        exception,
    ):
        # type: (...) -> _SE

    @abstractmethod
    def handle_job_error(
        self,
        item,
        job_error,
    ):
        # type: (...) -> _JE


class Raise(ErrorHandler["_I", "_O", "_O"], Generic["_I", "_O"]):

    def __init__(self, raise_type):
        self._raise_type = raise_type

    def handle_spawn_error(self, item, exception):
        raise self._raise_type(self.spawn_error_message(item, exception))

    def handle_job_error(self, item, job_error):
        raise self._raise_type(self.job_error_message(item, job_error))


class Retain(ErrorHandler["_I", "Tuple[_I, Exception]", "Tuple[_I, Job.Error]"], Generic["_I"]):

    def handle_spawn_error(self, item, exception):
        return item, exception

    def handle_job_error(self, item, job_error):
        return item, job_error


class Log(ErrorHandler["_I", "_O", "_O"], Generic["_I", "_O"]):

    def handle_spawn_error(self, item, exception):
        TRACER.log(self.spawn_error_message(item, exception))
        return None

    def handle_job_error(self, item, job_error):
        TRACER.log(self.job_error_message(item, job_error))
        return None


def execute_parallel(
    inputs,
    spawn_func,
    error_handler=None,
    max_jobs=None,
):
    # type: (...) -> Iterator[Union[_O, _SE, _JE]]
    handler = (
        error_handler or Log["_I", "_O"]()
    )
    size = _sanitize_max_jobs(max_jobs)
    TRACER.log(
        "Spawning a maximum of {} parallel jobs to process:\n  {}".format(
            size, "\n  ".join(map(str, inputs))
        ),
        V=9,
    )

    @attr.s(frozen=True)
    class Spawn(object):
        item = attr.ib()
        spawned_job = attr.ib()

    @attr.s(frozen=True)
    class SpawnError(object):
        item = attr.ib()
        error = attr.ib()

    stop = Event()
    job_slots = BoundedSemaphore(value=size)

    class DoneSentinel(object):
        pass

    done_sentinel = DoneSentinel()
    spawn_queue = Queue()

    def spawn_jobs():
        for item in inputs:
            if stop.is_set():
                break
            job_slots.acquire()
            try:
                result = Spawn(item, spawn_func(item))
            except Exception as e:
                result = SpawnError(item, e)
            finally:
                spawn_queue.put(result)
        spawn_queue.put(done_sentinel)

    @contextmanager
    def spawned_jobs():
        spawner = Thread(name="PEX Parallel Job Spawner", target=spawn_jobs)
        spawner.daemon = True
        spawner.start()
        try:
            yield
        finally:
            stop.set()


            try:
                job_slots.release()
            except ValueError:


                pass
            spawner.join()

    with spawned_jobs():
        error = None
        while True:
            spawn_result = spawn_queue.get()

            if isinstance(spawn_result, DoneSentinel):
                if error:
                    raise error
                return

            try:
                if isinstance(spawn_result, SpawnError):
                    try:
                        se_result = handler.handle_spawn_error(
                            spawn_result.item, spawn_result.error
                        )
                        if se_result is not None:
                            yield se_result
                    except Exception as e:

                        stop.set()
                        error = e
                elif (
                    error is not None
                ):
                    spawn_result.spawned_job.kill()
                else:
                    try:
                        yield spawn_result.spawned_job.await_result()
                    except Job.Error as e:
                        try:
                            je_result = handler.handle_job_error(spawn_result.item, e)
                            if je_result is not None:
                                yield je_result
                        except Exception as e:

                            stop.set()
                            error = e
            finally:
                job_slots.release()


if TYPE_CHECKING:

    class Comparable(Protocol):
        def __lt__(self, other):
            # type: (Any) -> bool
            pass


now = getattr(time, "perf_counter", getattr(time, "clock", time.time))


def _apply_function(
    function,
    input_item,
):
    # type: (...) -> Tuple[int, _O, float]
    start = now()
    result = function(input_item)
    return os.getpid(), result, now() - start


if TYPE_CHECKING:

    class Pool(Protocol):
        def imap_unordered(
            self,
            func,
            iterable,
            chunksize=1,
        ):
            # type: (...) -> Iterator[_O]
            pass

        def close(self):
            # type: () -> None
            pass

        def join(self):
            # type: () -> None
            pass


@contextmanager
def _mp_pool(size):
    # type: (int) -> Iterator[Pool]

    pool = multiprocessing.Pool(processes=size)
    try:
        yield pool
    finally:
        pool.close()
        pool.join()


MULTIPROCESSING_DEFAULT_MIN_AVERAGE_LOAD = 4


def iter_map_parallel(
    inputs,
    function,
    max_jobs=None,
    min_average_load=MULTIPROCESSING_DEFAULT_MIN_AVERAGE_LOAD,
    costing_function=None,
    result_render_function=None,
    noun="item",
    verb="process",
    verb_past="processed",
):
    # type: (...) -> Iterator[_O]
    input_items = list(inputs)
    if not input_items:
        return


    needed_slots = len(input_items) // min_average_load
    if needed_slots < 2:
        for item in input_items:
            yield function(item)
        return


    pool_size = min(needed_slots, _sanitize_max_jobs(max_jobs))

    if costing_function is not None:


        input_items.sort(key=costing_function, reverse=True)

    apply_function = functools.partial(_apply_function, function)

    slots = defaultdict(list)
    with TRACER.timed(
        "Using {pool_size} parallel jobs to {verb} {count} {inputs}".format(
            pool_size=pool_size,
            verb=verb,
            count=len(input_items),
            inputs=pluralize(input_items, noun),
        )
    ):
        with _mp_pool(size=pool_size) as pool:
            for pid, result, elapsed_secs in pool.imap_unordered(apply_function, input_items):
                TRACER.log(
                    "[{pid}] {verbed} {result} in {elapsed_secs:.2f}s".format(
                        pid=pid,
                        verbed=verb_past,
                        result=result_render_function(result) if result_render_function else result,
                        elapsed_secs=elapsed_secs,
                    ),
                    V=2,
                )
                yield result
                slots[pid].append(elapsed_secs)

    TRACER.log(
        "Elapsed time per {verb} job:\n  {times}".format(
            verb=verb,
            times="\n  ".join(
                "{index}) [{pid}] {total_secs:.2f}s {count} {inputs}".format(
                    index=index,
                    pid=pid,
                    count=len(elapsed),
                    inputs=pluralize(elapsed, noun),
                    total_secs=total_secs,
                )
                for index, (total_secs, pid, elapsed) in enumerate(
                    sorted(
                        ((sum(elapsed), pid, elapsed) for pid, elapsed in slots.items()),
                        reverse=True,
                    ),
                    start=1,
                )
            ),
        )
    )


def map_parallel(
    inputs,
    function,
    max_jobs=None,
    min_average_load=MULTIPROCESSING_DEFAULT_MIN_AVERAGE_LOAD,
    costing_function=None,
    result_render_function=None,
    noun="item",
    verb="process",
    verb_past="processed",
):
    # type: (...) -> List[_O]
    return list(
        iter_map_parallel(
            inputs,
            function,
            max_jobs=max_jobs,
            min_average_load=min_average_load,
            costing_function=costing_function,
            result_render_function=result_render_function,
            noun=noun,
            verb=verb,
            verb_past=verb_past,
        )
    )
