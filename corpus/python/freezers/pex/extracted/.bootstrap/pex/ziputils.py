

from __future__ import absolute_import

import io
import os
import shutil
import struct

from pex.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import BinaryIO, Optional, Text

    import attr
else:
    from pex.third_party import attr


class ZipError(Exception):


@attr.s(frozen=True)
class _Zip64Error(ZipError):

    record_type = attr.ib()
    field = attr.ib()
    value = attr.ib()
    message = attr.ib(default="")

    def __str__(self):
        # type: () -> str
        message_lines = [self.message] if self.message else []
        message_lines.append(
            "The {field} field of the {record_type} record has value {value} indicating Zip64 "
            "support is required, but Zip64 support is not implemented.".format(
                record_type=self.record_type,
                field=self.field,
                value=self.value,
            )
        )
        message_lines.append(
            "Please file an issue at https://github.com/pex-tool/pex/issues/new that includes "
            "this full backtrace if you need this support."
        )
        return "\n".join(message_lines)


_MAX_2_BYTES = 0xFFFF
_MAX_4_BYTES = 0xFFFFFFFF


@attr.s(frozen=True)
class _EndOfCentralDirectoryRecord(object):
    _SIGNATURE = b"\x50\x4b\x05\x06"
    _STRUCT = struct.Struct("<4sHHHHLLH")

    _MAX_SIZE = _STRUCT.size + (

        _MAX_2_BYTES
    )

    @classmethod
    def load(cls, zip_path):
        # type: (Text) -> _EndOfCentralDirectoryRecord
        file_size = os.path.getsize(zip_path)
        if file_size < cls._STRUCT.size:
            raise ValueError(
                "The file at {path} is too small to be a valid Zip file.".format(path=zip_path)
            )

        with open(zip_path, "rb") as fp:

            fp.seek(-cls._STRUCT.size, os.SEEK_END)
            if cls._SIGNATURE == fp.read(len(cls._SIGNATURE)):
                fp.seek(-len(cls._SIGNATURE), os.SEEK_CUR)
                return cls(cls._STRUCT.size, *cls._STRUCT.unpack(fp.read()))


            read_size = min(cls._MAX_SIZE, file_size)
            fp.seek(-read_size, os.SEEK_END)
            last_data_chunk = fp.read()
            start_eocd = last_data_chunk.find(cls._SIGNATURE)
            _struct = cls._STRUCT.unpack_from(last_data_chunk, start_eocd)
            zip_comment = last_data_chunk[start_eocd + cls._STRUCT.size :]
            eocd_size = len(last_data_chunk) - start_eocd
            return cls(eocd_size, *(_struct + (zip_comment,)))

    size = attr.ib()


    sig = attr.ib()
    disk_no = attr.ib(metadata={"max": _MAX_2_BYTES})
    cd_disk_no = attr.ib(metadata={"max": _MAX_2_BYTES})
    disk_cd_record_count = attr.ib(metadata={"max": _MAX_2_BYTES})
    total_cd_record_count = attr.ib(metadata={"max": _MAX_2_BYTES})
    cd_size = attr.ib(metadata={"max": _MAX_4_BYTES})
    cd_offset = attr.ib(metadata={"max": _MAX_4_BYTES})
    zip_comment_size = attr.ib()
    zip_comment = attr.ib(default=b"")

    @disk_no.validator
    @cd_disk_no.validator
    @disk_cd_record_count.validator
    @total_cd_record_count.validator
    @cd_size.validator
    @cd_offset.validator
    def _validate_does_not_require_zip64(
        self,
        attribute,
        value,
    ):


        if value == attribute.metadata["max"]:
            raise _Zip64Error(
                record_type="EndOfCentralDirectoryRecord", field=attribute.name, value=value
            )

    @property
    def start_of_zip_offset_from_eof(self):
        # type: () -> int
        return self.size + self.cd_size + self.cd_offset


@attr.s(frozen=True)
class Zip(object):

    @classmethod
    def load(cls, path):
        # type: (Text) -> Zip
        try:
            eocd = _EndOfCentralDirectoryRecord.load(path)
        except _Zip64Error as e:
            raise attr.evolve(
                e, message="The zip at {path} requires Zip64 support.".format(path=path)
            )
        header_size = os.path.getsize(path) - eocd.start_of_zip_offset_from_eof
        return cls(path=path, header_size=header_size)

    path = attr.ib()
    header_size = attr.ib()

    @property
    def has_header(self):
        # type: () -> bool
        return self.header_size > 0

    def isolate_header(
        self,
        out_fp,
        stop_at=None,
    ):
        # type: (...) -> bytes

        if not self.has_header:
            return b""

        remaining = self.header_size
        with open(self.path, "rb") as in_fp:
            if stop_at:


                in_fp.seek(self.header_size, os.SEEK_SET)
                while remaining > 0:
                    chunk_size = min(remaining, io.DEFAULT_BUFFER_SIZE)
                    in_fp.seek(-chunk_size, os.SEEK_CUR)
                    chunk = in_fp.read(chunk_size)
                    remaining -= len(chunk)

                    offset = chunk.rfind(stop_at)
                    if offset != -1:
                        remaining += offset
                        break

            excess = self.header_size - remaining
            in_fp.seek(0, os.SEEK_SET)
            for chunk in iter(lambda: in_fp.read(min(remaining, io.DEFAULT_BUFFER_SIZE)), b""):
                remaining -= len(chunk)
                out_fp.write(chunk)

            return in_fp.read(excess)

    def isolate_zip(self, out_fp):
        # type: (BinaryIO) -> None
        with open(self.path, "rb") as in_fp:
            if self.has_header:
                in_fp.seek(self.header_size, os.SEEK_SET)
            shutil.copyfileobj(in_fp, out_fp)
