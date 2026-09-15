from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import BinaryIO
from unittest.mock import MagicMock, patch

_PLUGIN_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

import disrobe_import as di

_REPORT: str = '{"schema":"disrobe.native.symbol-map/v1","image_base":0,"symbols":[]}'


class RuntimeContractTests(unittest.TestCase):
    def test_entrypoint_uses_pyghidra_script_context(
        self: RuntimeContractTests,
    ) -> None:
        script: MagicMock = MagicMock()
        with (
            TemporaryDirectory() as directory,
            patch.dict(di.__dict__, {"__this__": script}),
            patch.object(di, "_FlatApiApplier") as adapter,
        ):
            report: Path = Path(directory) / "saved-report.json"
            report.write_text(_REPORT, encoding="utf-8")
            script.getScriptArgs.return_value = [str(report)]
            di.run()
        adapter.assert_called_once_with(script, file_offsets=False)
        script.println.assert_called_once()

    def test_native_commands_read_report_file_and_clean_output(
        self: RuntimeContractTests,
    ) -> None:
        outputs: list[Path] = []
        for action in ("native symbols", "native disasm (json)"):
            with self.subTest(action=action):
                outputs.clear()

                def invoke(
                    args: list[str],
                    *,
                    stdout: BinaryIO | None = None,
                    stderr: BinaryIO | None = None,
                    timeout: int,
                    check: bool,
                    capture_output: bool = False,
                    text: bool = False,
                ) -> subprocess.CompletedProcess[bytes]:
                    self.assertEqual(timeout, di.CLI_TIMEOUT_SECONDS)
                    self.assertFalse(check)
                    self.assertIn("--out", args)
                    assert stdout is not None
                    report: Path = Path(args[args.index("--out") + 1])
                    outputs.append(report)
                    report.write_text(_REPORT, encoding="utf-8")
                    stdout.write(b"wrote native report\n")
                    return subprocess.CompletedProcess(args, 0)

                with patch.object(di.subprocess, "run", side_effect=invoke):
                    self.assertEqual(
                        di.run_disrobe_json(di.CLI_ACTIONS[action], "input.bin"),
                        _REPORT,
                    )
                self.assertEqual(len(outputs), 1)
                self.assertFalse(outputs[0].parent.exists())

    def test_ioc_reads_stdout_and_failure_keeps_diagnostics(
        self: RuntimeContractTests,
    ) -> None:
        def invoke(
            args: list[str],
            *,
            stdout: BinaryIO,
            stderr: BinaryIO,
            timeout: int,
            check: bool,
        ) -> subprocess.CompletedProcess[bytes]:
            self.assertNotIn("--out", args)
            stdout.write(_REPORT.encode("utf-8"))
            stderr.write(b"cannot read input")
            return subprocess.CompletedProcess(
                args, 0 if args[-1] == "valid.bin" else 2
            )

        with patch.object(di.subprocess, "run", side_effect=invoke):
            self.assertEqual(
                di.run_disrobe_json(di.CLI_ACTIONS["ioc"], "valid.bin"), _REPORT
            )
            with self.assertRaisesRegex(di.ReportError, "exited 2: cannot read input"):
                di.run_disrobe_json(di.CLI_ACTIONS["ioc"], "missing.bin")

    def test_report_read_rejects_oversize_and_invalid_utf8(
        self: RuntimeContractTests,
    ) -> None:
        with TemporaryDirectory() as directory:
            path: Path = Path(directory) / "report.json"
            path.write_bytes(b"x" * 17)
            with (
                patch.object(di, "MAX_REPORT_BYTES", 16),
                self.assertRaisesRegex(di.ReportError, "exceeds 16 bytes"),
            ):
                di.read_report(path)
            path.write_bytes(b"\xff")
            with self.assertRaisesRegex(di.ReportError, "not valid UTF-8"):
                di.read_report(path)

    def test_ioc_offsets_require_one_mapped_address(self: RuntimeContractTests) -> None:
        script: MagicMock = MagicMock()
        script.getScriptArgs.return_value = ["ioc.json"]
        memory: MagicMock = script.getCurrentProgram.return_value.getMemory.return_value
        mapped: object = object()
        memory.locateAddressesForFileOffset.return_value = [mapped]
        report: str = (
            '{"schema":"disrobe.ioc/v0","indicators":['
            '{"offset":1536,"kind":"url","value":"https://example.invalid"}]}'
        )
        listing_module: SimpleNamespace = SimpleNamespace(
            CodeUnit=SimpleNamespace(PLATE_COMMENT=0, EOL_COMMENT=1)
        )
        with (
            patch.dict(di.__dict__, {"__this__": script}),
            patch.object(di, "read_report", return_value=report),
            patch.object(di, "import_module", return_value=listing_module),
        ):
            di.run()
            memory.locateAddressesForFileOffset.assert_called_with(1536)
            script.createAsciiString.assert_called_once_with(mapped, 23)
            for addresses in ([], [mapped, object()]):
                memory.locateAddressesForFileOffset.return_value = addresses
                with self.assertRaisesRegex(di.ReportError, "expected one"):
                    di.run()

    def test_unicode_ioc_uses_utf8_type_and_byte_span(
        self: RuntimeContractTests,
    ) -> None:
        script: MagicMock = MagicMock()
        script.getScriptArgs.return_value = ["ioc.json"]
        mapped: object = object()
        memory: MagicMock = script.getCurrentProgram.return_value.getMemory.return_value
        memory.locateAddressesForFileOffset.return_value = [mapped]
        string_type: object = object()
        api_module: SimpleNamespace = SimpleNamespace(
            CodeUnit=SimpleNamespace(PLATE_COMMENT=0, EOL_COMMENT=1),
            StringUTF8DataType=SimpleNamespace(dataType=string_type),
        )
        report: str = (
            '{"schema":"disrobe.ioc/v0","indicators":['
            '{"offset":1536,"kind":"url","value":"https://example.invalid/caf\u00e9"}]}'
        )
        with (
            patch.dict(di.__dict__, {"__this__": script}),
            patch.object(di, "read_report", return_value=report),
            patch.object(di, "import_module", return_value=api_module),
        ):
            di.run()
        listing: MagicMock = (
            script.getCurrentProgram.return_value.getListing.return_value
        )
        listing.createData.assert_called_once_with(mapped, string_type, 29)
        script.createAsciiString.assert_not_called()


if __name__ == "__main__":
    unittest.main()
