from __future__ import annotations

import json
import sys
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_PLUGIN_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

import disrobe_import as di  # noqa: E402

_REPORTS: Path = Path(__file__).resolve().parent / "reports"


def _load(name: str) -> str:
    return (_REPORTS / name).read_text(encoding="utf-8")


@dataclass
class FakeAddress:
    value: int

    def __eq__(self: FakeAddress, other: object, /) -> bool:
        return isinstance(other, FakeAddress) and other.value == self.value

    def __hash__(self: FakeAddress, /) -> int:
        return hash(self.value)


@dataclass
class MockApplier:
    functions: dict[int, str] = field(default_factory=dict)
    labels: dict[int, str] = field(default_factory=dict)
    plate_comments: dict[int, str] = field(default_factory=dict)
    eol_comments: dict[int, str] = field(default_factory=dict)
    strings: dict[int, str] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)

    def address(self: MockApplier, value: int, /) -> FakeAddress:
        return FakeAddress(value)

    def create_function(self: MockApplier, ann: di.FunctionAnnotation, /) -> bool:
        self.functions[ann.address] = ann.name
        return True

    def create_label(self: MockApplier, ann: di.LabelAnnotation, /) -> bool:
        self.labels[ann.address] = ann.name
        return True

    def set_comment(self: MockApplier, ann: di.CommentAnnotation, /) -> bool:
        if ann.kind is di.CommentKind.PLATE:
            self.plate_comments[ann.address] = ann.text
        else:
            self.eol_comments[ann.address] = ann.text
        return True

    def create_string(self: MockApplier, ann: di.StringAnnotation, /) -> bool:
        self.strings[ann.address] = ann.value
        return True

    def log(self: MockApplier, message: str, /) -> None:
        self.logs.append(message)


class ParseLayerTest(unittest.TestCase):
    def test_rejects_non_json(self: ParseLayerTest, /) -> None:
        with self.assertRaises(di.ReportError):
            di.parse_report("not json {")

    def test_rejects_non_object_root(self: ParseLayerTest, /) -> None:
        with self.assertRaises(di.ReportError):
            di.parse_report("[1, 2, 3]")

    def test_rejects_missing_schema(self: ParseLayerTest, /) -> None:
        with self.assertRaises(di.ReportError):
            di.parse_report('{"functions": []}')

    def test_rejects_unsupported_schema(self: ParseLayerTest, /) -> None:
        with self.assertRaises(di.ReportError):
            di.build_annotations({"schema": "disrobe.bogus/v9"})

    def test_fails_fast_on_missing_required_field(self: ParseLayerTest, /) -> None:
        with self.assertRaises(di.ReportError):
            di.build_annotations({"schema": di.SCHEMA_DISASM})


class SymbolsMappingTest(unittest.TestCase):
    def setUp(self: SymbolsMappingTest, /) -> None:
        self.report: dict[str, Any] = json.loads(_load("native_symbols_v0.json"))
        self.ann: di.AnnotationSet = di.annotations_from_text(_load("native_symbols_v0.json"))

    def test_schema_and_source_match_report(self: SymbolsMappingTest, /) -> None:
        self.assertEqual(self.ann.schema, di.SCHEMA_SYMBOLS)
        self.assertEqual(self.ann.source, self.report["input"])

    def test_every_text_export_becomes_a_function_at_its_address(self: SymbolsMappingTest, /) -> None:
        expected: dict[int, str] = {
            e["address"]: e["name"]
            for e in self.report["exports"]
            if e["kind"] == "text" and e["address"] != 0
        }
        produced: dict[int, str] = {f.address: f.name for f in self.ann.functions}
        self.assertEqual(produced, expected)
        self.assertEqual(len(self.ann.functions), 7)

    def test_zero_address_file_symbol_is_not_emitted(self: SymbolsMappingTest, /) -> None:
        addresses: set[int] = {f.address for f in self.ann.functions} | {
            label.address for label in self.ann.labels
        }
        self.assertNotIn(0, addresses)

    def test_entry_symbol_is_flagged_as_entry(self: SymbolsMappingTest, /) -> None:
        entry_va: int = self.report["entry"]
        entry_fns: list[di.FunctionAnnotation] = [
            f for f in self.ann.functions if f.address == entry_va
        ]
        self.assertEqual(len(entry_fns), 1)
        self.assertTrue(entry_fns[0].is_entry)

    def test_apply_creates_named_functions_at_correct_addresses(self: SymbolsMappingTest, /) -> None:
        applier: MockApplier = MockApplier()
        result: di.ApplyResult = di.apply_annotations(self.ann, applier)
        self.assertEqual(result.functions, 7)
        self.assertEqual(applier.functions[2101632], "compute")
        self.assertEqual(applier.functions[2101824], "add")
        self.assertEqual(applier.functions[2101600], "_start")
        self.assertIn(2101632, applier.eol_comments)
        self.assertIn(".text", applier.eol_comments[2101632])


class SymbolMapMappingTest(unittest.TestCase):
    def setUp(self: SymbolMapMappingTest, /) -> None:
        self.report: dict[str, Any] = json.loads(_load("native_symbol_map_v1.json"))
        self.ann: di.AnnotationSet = di.annotations_from_text(_load("native_symbol_map_v1.json"))

    def test_image_base_is_carried_through(self: SymbolMapMappingTest, /) -> None:
        self.assertEqual(self.ann.image_base, self.report["image_base"])

    def test_recovered_label_symbols_map_to_labels(self: SymbolMapMappingTest, /) -> None:
        produced: dict[int, str] = {label.address: label.name for label in self.ann.labels}
        expected: dict[int, str] = {
            s["address"]: s["name"]
            for s in self.report["symbols"]
            if s["class"] == "label"
        }
        self.assertEqual(produced, expected)

    def test_notes_become_eol_comments(self: SymbolMapMappingTest, /) -> None:
        applier: MockApplier = MockApplier()
        di.apply_annotations(self.ann, applier)
        upx_addr: int = next(
            s["address"] for s in self.report["symbols"] if "upx" in s["name"]
        )
        self.assertIn(upx_addr, applier.eol_comments)
        self.assertIn("UPX", applier.eol_comments[upx_addr])

    def test_no_phantom_annotations(self: SymbolMapMappingTest, /) -> None:
        self.assertEqual(
            len(self.ann.labels) + len(self.ann.functions),
            self.report["symbol_count"],
        )


class DisasmMappingTest(unittest.TestCase):
    def setUp(self: DisasmMappingTest, /) -> None:
        self.report: dict[str, Any] = json.loads(_load("native_disasm_v2.json"))
        self.ann: di.AnnotationSet = di.annotations_from_text(_load("native_disasm_v2.json"))

    def test_function_count_matches_report(self: DisasmMappingTest, /) -> None:
        self.assertEqual(len(self.ann.functions), self.report["function_count"])

    def test_names_and_addresses_are_faithful(self: DisasmMappingTest, /) -> None:
        produced: dict[int, str] = {f.address: f.name for f in self.ann.functions}
        expected: dict[int, str] = {
            f["address"]: f["name"] for f in self.report["functions"]
        }
        self.assertEqual(produced, expected)

    def test_plate_comment_records_instruction_count(self: DisasmMappingTest, /) -> None:
        applier: MockApplier = MockApplier()
        di.apply_annotations(self.ann, applier)
        start_addr: int = next(
            f["address"] for f in self.report["functions"] if f["name"] == "_start"
        )
        self.assertIn(start_addr, applier.plate_comments)
        self.assertIn("instructions=", applier.plate_comments[start_addr])


class IocMappingTest(unittest.TestCase):
    def setUp(self: IocMappingTest, /) -> None:
        self.report: dict[str, Any] = json.loads(_load("ioc_v0.json"))
        self.ann: di.AnnotationSet = di.annotations_from_text(_load("ioc_v0.json"))

    def test_one_comment_and_string_per_indicator(self: IocMappingTest, /) -> None:
        self.assertEqual(len(self.ann.comments), self.report["total"])
        self.assertEqual(len(self.ann.strings), self.report["total"])

    def test_indicator_offset_value_kind_are_faithful(self: IocMappingTest, /) -> None:
        applier: MockApplier = MockApplier()
        di.apply_annotations(self.ann, applier)
        for ind in self.report["indicators"]:
            offset: int = ind["offset"]
            self.assertIn(offset, applier.eol_comments)
            self.assertIn(ind["value"], applier.eol_comments[offset])
            self.assertIn(ind["kind"], applier.eol_comments[offset])
            self.assertEqual(applier.strings[offset], ind["value"])


class ApplyAccountingTest(unittest.TestCase):
    def test_skip_is_counted_when_applier_refuses(self: ApplyAccountingTest, /) -> None:
        class RefusingApplier(MockApplier):
            def create_function(self: RefusingApplier, ann: di.FunctionAnnotation, /) -> bool:
                return False

        ann: di.AnnotationSet = di.annotations_from_text(_load("native_disasm_v2.json"))
        applier: RefusingApplier = RefusingApplier()
        result: di.ApplyResult = di.apply_annotations(ann, applier)
        self.assertEqual(result.functions, 0)
        self.assertEqual(result.skipped, len(ann.functions))

    def test_total_counts_all_annotation_categories(self: ApplyAccountingTest, /) -> None:
        ann: di.AnnotationSet = di.annotations_from_text(_load("native_symbols_v0.json"))
        self.assertEqual(
            ann.total(),
            len(ann.functions) + len(ann.labels) + len(ann.comments) + len(ann.strings),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
