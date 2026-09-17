from __future__ import annotations

import json
import os
import sys
import unittest
from dataclasses import dataclass, field

_PLUGIN_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from disrobe_ida import ApplyResult, apply_annotations, render_summary
from disrobe_report import Annotations, ReportError, parse_report, rebase

_FIXTURES: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _load_text(name: str) -> str:
    with open(os.path.join(_FIXTURES, name), "r", encoding="utf-8") as handle:
        return handle.read()


def _load_json(name: str) -> dict:
    return json.loads(_load_text(name))


@dataclass
class MockIda:
    base: int = 0x140000000
    names: dict[int, str] = field(default_factory=dict)
    funcs: set[int] = field(default_factory=set)
    comments: dict[tuple[int, bool], str] = field(default_factory=dict)
    structs: dict[str, tuple[tuple[str, int], ...]] = field(default_factory=dict)

    def image_base(self) -> int:
        return self.base

    def set_name(self, ea: int, name: str) -> bool:
        self.names[ea] = name
        return True

    def ensure_func(self, ea: int) -> bool:
        if ea in self.funcs:
            return False
        self.funcs.add(ea)
        return True

    def set_comment(self, ea: int, text: str, repeatable: bool) -> bool:
        self.comments[(ea, repeatable)] = text
        return True

    def comment_texts_at(self, ea: int) -> list[str]:
        return [text for (addr, _), text in self.comments.items() if addr == ea]

    def add_struct(self, name: str, fields: tuple[tuple[str, int], ...]) -> bool:
        self.structs[name] = fields
        return True

    def log(self, message: str) -> None:
        pass


class SymbolsReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.raw: str = _load_text("disc.symbols.json")
        self.doc: dict = json.loads(self.raw)
        self.ann: Annotations = parse_report(self.raw)

    def test_schema_and_source_match_report(self) -> None:
        self.assertEqual(self.ann.schema, self.doc["schema"])
        self.assertEqual(self.ann.source, self.doc["input"])
        self.assertIsNone(self.ann.image_base)

    def test_function_names_match_nonzero_named_exports(self) -> None:
        expected: dict[int, str] = {
            e["address"]: e["name"]
            for e in self.doc["exports"]
            if e["address"] != 0 and e["name"]
        }
        produced: dict[int, str] = {fn.address: fn.name for fn in self.ann.function_names}
        self.assertEqual(produced, expected)
        self.assertNotIn(0, produced, "zero-address file symbol must be dropped")

    def test_known_recovered_functions_present(self) -> None:
        produced: dict[int, str] = {fn.address: fn.name for fn in self.ann.function_names}
        self.assertEqual(produced.get(2101632), "compute")
        self.assertEqual(produced.get(2101744), "dispatch")
        self.assertEqual(produced.get(2101824), "add")

    def test_text_symbols_flagged_as_functions(self) -> None:
        by_addr: dict[int, bool] = {fn.address: fn.is_func for fn in self.ann.function_names}
        self.assertTrue(by_addr[2101632])

    def test_apply_uses_raw_addresses_when_no_image_base(self) -> None:
        ida: MockIda = MockIda(base=0x999000)
        result: ApplyResult = apply_annotations(self.ann, ida)
        self.assertFalse(result.rebased)
        self.assertEqual(ida.names[2101632], "compute")
        self.assertEqual(result.names_applied, len(self.ann.function_names))
        self.assertEqual(result.funcs_created, len(self.ann.function_names))

    def test_summary_lists_source(self) -> None:
        result: ApplyResult = apply_annotations(self.ann, MockIda())
        summary: str = render_summary(self.ann, result)
        self.assertIn("disrobe.native.symbols/v0", summary)
        self.assertIn("disc.unstripped.elf", summary)


class SymbolMapReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.raw: str = _load_text("nspack.symbol-map.json")
        self.doc: dict = json.loads(self.raw)
        self.ann: Annotations = parse_report(self.raw)

    def test_image_base_carried_from_report(self) -> None:
        self.assertEqual(self.ann.image_base, self.doc["image_base"])

    def test_every_symbol_becomes_a_name(self) -> None:
        self.assertEqual(len(self.ann.function_names), len(self.doc["symbols"]))
        produced: dict[int, str] = {fn.address: fn.name for fn in self.ann.function_names}
        for sym in self.doc["symbols"]:
            self.assertEqual(produced[sym["address"]], sym["name"])

    def test_label_class_symbols_not_marked_function(self) -> None:
        for fn in self.ann.function_names:
            self.assertFalse(fn.is_func, "packer-chain labels are class=label, not functions")

    def test_notes_become_repeatable_comments(self) -> None:
        noted: int = sum(1 for s in self.doc["symbols"] if s.get("note"))
        self.assertEqual(len(self.ann.comments), noted)
        for c in self.ann.comments:
            self.assertTrue(c.repeatable)
            self.assertTrue(c.text.startswith("disrobe: "))

    def test_rebase_applies_image_base_delta(self) -> None:
        ida: MockIda = MockIda(base=0x150000000)
        result: ApplyResult = apply_annotations(self.ann, ida)
        self.assertTrue(result.rebased)
        first = self.doc["symbols"][0]
        expected_ea: int = rebase(first["address"], self.doc["image_base"], ida.base)
        self.assertEqual(ida.names[expected_ea], first["name"])
        self.assertNotIn(first["address"], ida.names)


class CapabilitiesReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.raw: str = _load_text("disc.capabilities.json")
        self.doc: dict = json.loads(self.raw)
        self.ann: Annotations = parse_report(self.raw)

    def test_no_function_names_emitted(self) -> None:
        self.assertEqual(self.ann.function_names, ())

    def test_one_comment_per_capability_plus_each_evidence(self) -> None:
        caps: list[dict] = self.doc["capabilities"]
        expected: int = len(caps) + sum(len(c.get("evidence", [])) for c in caps)
        self.assertEqual(len(self.ann.comments), expected)

    def test_capability_comment_carries_rule_and_attack_tag(self) -> None:
        cap: dict = self.doc["capabilities"][0]
        matching = [
            c
            for c in self.ann.comments
            if c.address == cap["address"] and not c.repeatable and cap["rule"] in c.text
        ]
        self.assertEqual(len(matching), 1, "exactly one capability comment at the rule address")
        text: str = matching[0].text
        self.assertIn(cap["description"], text)
        self.assertIn("ATT&CK T1027", text)
        self.assertIn("MBC C0026.002", text)

    def test_evidence_addresses_get_comments(self) -> None:
        ida: MockIda = MockIda()
        apply_annotations(self.ann, ida)
        for ev in self.doc["capabilities"][0]["evidence"]:
            texts: list[str] = ida.comment_texts_at(ev["address"])
            self.assertTrue(
                any(ev["feature"] in t for t in texts),
                f"no evidence comment carrying {ev['feature']} at {ev['address']:#x}",
            )

    def test_apply_count_matches_comment_total(self) -> None:
        result: ApplyResult = apply_annotations(self.ann, MockIda())
        self.assertEqual(result.comments_applied, len(self.ann.comments))


class StringsReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.raw: str = _load_text("disc.strings.json")
        self.doc: dict = json.loads(self.raw)
        self.ann: Annotations = parse_report(self.raw)

    def test_every_string_preserved_in_order(self) -> None:
        self.assertEqual(len(self.ann.strings), len(self.doc["strings"]))
        self.assertEqual(len(self.ann.strings), self.doc["total"])
        for got, want in zip(self.ann.strings, self.doc["strings"]):
            self.assertEqual(got.offset, want["offset"])
            self.assertEqual(got.value, want["value"])

    def test_plain_tag_label(self) -> None:
        first = self.ann.strings[0]
        self.assertEqual(first.tag, "plain")

    def test_known_compiler_string_recovered(self) -> None:
        values: set[str] = {s.value for s in self.ann.strings}
        self.assertTrue(any(v.startswith("clang version 22.1.6") for v in values))

    def test_summary_includes_string_preview(self) -> None:
        result: ApplyResult = apply_annotations(self.ann, MockIda())
        self.assertEqual(result.strings_seen, len(self.doc["strings"]))
        summary: str = render_summary(self.ann, result)
        self.assertIn("recovered strings:", summary)


class StringTagDecodeTest(unittest.TestCase):
    def test_xor_rot_codec_wide_stack_tags(self) -> None:
        payload: str = json.dumps(
            {
                "schema": "disrobe.strings/v0",
                "uri": "synthetic",
                "byte_len": 0,
                "min_len": 4,
                "total": 5,
                "strings": [
                    {"value": "a", "offset": 0, "tag": "plain", "wide": True},
                    {"value": "b", "offset": 1, "tag": "xor", "key": 0x2A},
                    {"value": "c", "offset": 2, "tag": "rot", "n": 13},
                    {"value": "d", "offset": 3, "tag": "codec", "scheme": "base64"},
                    {"value": "e", "offset": 4, "tag": "stack_string"},
                ],
            }
        )
        ann: Annotations = parse_report(payload)
        tags: list[str] = [s.tag for s in ann.strings]
        self.assertEqual(tags, ["plain:wide", "xor:0x2a", "rot:13", "codec:base64", "stack-string"])


class StructReportTest(unittest.TestCase):
    def test_symbol_map_with_structs_creates_them(self) -> None:
        payload: str = json.dumps(
            {
                "schema": "disrobe.native.symbol-map/v1",
                "source": "synthetic",
                "format": "pe",
                "image_base": 0x400000,
                "symbol_count": 0,
                "symbols": [],
                "structs": [
                    {"name": "Header", "fields": [{"name": "magic", "size": 4}, {"name": "len", "size": 8}]}
                ],
            }
        )
        ann: Annotations = parse_report(payload)
        self.assertEqual(len(ann.structs), 1)
        ida: MockIda = MockIda()
        result: ApplyResult = apply_annotations(ann, ida)
        self.assertEqual(result.structs_created, 1)
        self.assertIn("Header", ida.structs)
        self.assertEqual(ida.structs["Header"], (("magic", 4), ("len", 8)))


class FailFastTest(unittest.TestCase):
    def test_non_json_rejected(self) -> None:
        with self.assertRaises(ReportError):
            parse_report("not json {")

    def test_non_object_root_rejected(self) -> None:
        with self.assertRaises(ReportError):
            parse_report("[1, 2, 3]")

    def test_missing_schema_rejected(self) -> None:
        with self.assertRaises(ReportError):
            parse_report(json.dumps({"symbols": []}))

    def test_unknown_schema_rejected(self) -> None:
        with self.assertRaises(ReportError):
            parse_report(json.dumps({"schema": "disrobe.bogus/v9"}))

    def test_missing_required_field_rejected(self) -> None:
        with self.assertRaises(ReportError):
            parse_report(json.dumps({"schema": "disrobe.native.symbol-map/v1", "symbols": []}))

    def test_symbol_address_must_be_int(self) -> None:
        payload: str = json.dumps(
            {
                "schema": "disrobe.native.symbol-map/v1",
                "image_base": 0,
                "symbols": [{"address": "nope", "name": "x", "class": "function"}],
            }
        )
        with self.assertRaises(ReportError):
            parse_report(payload)

    def test_bool_is_not_accepted_as_address(self) -> None:
        payload: str = json.dumps(
            {
                "schema": "disrobe.native.symbols/v0",
                "input": "x",
                "exports": [{"address": True, "name": "x", "kind": "text"}],
            }
        )
        with self.assertRaises(ReportError):
            parse_report(payload)


class DemangledLabelTest(unittest.TestCase):
    def test_demangled_preferred_over_mangled_name(self) -> None:
        payload: str = json.dumps(
            {
                "schema": "disrobe.native.symbol-map/v1",
                "image_base": 0x400000,
                "symbols": [
                    {
                        "address": 0x402000,
                        "name": "_ZN4core3fmt5Write9write_fmtE",
                        "demangled": "core::fmt::Write::write_fmt",
                        "class": "function",
                    }
                ],
            }
        )
        ann: Annotations = parse_report(payload)
        self.assertEqual(ann.function_names[0].name, "core::fmt::Write::write_fmt")
        self.assertTrue(ann.function_names[0].is_func)


if __name__ == "__main__":
    unittest.main(verbosity=2)
