from __future__ import annotations

import json
import pathlib
from typing import Any

import disrobe

ROOT: pathlib.Path = pathlib.Path(__file__).parents[3]
UPX_PACKED: pathlib.Path = (
    ROOT / "corpus" / "native" / "packers" / "upx" / "hello.packed.nrv2b.exe"
)
CHAIN_GOLDEN: pathlib.Path = (
    ROOT / "corpus" / "chain" / "goldens" / "upx_packed_pe.chain.json"
)
VERDICT_GRADES: dict[str, str] = {
    "ok": "ok",
    "complete": "ok",
    "fan-out": "ok",
    "extracted": "ok",
    "fan-out-partial": "incomplete",
    "stalled": "incomplete",
    "cycle": "incomplete",
    "cap-reached": "incomplete",
    "dry-run": "incomplete",
    "error": "failed",
}


def _ran_passes(document: dict[str, Any]) -> list[str]:
    return [node["pass"] for node in document["nodes"] if node["pass"] is not None]


def test_auto_report_getters_follow_the_chain_document() -> None:
    report: disrobe.ChainReport = disrobe.auto(
        UPX_PACKED.read_bytes(), path_hint=str(UPX_PACKED)
    )
    document: dict[str, Any] = json.loads(report.to_json())
    ran: list[str] = _ran_passes(document)

    assert "native.packer-unpack" in ran
    assert report.pass_count == len(ran)
    assert report.spec == document["spec"]["raw"] == "auto:8"
    assert report.passes == ran
    assert report.node_count == len(document["nodes"])
    assert report.node_count > report.pass_count
    assert report.verdict == document["verdict"]
    assert report.verdict_grade == VERDICT_GRADES[document["verdict"]]
    assert report.final_format == document["final_format"]
    assert not hasattr(report, "terminated")


def test_committed_chain_golden_getters_match_its_document() -> None:
    text: str = CHAIN_GOLDEN.read_text(encoding="utf-8")
    document: dict[str, Any] = json.loads(text)
    report: disrobe.ChainReport = disrobe.ChainReport.from_json_str(text)

    assert report.pass_count == len(_ran_passes(document)) == 1
    assert report.passes == ["native.packer-unpack"]
    assert report.node_count == len(document["nodes"]) == 2
    assert report.spec == "auto:8"
    assert report.verdict == document["verdict"] == "error"
    assert report.verdict_grade == "failed"
    assert report.final_format is None


def test_every_chain_verdict_has_the_core_grade() -> None:
    document: dict[str, Any] = json.loads(CHAIN_GOLDEN.read_text(encoding="utf-8"))
    for verdict, grade in VERDICT_GRADES.items():
        document["verdict"] = verdict
        report: disrobe.ChainReport = disrobe.ChainReport.from_obj(document)
        assert report.verdict == verdict
        assert report.verdict_grade == grade


def test_chain_getters_without_a_chain_document_are_empty() -> None:
    report: disrobe.ChainReport = disrobe.ChainReport.from_obj(
        {"verdict": "unrecognised", "nodes": [{"pass": None}]}
    )
    assert report.node_count == 1
    assert report.pass_count == 0
    assert report.passes == []
    assert report.spec is None
    assert report.verdict == "unrecognised"
    assert report.verdict_grade is None
    assert report.final_format is None
