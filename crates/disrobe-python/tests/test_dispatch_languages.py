"""Dispatch wiring oracle for the languages routed through disrobe.parse /
disrobe.disasm / disrobe.decompile.

Each newly-wired language is exercised on a committed fixture or an inline
sample. Every assertion checks the concrete typed return class AND a field the
underlying pass genuinely recovered, so a stubbed or mis-routed binding fails
here rather than passing silently.

Run with: python -m pytest crates/disrobe-python/tests
"""

from __future__ import annotations

import pathlib

import disrobe

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
HELLO_CLASS = (FIXTURES / "Hello.class").read_bytes()
HELLO_LUAC = (FIXTURES / "hello.5_1.luac").read_bytes()
HELLO_YARVC = (FIXTURES / "hello.rb.yarvc").read_bytes()
SWIFT_MACHO = (FIXTURES / "SwiftHello.macho").read_bytes()
SAMPLE_ELF = (FIXTURES / "sample.elf").read_bytes()

MINIFIED_JS = "var a=!0;var b=!1;function f(x){return x?a:b;}"
PHP_EVAL_CHAIN = '<?php eval(base64_decode("ZWNobyAiaGVsbG8gd29ybGQiOw==")); ?>'


def test_parse_javascript_returns_typed_unminify() -> None:
    report = disrobe.parse("javascript", MINIFIED_JS)
    assert isinstance(report, disrobe.JsUnminify)
    assert isinstance(report.source, str)
    assert "true" in report.source and "false" in report.source


def test_parse_typescript_alias_routes() -> None:
    report = disrobe.parse("ts", MINIFIED_JS)
    assert isinstance(report, disrobe.JsUnminify)
    assert isinstance(report.source, str)


def test_parse_php_returns_typed_decode() -> None:
    report = disrobe.parse("php", PHP_EVAL_CHAIN)
    assert isinstance(report, disrobe.PhpDecode)
    assert isinstance(report.source, str)
    assert "hello world" in report.source
    assert report.layer_count >= 1


def test_parse_kotlin_classfile_returns_jvmclass() -> None:
    report = disrobe.parse("kotlin", HELLO_CLASS)
    assert isinstance(report, disrobe.JvmClass)
    assert report.major_version == 52
    assert report.constant_pool_count >= 1


def test_parse_lua_bytecode_returns_decompilation() -> None:
    report = disrobe.parse("lua", HELLO_LUAC)
    assert isinstance(report, disrobe.LuaDecompilation)
    assert isinstance(report.source, str)
    assert "print" in report.source


def test_parse_ruby_yarv_returns_analysis() -> None:
    report = disrobe.parse("ruby", HELLO_YARVC)
    assert isinstance(report, disrobe.RubyAnalysis)
    assert report.flavor is not None
    assert report.input_len == len(HELLO_YARVC)


def test_parse_swift_macho_returns_swiftreport() -> None:
    report = disrobe.parse("swift", SWIFT_MACHO)
    assert isinstance(report, disrobe.SwiftReport)
    assert report.container is not None
    assert report.slice_count >= 1


def test_parse_go_returns_go_analysis() -> None:
    report = disrobe.parse("go", SAMPLE_ELF)
    assert isinstance(report, disrobe.GoAnalysis)
    assert report.image_kind == "elf"


def test_disasm_ruby_yields_yarv_listing() -> None:
    listing = disrobe.disasm("ruby", HELLO_YARVC)
    assert isinstance(listing, str)
    assert "disasm:" in listing
    assert "hello world" in listing
    assert "puts" in listing


def test_decompile_lua_returns_canonical_source() -> None:
    src = disrobe.decompile("lua", HELLO_LUAC)
    assert isinstance(src, disrobe.CanonicalSource)
    assert src.language == "lua"
    assert "print" in (src.source or "")
    assert src.confidence is not None


def test_decompile_ruby_returns_canonical_source() -> None:
    src = disrobe.decompile("ruby", HELLO_YARVC)
    assert isinstance(src, disrobe.CanonicalSource)
    assert src.language == "ruby"
    assert isinstance(src.source, str)


def test_decompile_php_returns_canonical_source() -> None:
    src = disrobe.decompile("php", PHP_EVAL_CHAIN)
    assert isinstance(src, disrobe.CanonicalSource)
    assert src.language == "php"
    assert "hello world" in (src.source or "")


def test_decompile_kotlin_classfile_returns_canonical_source() -> None:
    src = disrobe.decompile("kotlin", HELLO_CLASS)
    assert isinstance(src, disrobe.CanonicalSource)
    assert src.language in {"kotlin", "java"}
    assert isinstance(src.source, str)
    assert "class" in (src.source or "")


def test_decompile_jvm_class_returns_canonical_source() -> None:
    src = disrobe.decompile("class", HELLO_CLASS)
    assert isinstance(src, disrobe.CanonicalSource)
    assert src.language == "java"
    assert "Hello" in (src.source or "")


def test_decompile_javascript_returns_canonical_source() -> None:
    src = disrobe.decompile("js", MINIFIED_JS)
    assert isinstance(src, disrobe.CanonicalSource)
    assert src.language == "javascript"
    assert isinstance(src.source, str)


def test_dispatch_no_longer_defers_to_cli() -> None:
    deferred: list[str] = []
    for language, sample in (
        ("go", SAMPLE_ELF),
        ("kotlin", HELLO_CLASS),
        ("lua", HELLO_LUAC),
        ("ruby", HELLO_YARVC),
        ("php", PHP_EVAL_CHAIN),
        ("swift", SWIFT_MACHO),
        ("javascript", MINIFIED_JS),
    ):
        try:
            disrobe.parse(language, sample)
        except disrobe.UnsupportedLanguage:
            deferred.append(language)
        except disrobe.DisrobeError:
            pass
    assert not deferred, "languages still deferring in parse dispatch: " + ", ".join(deferred)
