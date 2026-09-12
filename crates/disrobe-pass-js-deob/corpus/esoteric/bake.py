#!/usr/bin/env python3
"""Bake esoteric-obfuscator fixtures for disrobe-pass-js-deob.

Outputs are committed under crates/disrobe-pass-js-deob/corpus/esoteric/;
this script is not required to be runnable in CI."""

from __future__ import annotations

import math
import sys
from pathlib import Path

OUT_DIR: Path = Path(__file__).resolve().parent


def jsfuck_basic_payload() -> str:
    return (
        "[][(![]+[])[+[]]]+([][[]]+[])[+!+[]]"
        "+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]"
        "+(!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]"
    )


def jsfuck_atoms_payload() -> str:
    parts: list[str] = [
        "+!+[]",
        "(![]+[])",
        "(!+[]+[])",
        "([][[]]+[])",
        "(+[]+[])",
        "([]+[][[]])",
        "(!+[]+!+[]+!+[])",
        "([]+[])",
        "(![]+[])",
        "([]+[])",
        "(![]+[])",
    ]
    return "+".join(parts)


def jjencode_payload(g: str) -> str:
    parts: list[str] = []
    parts.append(f"{g}=~[];")
    parts.append(
        f"{g}={{___:++{g},$$$$:(![]+\"\")[{g}],"
        f"__$:++{g},$_$_:(![]+\"\")[{g}],_$_:++{g},"
        f"$_$$:({{}}+\"\")[{g}],$$_$:({g}[{g}]+\"\")[{g}]}};"
    )
    parts.append(f"{g}.$_=({g}.$_=$$+\"\")[{g}.$_$];")
    parts.append(f"{g}.___;")
    return "".join(parts)


def aaencode_marker() -> str:
    return (
        "ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇`*/ ['_'];"
        "o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ)=(ﾟｰﾟ)-(ﾟｰﾟ); "
        "(ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);"
        + "(ﾟΘﾟ)" * 32
    )


def packer_payload() -> str:
    return (
        "eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};"
        "if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}"
        "k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};"
        "while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}"
        "('0 1 2 3 4 5',6,6,'console|log|hello|world|disrobe|fixture'.split('|'),0,{}))"
    )


def firetruck_payload() -> str:
    base: str = "([]+[])./.+!+[].(./.)+"
    repeat: int = math.ceil(512 / len(base))
    return base * repeat + "[]"


def write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    print(f"wrote {path.name} ({len(content)}b)")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write(OUT_DIR / "jsfuck-basic.fuck.js", jsfuck_basic_payload())
    write(OUT_DIR / "jsfuck-atoms.fuck.js", jsfuck_atoms_payload())
    write(OUT_DIR / "jsfuck-bool-true.fuck.js", "!+[]")
    write(OUT_DIR / "jsfuck-bool-false.fuck.js", "![]")
    write(OUT_DIR / "jjencode-basic.jjencode.js", jjencode_payload("$"))
    write(OUT_DIR / "jjencode-alt-global.jjencode.js", jjencode_payload("_"))
    write(OUT_DIR / "aaencode-banner.aaencode.js", aaencode_marker())
    write(
        OUT_DIR / "aaencode-bigger.aaencode.js",
        aaencode_marker() + "\n" + "(ﾟΘﾟ)" * 256,
    )
    write(OUT_DIR / "packer-small.packed.js", packer_payload())
    write(OUT_DIR / "jsfiretruck-synth.firetruck.js", firetruck_payload())
    write(
        OUT_DIR / "eval-indirection-const.js",
        'var z = eval("var __recovered = 42;"); console.log(__recovered);',
    )
    write(
        OUT_DIR / "eval-indirection-newfn.js",
        '(new Function("return 7 * 6;"))();',
    )
    write(
        OUT_DIR / "atob-indirection-simple.js",
        'var msg = atob("SGVsbG8sIGRpc3JvYmUh");',
    )
    write(
        OUT_DIR / "atob-indirection-nested.js",
        'var deeper = atob("YXRvYigiU0dWc2JHOD0iKQ==");',
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
