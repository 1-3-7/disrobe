import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SDK_VERSION = "9.0.318"
REF_PACKS = {"net8.0": "8.0.31", "net9.0": "9.0.20"}
COMMON_FLAGS = [
    "-nologo",
    "-noconfig",
    "-nostdlib",
    "-target:library",
    "-langversion:13.0",
    "-optimize+",
    "-debug-",
    "-utf8output",
]
REFERENCE_RUNTIME = {"runtimeOptions": {"tfm": "net9.0", "framework": {"name": "Microsoft.NETCore.App", "version": "9.0.0"}}}


class BuildError(Exception):
    pass


@dataclass
class Variant:
    source: str
    framework: str = "net9.0"
    deterministic: bool = True
    resources: list = field(default_factory=list)
    links: list = field(default_factory=list)
    public_key: bool = False
    unsafe: bool = False


@dataclass
class Pair:
    name: str
    assembly: str
    old: Variant
    new: Variant
    description: str


PAIRS = [
    Pair("members", "Shop", Variant("members/old.cs"), Variant("members/new.cs"),
         "types, fields, methods, properties, events and a nested type added, removed and renamed"),
    Pair("body", "Scoring", Variant("body/old.cs"), Variant("body/new.cs"),
         "method bodies changed under unchanged signatures: an arithmetic constant, a same-length string literal, a catch type and a loop shape, beside an untouched method"),
    Pair("signature", "Units", Variant("signature/old.cs"), Variant("signature/new.cs"),
         "return, parameter, field and property types changed, one overload replaced, a ref parameter turned into an in parameter and a generic constraint added"),
    Pair("reorder", "Layout", Variant("reorder/old.cs"), Variant("reorder/new.cs"),
         "the same types, fields and methods declared in another order, so only metadata tokens move"),
    Pair("attributes", "Tagged", Variant("attributes/old.cs"), Variant("attributes/new.cs"),
         "custom attribute values, additions and removals on the assembly, types, fields, methods and parameters, plus the Serializable and NonSerialized pseudo-attributes"),
    Pair("version", "Release",
         Variant("version/old.cs", framework="net8.0"),
         Variant("version/new.cs", framework="net9.0", public_key=True),
         "assembly version, file and informational versions, target framework net8.0 to net9.0 and a public key added"),
    Pair("pinvoke", "Platform", Variant("pinvoke/old.cs"), Variant("pinvoke/new.cs"),
         "P/Invoke entry point, module and mapping flags changed, one import removed and one added"),
    Pair("resource", "Assets",
         Variant("resource/old.cs", resources=[
             ("resource/res/greeting.txt", "Assets.Greeting.txt", "public"),
             ("resource/res/logo.bin", "Assets.Logo.bin", "private"),
             ("resource/res/legacy.txt", "Assets.Legacy.txt", "public"),
         ]),
         Variant("resource/new.cs", resources=[
             ("resource/res/greeting-v2.txt", "Assets.Greeting.txt", "public"),
             ("resource/res/logo.bin", "Assets.Logo.bin", "public"),
             ("resource/res/terms.txt", "Assets.Terms.txt", "public"),
         ], links=[("resource/res/manual.txt", "Assets.Manual.txt", "public")]),
         "embedded resource content and visibility changed, one resource removed, one embedded and one linked resource added"),
    Pair("shapes", "Shapes", Variant("shapes/old.cs", unsafe=True), Variant("shapes/new.cs", unsafe=True),
         "explicit interface implementation, struct packing, explicit field offset, fixed buffer, parameter marshalling, function pointer, multi-dimensional array, nested generic reference, pinned local, generic constraints, default parameter value, constant, event type and accessor changes"),
    Pair("identical", "Stable",
         Variant("identical/same.cs", deterministic=False),
         Variant("identical/same.cs", deterministic=False),
         "one source compiled twice without -deterministic: only the MVID and the PE timestamp may differ"),
]


def run(command, cwd, timeout=300):
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        timeout=timeout,
        creationflags=NO_WINDOW,
    )
    if completed.returncode != 0:
        raise BuildError(
            "command failed ({}): {}\n{}\n{}".format(
                completed.returncode,
                " ".join(str(part) for part in command),
                completed.stdout.decode("utf-8", "replace"),
                completed.stderr.decode("utf-8", "replace"),
            )
        )
    return completed.stdout


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def public_key_blob():
    modulus = b"".join(hashlib.sha512(b"disrobe build-compare public key %d" % i).digest() for i in range(2))
    modulus = bytearray(modulus)
    modulus[0] |= 1
    modulus[-1] |= 0x80
    rsa = b"\x06\x02\x00\x00" + struct.pack("<I", 0x2400) + b"RSA1" + struct.pack("<II", 1024, 65537) + bytes(modulus)
    return struct.pack("<III", 0x2400, 0x8004, len(rsa)) + rsa


class Toolchain:
    def __init__(self, dotnet):
        self.dotnet = Path(dotnet)
        root = self.dotnet.parent
        self.csc = root / "sdk" / SDK_VERSION / "Roslyn" / "bincore" / "csc.dll"
        if not self.csc.is_file():
            raise BuildError("missing {}".format(self.csc))
        self.refs = {}
        for framework, version in REF_PACKS.items():
            directory = root / "packs" / "Microsoft.NETCore.App.Ref" / version / "ref" / framework
            if not directory.is_dir():
                raise BuildError("missing reference pack {}".format(directory))
            self.refs[framework] = sorted(directory.glob("*.dll"))
        banner = run([str(self.dotnet), str(self.csc), "-version"], HERE).decode().strip()
        self.compiler = banner

    def compile(self, sources, output, framework, extra, scratch):
        output.parent.mkdir(parents=True, exist_ok=True)
        rsp = scratch / (output.stem + "-" + framework + ".rsp")
        lines = ["-reference:\"{}\"".format(path) for path in self.refs[framework]]
        rsp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        command = [str(self.dotnet), str(self.csc)] + COMMON_FLAGS + extra + ["-out:" + str(output), "@" + str(rsp)] + [str(HERE / s) for s in sources]
        run(command, HERE)


def variant_flags(variant, scratch):
    flags = ["-deterministic" if variant.deterministic else "-deterministic-"]
    if variant.unsafe:
        flags.append("-unsafe+")
    shown = list(flags)
    for path, name, visibility in variant.resources:
        flags.append("-resource:{},{},{}".format(HERE / path, name, visibility))
        shown.append("-resource:{},{},{}".format(path, name, visibility))
    for path, name, visibility in variant.links:
        flags.append("-linkresource:{},{},{}".format(HERE / path, name, visibility))
        shown.append("-linkresource:{},{},{}".format(path, name, visibility))
    if variant.public_key:
        key = scratch / "public.snk"
        key.write_bytes(public_key_blob())
        flags += ["-publicsign", "-keyfile:" + str(key)]
        shown += ["-publicsign", "-keyfile:<public.snk>"]
    return flags, shown


def build_reference(tools, scratch):
    out = scratch / "reference" / "BuildCompareReference.dll"
    out.parent.mkdir(parents=True, exist_ok=True)
    rsp = scratch / "reference.rsp"
    rsp.write_text("\n".join("-reference:\"{}\"".format(p) for p in tools.refs["net9.0"]) + "\n", encoding="utf-8")
    run([str(tools.dotnet), str(tools.csc), "-nologo", "-noconfig", "-nostdlib", "-target:exe", "-langversion:13.0",
         "-optimize+", "-debug-", "-deterministic", "-out:" + str(out), "@" + str(rsp), str(HERE / "reference" / "BuildCompareReference.cs")], HERE)
    (out.parent / "BuildCompareReference.runtimeconfig.json").write_text(json.dumps(REFERENCE_RUNTIME), encoding="utf-8")
    return out


def coff_timestamp(path):
    data = Path(path).read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    return struct.unpack_from("<I", data, pe + 8)[0]


def toml_string(value):
    return json.dumps(value, ensure_ascii=False)


def build(tools, target, scratch):
    records = []
    for pair in PAIRS:
        outputs = {}
        for side, variant in (("old", pair.old), ("new", pair.new)):
            flags, shown = variant_flags(variant, scratch)
            output = target / pair.name / side / (pair.assembly + ".dll")
            if pair.name == "identical" and side == "new":
                time.sleep(2.0)
            tools.compile([variant.source], output, variant.framework, flags, scratch)
            for path, _name, _visibility in variant.links:
                shutil.copyfile(HERE / path, output.parent / Path(path).name)
            outputs[side] = (output, variant, shown)
        if pair.name == "identical":
            old_path, new_path = outputs["old"][0], outputs["new"][0]
            if sha256(old_path) == sha256(new_path) or coff_timestamp(old_path) == coff_timestamp(new_path):
                raise BuildError("the identical pair must differ in MVID and PE timestamp")
        records.append((pair, outputs))
    return records


def write_reference_outputs(tools, reference, target, records):
    for pair, outputs in records:
        text = run([str(tools.dotnet), str(reference), str(outputs["old"][0]), str(outputs["new"][0])], HERE)
        (target / pair.name / "reference.txt").write_bytes(text)


def manifest(tools, records):
    out = []
    out.append('schema = "disrobe.corpus.v1"')
    out.append('crate = "disrobe-pass-dotnet"')
    out.append('generated = "{}"'.format(time.strftime("%Y-%m-%d", time.gmtime())))
    out.append('toolchain = {}'.format(toml_string(".NET SDK {} ({}), reference packs Microsoft.NETCore.App.Ref {} and {}".format(
        SDK_VERSION, tools.compiler, REF_PACKS["net8.0"], REF_PACKS["net9.0"]))))
    out.append('note = "self-authored C# pairs, one per change kind; nothing in them runs, the reference only reads the built assemblies"')
    out.append("")
    out.append("[provenance]")
    out.append('compiler = {}'.format(toml_string("dotnet <sdk>/Roslyn/bincore/csc.dll {} <variant flags> -out:<pair>/<side>/<Assembly>.dll @<every assembly of the reference pack for the variant framework> <source>".format(" ".join(COMMON_FLAGS)))))
    out.append('public_key = "version/new uses -publicsign with a 1024-bit RSA public key blob that build.py derives from SHA-512 of a fixed label; no private key exists"')
    out.append('reference = "reference/BuildCompareReference.cs, compiled with the same csc.dll against the net9.0 reference pack, reads both builds through System.Reflection.Metadata and System.Reflection.Emit.OpCodes and prints the expected findings; command: dotnet BuildCompareReference.dll <old> <new> > <pair>/reference.txt"')
    out.append('rebuild = "python -I corpus/dotnet/build-compare/build.py --dotnet <dotnet.exe> (add --check to rebuild into a scratch directory and compare)"')
    for pair, outputs in records:
        for side in ("old", "new"):
            path, variant, shown = outputs[side]
            rel = path.relative_to(path.parents[2]).as_posix()
            out.append("")
            out.append("[[fixture]]")
            out.append('name = "{}/{}"'.format(pair.name, side))
            out.append('path = "{}"'.format(rel))
            out.append('kind = "managed-pe-dll"')
            out.append('provenance = "real"')
            out.append('source = "{}"'.format(variant.source))
            out.append('framework = "{}"'.format(variant.framework))
            out.append('flags = {}'.format(toml_string(" ".join(shown))))
            out.append('sha256 = "{}"'.format(sha256(path)))
            out.append('description = {}'.format(toml_string(pair.description)))
            for link_path, _name, _visibility in variant.links:
                linked = path.parent / Path(link_path).name
                out.append("")
                out.append("[[fixture]]")
                out.append('name = "{}/{}/{}"'.format(pair.name, side, linked.name))
                out.append('path = "{}"'.format(linked.relative_to(path.parents[2]).as_posix()))
                out.append('kind = "linked-resource"')
                out.append('provenance = "self-authored"')
                out.append('source = "{}"'.format(link_path))
                out.append('sha256 = "{}"'.format(sha256(linked)))
                out.append('description = "the file the -linkresource entry of {} names"'.format(rel))
        reference = path.parents[1] / "reference.txt"
        out.append("")
        out.append("[[fixture]]")
        out.append('name = "{}/reference"'.format(pair.name))
        out.append('path = "{}/reference.txt"'.format(pair.name))
        out.append('kind = "reference-output"')
        out.append('provenance = "real"')
        out.append('source = "reference/BuildCompareReference.cs"')
        out.append('sha256 = "{}"'.format(sha256(reference)))
        out.append('description = "System.Reflection.Metadata reading of {0}/old and {0}/new, diffed into the expected findings"'.format(pair.name))
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description="rebuild the .NET build-comparison pairs and their reference outputs")
    parser.add_argument("--dotnet", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    tools = Toolchain(args.dotnet)
    with tempfile.TemporaryDirectory(prefix="build-compare-") as raw:
        scratch = Path(raw)
        target = scratch / "out" if args.check else HERE
        reference = build_reference(tools, scratch)
        records = build(tools, target, scratch)
        write_reference_outputs(tools, reference, target, records)
        if args.check:
            mismatches = []
            for pair, outputs in records:
                if pair.name == "identical":
                    rebuilt = [line.split(":")[0] for line in (target / pair.name / "reference.txt").read_text(encoding="utf-8").splitlines()]
                    committed = [line.split(":")[0] for line in (HERE / pair.name / "reference.txt").read_text(encoding="utf-8").splitlines()]
                    if rebuilt != committed:
                        mismatches.append(pair.name + "/reference.txt")
                    continue
                names = [pair.name + "/reference.txt"] + [outputs[side][0].relative_to(target).as_posix() for side in ("old", "new")]
                for name in names:
                    if sha256(target / name) != sha256(HERE / name):
                        mismatches.append(name)
            if mismatches:
                raise BuildError("rebuild differs from the committed files: " + ", ".join(mismatches))
            print("rebuild matches the committed fixtures and reference outputs")
        else:
            (HERE / "MANIFEST.toml").write_text(manifest(tools, records), encoding="utf-8", newline="\n")
            print("built {} pairs".format(len(records)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BuildError as error:
        print("build.py: {}".format(error), file=sys.stderr)
        sys.exit(1)
