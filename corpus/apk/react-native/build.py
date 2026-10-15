"""Build the React Native asset APK and IPA fixtures.

usage: python build.py <aapt2> <node>

The packager asset records come from behaviour/rnassets.hermes-stdout.txt, the output of the
reference hermes interpreter running the bundle. asset_paths.js runs React Native's own asset
copy step (reference/saveAssets.js with its scale filter and Android and iOS path rules, MIT)
and prints, one JSON array per record, where it would write that record's files. For Android, aapt2 compiles and links
those files with the bundle as assets/index.android.bundle; the xxxhdpi density of the webp
icon is left out, as in a base APK whose densities moved to a split. rnassets.apk carries the
v89 Hermes bundle, rnassets-js.apk the plain JavaScript bundle rnassets.min.js, and
rnassets-short.apk the v98 bundle after aapt2 optimize --shorten-resource-paths, so its files
are only reachable through resources.arsc. rnassets.ipa is a zip laid out as an iOS app:
Payload/RnAssets.app/main.jsbundle is the v94 Hermes bundle and each file sits at the iOS path
under the app, with the @3x webp icon left out.
"""

import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
HERMES = os.path.normpath(os.path.join(HERE, "..", "..", "mobile", "hermes"))
OMITTED = {
    "res/drawable-xxxhdpi/node_modules_scope_icons_assets_iconback.webp",
    "assets/node_modules/@scope/icons/assets/Icon-Back@3x.webp",
}
APP = "Payload/RnAssets.app"
MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.disrobe.rnassets">\n  <application />\n</manifest>\n'
)
INFO_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    '<plist version="1.0">\n<dict>\n'
    '  <key>CFBundleIdentifier</key>\n  <string>com.disrobe.rnassets</string>\n'
    '  <key>CFBundleName</key>\n  <string>RnAssets</string>\n'
    '</dict>\n</plist>\n'
)


def sha256(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def png(width: int, height: int, shade: int) -> bytes:
    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    rows = b"".join(b"\x00" + bytes([shade]) * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )


def picture(kind: str, width: int, height: int, shade: int) -> bytes:
    if kind == "png":
        return png(width, height, shade)
    from PIL import Image

    image = Image.new("L", (width, height), shade)
    out = io.BytesIO()
    if kind == "webp":
        image.save(out, format="WEBP", lossless=True)
    elif kind == "jpg":
        image.save(out, format="JPEG", quality=90)
    else:
        raise SystemExit(f"no encoder for {kind}")
    return out.getvalue()


def placeholder_font() -> bytes:
    return struct.pack(">IHHHH", 0x00010000, 0, 0, 0, 0)


def asset_files(node: str, scratch: str, records: list, platform: str) -> dict:
    records_path = os.path.join(scratch, f"records-{platform}.json")
    with open(records_path, "w", encoding="utf-8") as handle:
        json.dump(records, handle)
    listing = subprocess.run(
        [node, os.path.join(HERE, "asset_paths.js"), platform, records_path],
        check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    files = {}
    for record, line in zip(records, listing):
        width = int(record.get("width", 8))
        height = int(record.get("height", 8))
        for shade, relative in enumerate(json.loads(line)):
            if relative in OMITTED:
                continue
            files[relative] = placeholder_font() if record["type"] == "ttf" else picture(
                record["type"], width, height, 40 + 40 * shade)
    return files


def link(aapt2: str, scratch: str, compiled: str, bundle: str, out: str) -> None:
    assets = os.path.join(scratch, "assets-" + os.path.basename(out))
    os.makedirs(assets)
    shutil.copyfile(bundle, os.path.join(assets, "index.android.bundle"))
    subprocess.run(
        [aapt2, "link", "-o", out, "--manifest", os.path.join(scratch, "AndroidManifest.xml"),
         "-A", assets, compiled],
        check=True,
    )


def write_ipa(out: str, files: dict) -> None:
    with zipfile.ZipFile(out, "w") as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, files[name])


def main() -> int:
    aapt2, node = sys.argv[1], sys.argv[2]
    with open(os.path.join(HERMES, "behaviour", "rnassets.hermes-stdout.txt"), encoding="utf-8") as handle:
        records = json.loads(handle.read().split("\n")[1])
    with tempfile.TemporaryDirectory() as scratch:
        for relative, data in asset_files(node, scratch, records, "android").items():
            target = os.path.join(scratch, relative)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(data)
        with open(os.path.join(scratch, "AndroidManifest.xml"), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(MANIFEST)
        compiled = os.path.join(scratch, "compiled.zip")
        subprocess.run([aapt2, "compile", "--dir", os.path.join(scratch, "res"), "-o", compiled], check=True)
        link(aapt2, scratch, compiled, os.path.join(HERMES, "behaviour", "rnassets.hbc"),
             os.path.join(HERE, "rnassets.apk"))
        link(aapt2, scratch, compiled, os.path.join(HERE, "rnassets.min.js"),
             os.path.join(HERE, "rnassets-js.apk"))
        modern = os.path.join(scratch, "modern.apk")
        link(aapt2, scratch, compiled, os.path.join(HERMES, "modern", "rnassets.hbc.v98"), modern)
        short = os.path.join(HERE, "rnassets-short.apk")
        mapping = os.path.join(scratch, "short.map")
        subprocess.run(
            [aapt2, "optimize", "--shorten-resource-paths", "--resource-path-shortening-map",
             mapping, "-o", short, modern],
            check=True,
        )
        with open(mapping, "rb") as handle:
            lines = sorted(handle.read().replace(b"\r\n", b"\n").strip(b"\n").split(b"\n"))
        with open(os.path.join(HERE, "rnassets-short.map.txt"), "wb") as handle:
            handle.write(b"\n".join(lines) + b"\n")
        ipa = {f"{APP}/{relative}": data for relative, data in asset_files(node, scratch, records, "ios").items()}
        with open(os.path.join(HERMES, "bands", "rnassets.hbc.v94"), "rb") as handle:
            ipa[f"{APP}/main.jsbundle"] = handle.read()
        ipa[f"{APP}/Info.plist"] = INFO_PLIST.encode("utf-8")
        write_ipa(os.path.join(HERE, "rnassets.ipa"), ipa)
    for item in ("rnassets.apk", "rnassets-js.apk", "rnassets-short.apk", "rnassets-short.map.txt", "rnassets.ipa"):
        path = os.path.join(HERE, item)
        print(item, os.path.getsize(path), sha256(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
