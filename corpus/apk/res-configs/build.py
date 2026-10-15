"""Build the resource configuration fixture.

usage: python build.py <aapt2>

Writes one values directory per qualifier below, each holding the string resource
"label" whose value is the directory name, compiles and links them with aapt2, and records
`aapt2 dump resources` and `aapt2 dump configurations` over the linked APK as the reference
for how each binary ResTable_config reads back.
"""

import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
QUALIFIERS = [
    "",
    "fr",
    "fr-rCA",
    "zh-rTW",
    "b+sr+Latn",
    "b+es+419",
    "b+ast",
    "b+de+DE+1901",
    "mcc310",
    "mcc310-mnc004",
    "feminine",
    "masculine",
    "neuter",
    "ldrtl",
    "ldltr",
    "sw600dp",
    "w820dp",
    "h720dp",
    "small",
    "xlarge",
    "long",
    "notlong",
    "round",
    "notround",
    "widecg",
    "nowidecg",
    "highdr",
    "lowdr",
    "land",
    "port",
    "car",
    "desk",
    "television",
    "appliance",
    "watch",
    "vrheadset",
    "night",
    "notnight",
    "ldpi",
    "tvdpi",
    "xxxhdpi",
    "420dpi",
    "nodpi",
    "anydpi",
    "notouch",
    "finger",
    "keysexposed",
    "keyshidden",
    "keyssoft",
    "nokeys",
    "qwerty",
    "12key",
    "navexposed",
    "navhidden",
    "nonav",
    "dpad",
    "trackball",
    "wheel",
    "v21",
    "v26",
    "fr-rFR-land-night-xhdpi-v26",
    "mcc208-mnc10-fr-rFR-ldrtl-sw600dp-w720dp-h1024dp-large-long-round-widecg-highdr-land-car-night-xhdpi-finger-keyshidden-qwerty-navhidden-dpad-v28",
]
MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.disrobe.resconfigs">\n  <application />\n</manifest>\n'
)


def sha256(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def dump(aapt2: str, kind: str, apk: str, out: str) -> None:
    text = subprocess.run(
        [aapt2, "dump", kind, apk], check=True, capture_output=True
    ).stdout.replace(b"\r\n", b"\n")
    with open(out, "wb") as handle:
        handle.write(text)


def main() -> int:
    aapt2 = sys.argv[1]
    with tempfile.TemporaryDirectory() as scratch:
        for qualifier in QUALIFIERS:
            folder = "values" + ("-" + qualifier if qualifier else "")
            directory = os.path.join(scratch, "res", folder)
            os.makedirs(directory)
            with open(os.path.join(directory, "strings.xml"), "w", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    '<?xml version="1.0" encoding="utf-8"?>\n'
                    f'<resources>\n  <string name="label">{folder}</string>\n</resources>\n'
                )
        manifest = os.path.join(scratch, "AndroidManifest.xml")
        with open(manifest, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(MANIFEST)
        compiled = os.path.join(scratch, "compiled.zip")
        subprocess.run([aapt2, "compile", "--dir", os.path.join(scratch, "res"), "-o", compiled], check=True)
        apk = os.path.join(HERE, "configs.apk")
        subprocess.run([aapt2, "link", "-o", apk, "--manifest", manifest, compiled], check=True)
    dump(aapt2, "resources", apk, os.path.join(HERE, "configs.apk.resources.txt"))
    dump(aapt2, "configurations", apk, os.path.join(HERE, "configs.apk.configurations.txt"))
    for item in ("configs.apk", "configs.apk.resources.txt", "configs.apk.configurations.txt"):
        path = os.path.join(HERE, item)
        print(item, os.path.getsize(path), sha256(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
