"""Build the Android packer mimic fixtures.

Usage: python build.py <jdk bin directory> <r8 jar> <zig executable> <aapt2 executable>

No packer, protector, or third-party app is involved. Every APK here is authored by this
script to reproduce one layout described in public research on that packer (file names,
manifest application class, stub classes, and where documented the payload container).
Class files come from javac, dex files from D8 (r8 jar), the placeholder native libraries
from zig, and every manifest is binary XML written below and checked with
`aapt2 dump xmltree`. The packed payloads are built from original.dex, which is the
reference a recovery is graded against.
"""

import hashlib
import io
import os
import struct
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "build")
ANDROID_NS = "http://schemas.android.com/apk/res/android"
ATTR_NAME = 0x01010003

ORIGINAL_SOURCE = """package com.example.packed;

public final class MainActivity {
    private final String greeting;

    public MainActivity(String greeting) {
        this.greeting = greeting;
    }

    public String render(int count) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < count; i++) {
            out.append(greeting).append(':').append(i).append(';');
        }
        return out.toString();
    }

    public static int checksum(String text) {
        int sum = 7;
        for (int i = 0; i < text.length(); i++) {
            sum = sum * 31 + text.charAt(i);
        }
        return sum;
    }
}
"""

SECOND_SOURCE = """package com.example.packed;

public final class Settings {
    public static final String ENDPOINT = "https://example.invalid/api";

    public static String describe(boolean enabled) {
        return enabled ? "enabled:" + ENDPOINT : "disabled";
    }
}
"""

STUB_LIB_SOURCE = "int stub_marker(void) { return 0; }\n"

RC4_DEXHELPER_KEY = bytes.fromhex("66976ce86d4638b0095aa5d70fcb9aa0")
OPEN_SOURCE_JIAGU_KEY = b"bajk3b4j3bvuoa3h"
OPEN_SOURCE_JIAGU_IV = b"mers46ha35ga23hn"
JIAGU_RC4_KEY = bytes.fromhex("6876997296609f63962c9830c2365142")


def run(command, cwd=None):
    subprocess.run(command, cwd=cwd, check=True)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def compile_java(jdk, r8, name, sources):
    work = os.path.join(BUILD, name)
    os.makedirs(work, exist_ok=True)
    paths = []
    for relative, text in sources.items():
        path = os.path.join(work, "src", relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        paths.append(path)
    classes = os.path.join(work, "classes")
    os.makedirs(classes, exist_ok=True)
    run([os.path.join(jdk, "javac"), "--release", "8", "-g:none", "-d", classes, *paths])
    class_files = []
    for root, _, files in os.walk(classes):
        for file in sorted(files):
            class_files.append(os.path.join(root, file))
    out = os.path.join(work, "dex")
    os.makedirs(out, exist_ok=True)
    run([os.path.join(jdk, "java"), "-cp", r8, "com.android.tools.r8.D8", "--release",
         "--min-api", "21", "--output", out, *sorted(class_files)])
    with open(os.path.join(out, "classes.dex"), "rb") as handle:
        return handle.read()


def stub_dex(jdk, r8, name, class_name):
    package, _, simple = class_name.rpartition(".")
    source = "package {};\n\npublic class {} {{\n    public static String marker() {{\n        return \"stub\";\n    }}\n}}\n".format(package, simple)
    return compile_java(jdk, r8, name, {class_name.replace(".", "/") + ".java": source})


class StringPool:
    def __init__(self, ordered):
        self.strings = list(ordered)

    def index(self, text):
        if text not in self.strings:
            self.strings.append(text)
        return self.strings.index(text)

    def chunk(self):
        offsets = []
        data = bytearray()
        for text in self.strings:
            offsets.append(len(data))
            units = text.encode("utf-16-le")
            data += struct.pack("<H", len(units) // 2) + units + b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"
        header = 28
        strings_start = header + 4 * len(self.strings)
        size = strings_start + len(data)
        out = struct.pack("<HHIIIIII", 0x0001, header, size, len(self.strings), 0, 0, strings_start, 0)
        out += b"".join(struct.pack("<I", o) for o in offsets) + bytes(data)
        return out


def axml_manifest(package, application):
    pool = StringPool(["name", "android", ANDROID_NS, "package", "manifest", "application", package, application])
    resource_map = struct.pack("<HHI", 0x0180, 8, 12) + struct.pack("<I", ATTR_NAME)
    body = bytearray()

    def node(kind, size, extra):
        return struct.pack("<HHIII", kind, 16, size, 1, 0xFFFFFFFF) + extra

    body += node(0x0100, 24, struct.pack("<II", pool.index("android"), pool.index(ANDROID_NS)))

    def start(name, attrs):
        attr_bytes = bytearray()
        for ns, attr, value in attrs:
            ns_index = pool.index(ns) if ns else 0xFFFFFFFF
            value_index = pool.index(value)
            attr_bytes += struct.pack("<IIIHBBI", ns_index, pool.index(attr), value_index, 8, 0, 0x03, value_index)
        extra = struct.pack("<IIHHHHHH", 0xFFFFFFFF, pool.index(name), 0x14, 0x14, len(attrs), 0, 0, 0)
        return node(0x0102, 16 + len(extra) + len(attr_bytes), extra + bytes(attr_bytes))

    def end(name):
        return node(0x0103, 24, struct.pack("<II", 0xFFFFFFFF, pool.index(name)))

    body += start("manifest", [(None, "package", package)])
    body += start("application", [(ANDROID_NS, "name", application)])
    body += end("application")
    body += end("manifest")
    body += node(0x0101, 24, struct.pack("<II", pool.index("android"), pool.index(ANDROID_NS)))
    content = pool.chunk() + resource_map + bytes(body)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(content)) + content


def rc4(key, data):
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


def aes_cbc_encrypt(jdk, key, iv, plaintext):
    work = os.path.join(BUILD, "aes")
    os.makedirs(work, exist_ok=True)
    plain_path = os.path.join(work, "plain.bin")
    cipher_path = os.path.join(work, "cipher.bin")
    with open(plain_path, "wb") as handle:
        handle.write(plaintext)
    source = os.path.join(work, "Encrypt.java")
    with open(source, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "import javax.crypto.Cipher;\n"
            "import javax.crypto.spec.IvParameterSpec;\n"
            "import javax.crypto.spec.SecretKeySpec;\n"
            "import java.nio.file.Files;\n"
            "import java.nio.file.Paths;\n"
            "public class Encrypt {\n"
            "  public static void main(String[] args) throws Exception {\n"
            "    Cipher cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n"
            "    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(args[0].getBytes(\"US-ASCII\"), \"AES\"), new IvParameterSpec(args[1].getBytes(\"US-ASCII\")));\n"
            "    Files.write(Paths.get(args[3]), cipher.doFinal(Files.readAllBytes(Paths.get(args[2]))));\n"
            "  }\n"
            "}\n"
        )
    run([os.path.join(jdk, "java"), source, key.decode(), iv.decode(), plain_path, cipher_path])
    with open(cipher_path, "rb") as handle:
        return handle.read()


def write_apk(name, entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, data in entries:
            info = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if path.endswith((".so", ".arsc")) else zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    data = buffer.getvalue()
    with open(os.path.join(HERE, name), "wb") as handle:
        handle.write(data)
    return data


def main():
    jdk, r8, zig, aapt2 = sys.argv[1:5]
    os.makedirs(BUILD, exist_ok=True)
    original = compile_java(jdk, r8, "original", {
        "com/example/packed/MainActivity.java": ORIGINAL_SOURCE,
        "com/example/packed/Settings.java": SECOND_SOURCE,
    })
    with open(os.path.join(HERE, "original.dex"), "wb") as handle:
        handle.write(original)
    second = compile_java(jdk, r8, "second", {"com/example/packed/Settings.java": SECOND_SOURCE})
    with open(os.path.join(HERE, "second.dex"), "wb") as handle:
        handle.write(second)

    lib_source = os.path.join(BUILD, "stub.c")
    with open(lib_source, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(STUB_LIB_SOURCE)
    lib_path = os.path.join(BUILD, "libstub.so")
    run([zig, "cc", "-target", "aarch64-linux-gnu", "-shared", "-O2", "-s", "-o", lib_path, lib_source])
    with open(lib_path, "rb") as handle:
        native = handle.read()

    package = "com.example.packed"

    def manifest(application):
        return ("AndroidManifest.xml", axml_manifest(package, application))

    built = {}

    stub = stub_dex(jdk, r8, "jiagu_legacy", "com.qihoo.util.StubApplication")
    built["jiagu-legacy.apk"] = [manifest("com.qihoo.util.StubApplication"), ("classes.dex", stub),
                                 ("assets/libprotectClass.so", native), ("assets/libprotectClass_x86.so", native),
                                 ("assets/libqupc.so", native)]

    stub = stub_dex(jdk, r8, "jiagu", "com.stub.StubApp")
    tail = b"qh\x00\x01" + rc4(JIAGU_RC4_KEY, original[:256])
    built["jiagu.apk"] = [manifest("com.stub.StubApp"), ("classes.dex", stub + tail),
                          ("assets/libjiagu.so", native), ("assets/libjiagu_a64.so", native),
                          ("assets/libjiagu_x86.so", native)]

    stub = stub_dex(jdk, r8, "bangcle", "com.bangcle.protect.ApplicationWrapper")
    built["bangcle.apk"] = [manifest("com.bangcle.protect.ApplicationWrapper"), ("classes.dex", stub),
                            ("lib/armeabi/libsecexe.so", native), ("lib/armeabi/libsecmain.so", native),
                            ("assets/bangcle_classes.jar", rc4(b"runtime-only-key", original)),
                            ("assets/bangcleplugin/container.dex", stub)]

    large_source = "package com.example.packed;\n\npublic final class Catalog {\n"
    for index in range(3000):
        large_source += "    public static String entry{0}() {{ return \"catalog entry {0} of the packed fixture\"; }}\n".format(index)
    large_source += "}\n"
    large = compile_java(jdk, r8, "large", {"com/example/packed/Catalog.java": large_source})
    with open(os.path.join(HERE, "large.dex"), "wb") as handle:
        handle.write(large)
    stub = stub_dex(jdk, r8, "dexhelper", "com.secneo.apkwrapper.ApplicationWrapper")
    head = rc4(RC4_DEXHELPER_KEY, large[:0x20000])
    rest = bytes(b ^ 0xAC for b in large[0x20000:])
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as jar:
        info = zipfile.ZipInfo("classes.dex", date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        jar.writestr(info, head + rest)
    built["dexhelper.apk"] = [manifest("com.secneo.apkwrapper.ApplicationWrapper"), ("classes.dex", stub),
                              ("lib/arm64-v8a/libDexHelper.so", native),
                              ("assets/classes0.jar", inner.getvalue())]

    stub = stub_dex(jdk, r8, "ijiami", "com.shell.SuperApplication")
    built["ijiami.apk"] = [manifest("com.shell.SuperApplication"), ("classes.dex", stub),
                           ("lib/armeabi/libexec.so", native), ("lib/armeabi/libexecmain.so", native),
                           ("assets/ijiami.dat", rc4(b"runtime-only-key", original)),
                           ("META-INF/signed.bin", b"\x00" * 32)]

    stub = stub_dex(jdk, r8, "legu", "com.tencent.StubShell.TxAppEntry")
    built["legu.apk"] = [manifest("com.tencent.StubShell.TxAppEntry"), ("classes.dex", stub),
                         ("lib/armeabi-v7a/libshella-4.1.0.18.so", native),
                         ("lib/armeabi-v7a/libshell-super.2019.so", native),
                         ("assets/0OO00l111l1l", rc4(b"runtime-only-key", original)),
                         ("assets/tosversion", b"4.1.0.18\n")]

    stub = stub_dex(jdk, r8, "baidu", "com.baidu.protect.StubApplication")
    built["baidu.apk"] = [manifest("com.baidu.protect.StubApplication"), ("classes.dex", stub),
                          ("lib/armeabi/libbaiduprotect.so", native),
                          ("assets/baiduprotect1.jar", rc4(b"runtime-only-key", original))]

    stub = stub_dex(jdk, r8, "alibaba", "com.ali.mobisecenhance.StubApplication")
    built["alibaba.apk"] = [manifest("com.ali.mobisecenhance.StubApplication"), ("classes.dex", stub),
                            ("lib/armeabi/libmobisec.so", native), ("lib/armeabi/libmobisecy1.so", native)]

    stub = stub_dex(jdk, r8, "dexprotector", "com.licel.dexprotector.ProtectedApplication")
    built["dexprotector.apk"] = [manifest("com.licel.dexprotector.ProtectedApplication"), ("classes.dex", stub),
                                 ("lib/arm64-v8a/libdexprotector.so", native),
                                 ("assets/classes.dex.dat", rc4(b"runtime-only-key", original)),
                                 ("assets/dp.mp3", b"\x00" * 64)]

    stub = stub_dex(jdk, r8, "appguard", "com.inca.security.Core.AppGuardEngine")
    built["appguard.apk"] = [manifest("com.example.packed.App"), ("classes.dex", stub),
                             ("assets/appguard/arm64-v8a/libengine.sox", b"SOX\x01" + b"\x00" * 60),
                             ("assets/appguard/arm64-v8a/libstub.sox", b"SOX\x01" + b"\x00" * 60)]

    stub = stub_dex(jdk, r8, "promon", "no.promon.shield.Shield")
    built["promon.apk"] = [manifest("com.example.packed.App"), ("classes.dex", stub),
                           ("lib/arm64-v8a/libshield.so", native), ("assets/pbi.bin", b"\x00" * 80),
                           ("assets/mappings.bin", b"\x00" * 16), ("assets/config-encrypt.txt", b"\x00" * 16)]

    stub = stub_dex(jdk, r8, "pangxie", "com.merry.wapper.WapperApplication")
    built["pangxie.apk"] = [manifest("com.merry.wapper.WapperApplication"), ("classes.dex", stub),
                            ("lib/armeabi/libnsecure.so", native),
                            ("assets/packed.dex", bytes(b ^ 0x54 for b in original))]

    stub = stub_dex(jdk, r8, "open_source_jiagu", "com.frezrik.jiagu.StubApp")
    name = b"com.example.packed.App"
    block = bytes([len(name)]) + name + struct.pack(">I", len(original)) + original
    block += struct.pack(">I", len(second)) + bytes(b ^ 0x66 for b in second[:112]) + second[112:]
    encrypted = aes_cbc_encrypt(jdk, OPEN_SOURCE_JIAGU_KEY, OPEN_SOURCE_JIAGU_IV, block[:512])
    packed = stub + encrypted + block[512:] + struct.pack(">I", len(stub))
    built["open-source-jiagu.apk"] = [manifest("com.frezrik.jiagu.StubApp"), ("classes.dex", packed),
                                      ("lib/arm64-v8a/libjiagu.so", native)]

    for name, entries in sorted(built.items()):
        data = write_apk(name, entries)
        dump = subprocess.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", os.path.join(HERE, name)],
                              check=True, capture_output=True, text=True).stdout
        with open(os.path.join(HERE, name + ".xmltree.txt"), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(dump.replace("\r\n", "\n"))
        print(name, len(data), sha256(data))
    for name in ("original.dex", "second.dex", "large.dex"):
        with open(os.path.join(HERE, name), "rb") as handle:
            data = handle.read()
        print(name, len(data), sha256(data))


if __name__ == "__main__":
    main()
