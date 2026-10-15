"""Count the Rust symbols of a binary per crate from llvm-nm, the reference for the inventory grade.

llvm-nm lists the defined symbols twice in symbol-table order, once mangled and once
demangled by LLVM's own Itanium and Rust v0 demanglers. A symbol is Rust when its mangled
name (after the one extra leading underscore Mach-O adds) is v0 (_R) or legacy (_ZN with
the 17h<16 hex>E hash). LLVM leaves the legacy $LT$-style escapes in place, so this script
decodes them the way the legacy scheme defines them.

A symbol belongs to the crate its demangled path starts with. For <T as Trait>::item and
<T>::item the self type decides when it is a path; otherwise the trait does. Symbols whose
path starts with neither (a primitive self type without a trait, a bare generic) count as
unattributed.

Usage: python reference_symbols.py <llvm-nm> <binary> <output tsv>
"""

import re
import subprocess
import sys

LEGACY_HASH = re.compile(r'17h[0-9a-f]{16}E')
IDENT = re.compile(r'[A-Za-z0-9_]+')
LIFETIME = re.compile(r"'[A-Za-z0-9_]+ ")
ESCAPES = {'SP': '@', 'BP': '*', 'RF': '&', 'LT': '<', 'GT': '>', 'LP': '(', 'RP': ')', 'C': ','}
PREFIXES = ('&', '*const ', '*mut ', 'mut ', 'dyn ', 'const ')


def nm(tool, binary, demangle):
    command = [tool, '--defined-only', '--no-sort', '--format=just-symbols', binary]
    if demangle:
        command.insert(1, '--demangle')
    return subprocess.run(command, capture_output=True, check=True, text=True).stdout.splitlines()


def scheme(mangled):
    core = mangled
    if not (core.startswith('_ZN') or core.startswith('_R')) and core.startswith('_'):
        core = core[1:]
    if core.startswith('_R') and len(core) > 2 and (core[2].isupper() or core[2].isdigit()):
        return 'v0'
    if core.startswith('_ZN') and LEGACY_HASH.search(core):
        return 'legacy'
    return None


def decode_legacy(text):
    out = []
    for segment in text.split('::'):
        if segment.startswith('_$'):
            segment = segment[1:]
        decoded = []
        index = 0
        while index < len(segment):
            char = segment[index]
            if char == '$':
                close = segment.find('$', index + 1)
                if close == -1:
                    decoded.append(segment[index:])
                    break
                escape = segment[index + 1:close]
                if escape in ESCAPES:
                    decoded.append(ESCAPES[escape])
                elif escape.startswith('u') and re.fullmatch(r'[0-9a-f]+', escape[1:]):
                    decoded.append(chr(int(escape[1:], 16)))
                else:
                    decoded.append(segment[index:close + 1])
                index = close + 1
            elif char == '.' and segment[index + 1:index + 2] == '.':
                decoded.append('::')
                index += 2
            else:
                decoded.append(char)
                index += 1
        out.append(''.join(decoded))
    return '::'.join(out)


def matching_close(text):
    depth = 0
    for index, char in enumerate(text):
        if char == '<':
            depth += 1
        elif char == '>' and not (index > 0 and text[index - 1] == '-'):
            depth -= 1
            if depth == 0:
                return index
    return None


def split_as(inner):
    depth = 0
    index = 0
    while index < len(inner):
        char = inner[index]
        if char in '<([':
            depth += 1
        elif char in ')]' or (char == '>' and not (index > 0 and inner[index - 1] == '-')):
            depth -= 1
        elif depth == 0 and inner.startswith(' as ', index):
            return inner[:index], inner[index + 4:]
        index += 1
    return inner, None


def leading_crate(path):
    text = path
    changed = True
    while changed:
        changed = False
        for prefix in PREFIXES:
            if text.startswith(prefix):
                text = text[len(prefix):]
                changed = True
        lifetime = LIFETIME.match(text)
        if lifetime:
            text = text[lifetime.end():]
            changed = True
    ident = IDENT.match(text)
    if not ident:
        return None
    rest = re.sub(r'^\[[0-9a-f]+\]', '', text[ident.end():])
    return ident.group(0) if rest.startswith('::') else None


def attribute(demangled):
    if demangled.startswith('<'):
        close = matching_close(demangled)
        if close is None:
            return None
        self_type, trait = split_as(demangled[1:close])
        crate = leading_crate(self_type)
        if crate is None and trait is not None:
            crate = leading_crate(trait)
        return crate
    return leading_crate(demangled)


def main():
    tool, binary, output = sys.argv[1:4]
    mangled = nm(tool, binary, False)
    demangled = nm(tool, binary, True)
    if len(mangled) != len(demangled):
        raise SystemExit('llvm-nm listed a different number of symbols with --demangle')
    totals = {'legacy': 0, 'v0': 0, 'unattributed': 0}
    crates = {}
    for raw, text in zip(mangled, demangled):
        kind = scheme(raw)
        if kind is None or text == raw:
            continue
        totals[kind] += 1
        crate = attribute(decode_legacy(text) if kind == 'legacy' else text)
        if crate is None:
            totals['unattributed'] += 1
            continue
        counts = crates.setdefault(crate, {'legacy': 0, 'v0': 0})
        counts[kind] += 1
    version = subprocess.run([tool, '--version'], capture_output=True, check=True, text=True).stdout
    version = next(line.strip() for line in version.splitlines() if 'LLVM version' in line)
    with open(output, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(f'# Rust symbols per crate, llvm-nm ({version}) through reference_symbols.py\n')
        handle.write('# total\tlegacy\tv0\tunattributed\n')
        handle.write(f"total\t{totals['legacy']}\t{totals['v0']}\t{totals['unattributed']}\n")
        handle.write('# crate\tname\tlegacy\tv0\n')
        for name in sorted(crates):
            handle.write(f"crate\t{name}\t{crates[name]['legacy']}\t{crates[name]['v0']}\n")


if __name__ == '__main__':
    main()
