"""Derive the rustc release table the Rust binary inventory consults.

Every stable release of Rust is a tag X.Y.Z of https://github.com/rust-lang/rust. The tag
peels to the commit `rustc -vV` reports as commit-hash, and the standard library shipped
with that release records the same commit in its /rustc/<commit>/library/... panic paths.
This script lists the tags with `git ls-remote --tags`, keeps the X.Y.Z ones, peels
annotated tags to their commit and writes one line per release, ordered by version.

Usage: python derive_rustc_releases.py <output tsv>
"""

import re
import subprocess
import sys

REPOSITORY = 'https://github.com/rust-lang/rust.git'
RELEASE = re.compile(r'^(\d+)\.(\d+)\.(\d+)$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')


def releases():
    listing = subprocess.run(['git', 'ls-remote', '--tags', REPOSITORY], capture_output=True, check=True,
                             text=True).stdout
    direct = {}
    peeled = {}
    for line in listing.splitlines():
        sha, ref = line.split('\t')
        if not COMMIT.match(sha) or not ref.startswith('refs/tags/'):
            continue
        name = ref.removeprefix('refs/tags/')
        if name.endswith('^{}'):
            peeled[name.removesuffix('^{}')] = sha
        else:
            direct[name] = sha
    table = []
    for name, sha in direct.items():
        match = RELEASE.match(name)
        if match is None:
            continue
        version = tuple(int(part) for part in match.groups())
        if version < (1, 0, 0):
            continue
        table.append((version, name, peeled.get(name, sha)))
    table.sort()
    return table


def main():
    output = sys.argv[1]
    table = releases()
    commits = [commit for _, _, commit in table]
    if len(commits) != len(set(commits)):
        raise SystemExit('two release tags peel to one commit')
    with open(output, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write('# Commit of every stable Rust release tag from 1.0.0, derived from github.com/rust-lang/rust\n')
        handle.write('# by crates/disrobe-pass-nativelang/tests/support/derive_rustc_releases.py: git ls-remote\n')
        handle.write('# --tags, X.Y.Z tags only, annotated tags peeled to the commit rustc -vV reports.\n')
        handle.write('# version\tcommit\n')
        for _, name, commit in table:
            handle.write(f'{name}\t{commit}\n')


if __name__ == '__main__':
    main()
