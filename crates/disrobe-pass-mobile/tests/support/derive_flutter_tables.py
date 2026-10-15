"""Derive the tables the Flutter identity report consults.

dart_snapshot_hashes.tsv: the Dart VM stamps each AOT snapshot with the MD5 of
the runtime/vm source files that tools/make_version.py lists in
VM_SNAPSHOT_FILES at the commit it was built from. This script repeats that
computation for every stable tag of https://github.com/dart-lang/sdk from 2.0.0.

flutter_engine_revisions.tsv: for every release tag of
https://github.com/flutter/flutter from 1.0.0, the engine revision pinned in
bin/internal/engine.version and the Dart SDK revision pinned in DEPS (the
flutter repository's own DEPS once the engine moved into it, the engine
repository's DEPS at that revision before), with the Dart version that
revision is tagged as.

Usage: python derive_flutter_tables.py <output directory>
"""

import ast
import concurrent.futures
import hashlib
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

DART_REPOSITORY = 'https://github.com/dart-lang/sdk'
FLUTTER_REPOSITORY = 'https://github.com/flutter/flutter'
RAW = 'https://raw.githubusercontent.com/{repository}/{revision}/{path}'
RELEASE = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)$')
SNAPSHOT_FILES = re.compile(r'(?m)^VM_SNAPSHOT_FILES\s*=\s*(\[[^\]]*\])')
DART_REVISION = re.compile(r"""['"]dart_revision['"]\s*:\s*['"]([0-9a-f]{40})['"]""")
REVISION = re.compile(r'^[0-9a-f]{40}$')


def fetch(repository, revision, path):
    for attempt in range(4):
        try:
            with urllib.request.urlopen(RAW.format(repository=repository, revision=revision, path=path),
                                        timeout=120) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            if attempt == 3:
                raise
        except OSError:
            if attempt == 3:
                raise
    raise AssertionError('unreachable')


def release_tags(repository, minimum_major):
    listing = subprocess.run(['git', 'ls-remote', '--tags', repository], capture_output=True, check=True,
                             text=True).stdout
    commits = {}
    for line in listing.splitlines():
        sha, ref = line.split('\t')
        name = ref.removeprefix('refs/tags/')
        peeled = name.endswith('^{}')
        name = name.removesuffix('^{}')
        match = RELEASE.match(name)
        if match is None or int(match.group(1)) < minimum_major:
            continue
        if peeled or name not in commits:
            commits[name] = sha
    return sorted(commits.items(), key=lambda item: tuple(int(part) for part in RELEASE.match(item[0]).groups()))


def snapshot_hash(tag):
    source = fetch('dart-lang/sdk', tag, 'tools/make_version.py')
    if source is None:
        raise ValueError(f'{tag}: no tools/make_version.py')
    found = SNAPSHOT_FILES.search(source.decode('utf-8'))
    if found is None:
        raise ValueError(f'{tag}: tools/make_version.py has no VM_SNAPSHOT_FILES list')
    names = ast.literal_eval(found.group(1))
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ValueError(f'{tag}: VM_SNAPSHOT_FILES is not a list of file names')
    digest = hashlib.md5()
    for name in names:
        body = fetch('dart-lang/sdk', tag, f'runtime/vm/{name}')
        if body is None:
            raise ValueError(f'{tag}: runtime/vm/{name} is missing')
        digest.update(body)
    return digest.hexdigest()


def flutter_release(tag):
    engine = fetch('flutter/flutter', tag, 'bin/internal/engine.version')
    if engine is None:
        return None
    engine_revision = engine.decode('utf-8').strip()
    if not REVISION.match(engine_revision):
        raise ValueError(f'flutter {tag}: engine.version is not a revision: {engine_revision!r}')
    deps = fetch('flutter/flutter', tag, 'DEPS')
    found = DART_REVISION.search(deps.decode('utf-8')) if deps is not None else None
    if found is None:
        deps = fetch('flutter/engine', engine_revision, 'DEPS')
        found = DART_REVISION.search(deps.decode('utf-8')) if deps is not None else None
    if found is None:
        raise ValueError(f'flutter {tag}: no dart_revision in DEPS')
    return engine_revision, found.group(1)


def main():
    directory = sys.argv[1]
    dart_tags = release_tags(DART_REPOSITORY, 2)
    flutter_tags = release_tags(FLUTTER_REPOSITORY, 1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        hashes = list(pool.map(lambda item: snapshot_hash(item[0]), dart_tags))
        releases = list(pool.map(lambda item: flutter_release(item[0]), flutter_tags))
    with open(os.path.join(directory, 'dart_snapshot_hashes.tsv'), 'w', encoding='utf-8', newline='\n') as handle:
        handle.write('# Dart snapshot hash of every stable Dart SDK tag from 2.0.0, derived from github.com/dart-lang/sdk\n')
        handle.write('# by crates/disrobe-pass-mobile/tests/support/derive_flutter_tables.py: MD5 over the runtime/vm\n')
        handle.write('# files that tools/make_version.py lists in VM_SNAPSHOT_FILES at each tag.\n')
        handle.write('# snapshot_hash\tdart_version\tdart_revision\n')
        for (tag, commit), digest in zip(dart_tags, hashes):
            handle.write(f'{digest}\t{tag}\t{commit}\n')
    dart_versions = {commit: tag for tag, commit in dart_tags}
    rows = 0
    with open(os.path.join(directory, 'flutter_engine_revisions.tsv'), 'w', encoding='utf-8', newline='\n') as handle:
        handle.write('# Engine and Dart SDK revision of every github.com/flutter/flutter release tag from 1.0.0 that\n')
        handle.write('# pins bin/internal/engine.version, derived by\n')
        handle.write('# crates/disrobe-pass-mobile/tests/support/derive_flutter_tables.py; dart_version is empty when\n')
        handle.write('# the pinned Dart revision is not a stable Dart SDK tag.\n')
        handle.write('# engine_revision\tflutter_version\tdart_revision\tdart_version\n')
        for (tag, _commit), release in zip(flutter_tags, releases):
            if release is None:
                continue
            engine_revision, dart_revision = release
            handle.write(f'{engine_revision}\t{tag.removeprefix("v")}\t{dart_revision}\t{dart_versions.get(dart_revision, "")}\n')
            rows += 1
    print(f'{len(dart_tags)} Dart tags, {len(set(hashes))} distinct snapshot hashes; '
          f'{rows} of {len(flutter_tags)} Flutter tags pin an engine')


if __name__ == '__main__':
    main()
