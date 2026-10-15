"""Dump compiled NIB files (NIBArchive) as reference JSON with the independent `nibarchive`
parser from PyPI (https://github.com/MatrixEditor/nibarchive), for nib_archive_reference.rs.
Each object is [class, [[key, value type, value], ...]]; a data value the parser reads as a
packed number list is {"numbers": [...]}, any other data value is lowercase hex.

Usage: python dump_nib_reference.py <out.json> <file.nib>...
"""

import io
import json
import os
import sys

import nibarchive


def render(value):
    kind = int(value.type)
    data = value.data
    if kind in (8, -1):
        if isinstance(data, list):
            return 8, {'numbers': [float(item) for item in data]}
        return 8, bytes(data).hex()
    if kind in (6, 7):
        return kind, float(data)
    if kind == 9:
        return kind, None
    return kind, data


def dump(path):
    with open(path, 'rb') as handle:
        archive = nibarchive.NIBArchiveParser().parse(io.BytesIO(handle.read()))
    objects = []
    for item in archive.objects:
        values = []
        for value in archive.values[item.values_index:item.values_index + item.value_count]:
            kind, rendered = render(value)
            values.append([archive.keys[value.key_index].name, kind, rendered])
        objects.append([archive.class_names[item.class_name_index].name, values])
    return {
        'format_version': archive.header.unknown_1,
        'coder_version': archive.header.unknown_2,
        'classes': [[name.name, list(name.extras)] for name in archive.class_names],
        'objects': objects,
    }


def main():
    output = sys.argv[1]
    result = {os.path.basename(path): dump(path) for path in sys.argv[2:]}
    with open(output, 'w', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, separators=(',', ':'), sort_keys=True)
        handle.write('\n')


if __name__ == '__main__':
    main()
