"""Write the authored asset catalog in corpus/apple/src/Assets.xcassets: an app icon, a
three-scale image set, a colour set and a data set, from deterministic stdlib-made PNGs."""

import json
import pathlib
import struct
import sys
import zlib

root = pathlib.Path(sys.argv[1]) / 'Assets.xcassets'


def png(width, height, colour):
    raw = b''.join(b'\x00' + bytes(colour) * width for _ in range(height))

    def chunk(kind, data):
        body = kind + data
        return struct.pack('>I', len(data)) + body + struct.pack('>I', zlib.crc32(body) & 0xffffffff)

    header = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b'')


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8', newline='\n')


info = {'author': 'xcode', 'version': 1}
write_json(root / 'Contents.json', {'info': info})

icon = root / 'AppIcon.appiconset'
(icon).mkdir(parents=True, exist_ok=True)
(icon / 'icon-1024.png').write_bytes(png(1024, 1024, (32, 96, 160, 255)))
write_json(icon / 'Contents.json', {
    'images': [{'filename': 'icon-1024.png', 'idiom': 'universal', 'platform': 'ios', 'size': '1024x1024'}],
    'info': info,
})

image = root / 'Badge.imageset'
image.mkdir(parents=True, exist_ok=True)
images = []
for scale in (1, 2, 3):
    name = f'badge@{scale}x.png'
    (image / name).write_bytes(png(16 * scale, 12 * scale, (200, 40 + 50 * scale, 20, 255)))
    images.append({'filename': name, 'idiom': 'universal', 'scale': f'{scale}x'})
write_json(image / 'Contents.json', {'images': images, 'info': info})

colour = root / 'AccentTint.colorset'
write_json(colour / 'Contents.json', {
    'colors': [
        {'color': {'color-space': 'srgb', 'components': {'alpha': '1.000', 'blue': '0.200', 'green': '0.400', 'red': '0.800'}},
         'idiom': 'universal'},
        {'appearances': [{'appearance': 'luminosity', 'value': 'dark'}],
         'color': {'color-space': 'srgb', 'components': {'alpha': '1.000', 'blue': '0.900', 'green': '0.700', 'red': '0.300'}},
         'idiom': 'universal'},
    ],
    'info': info,
})

data = root / 'Settings.dataset'
data.mkdir(parents=True, exist_ok=True)
(data / 'settings.json').write_text('{"version": 3, "feature": "fixture"}\n', encoding='utf-8', newline='\n')
write_json(data / 'Contents.json', {
    'data': [{'filename': 'settings.json', 'idiom': 'universal', 'universal-type-identifier': 'public.json'}],
    'info': info,
})
print('written', root)
