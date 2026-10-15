"""Write the authored asset catalog in corpus/apple/src/Assets.xcassets: a patterned app icon,
a three-scale patterned image set, a grey image set, a lossless image set, a colour set and a
data set, from deterministic stdlib-made PNGs whose every opaque pixel follows icon_colour,
badge_colour or mono_colour, so a decoder is graded on pixel values, row order and channel
order."""

import json
import pathlib
import struct
import sys
import zlib

root = pathlib.Path(sys.argv[1]) / 'Assets.xcassets'


def icon_colour(x, y):
    return ((x >> 2) & 0xff, (y >> 2) & 0xff, (((x >> 6) + (y >> 6)) * 16) & 0xff, 255)


def badge_colour(scale, x, y):
    return ((x * 37 + scale * 11) % 256, (y * 53) % 256, ((x + y) * 29) % 256, 255)


def mono_colour(x, y):
    grey = (x * 4 + y * 3) & 0xff
    return (grey, grey, grey, 255)


def png(width, height, colour):
    def row(y):
        pixels = b''.join(bytes(colour(x, y)) for x in range(width))
        return b'\x01' + bytes((pixels[i] - (pixels[i - 4] if i >= 4 else 0)) & 0xff for i in range(len(pixels)))

    raw = b''.join(row(y) for y in range(height))

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
(icon / 'icon-1024.png').write_bytes(png(1024, 1024, icon_colour))
write_json(icon / 'Contents.json', {
    'images': [{'filename': 'icon-1024.png', 'idiom': 'universal', 'platform': 'ios', 'size': '1024x1024'}],
    'info': info,
})

image = root / 'Badge.imageset'
image.mkdir(parents=True, exist_ok=True)
images = []
for scale in (1, 2, 3):
    name = f'badge@{scale}x.png'
    (image / name).write_bytes(png(16 * scale, 12 * scale, lambda x, y, s=scale: badge_colour(s, x, y)))
    images.append({'filename': name, 'idiom': 'universal', 'scale': f'{scale}x'})
write_json(image / 'Contents.json', {'images': images, 'info': info})

mono = root / 'Mono.imageset'
mono.mkdir(parents=True, exist_ok=True)
(mono / 'mono.png').write_bytes(png(64, 48, mono_colour))
write_json(mono / 'Contents.json', {
    'images': [{'filename': 'mono.png', 'idiom': 'universal'}],
    'info': info,
})

lossless = root / 'BadgeLossless.imageset'
lossless.mkdir(parents=True, exist_ok=True)
(lossless / 'badge-lossless.png').write_bytes(png(48, 36, lambda x, y: badge_colour(3, x, y)))
write_json(lossless / 'Contents.json', {
    'images': [{'filename': 'badge-lossless.png', 'idiom': 'universal'}],
    'info': info,
    'properties': {'compression-type': 'lossless'},
})

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
