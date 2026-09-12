

from __future__ import absolute_import, print_function
import re
import sys
from .csscolors import parse_rgb, css_colors

_PY2 = sys.version_info[0] == 2
string_types = basestring if _PY2 else str

from functools import partial


COLORS = ('black', 'red', 'green', 'yellow', 'blue',
          'magenta', 'cyan', 'white')


STYLES = ('none', 'bold', 'faint', 'italic', 'underline', 'blink',
          'blink2', 'negative', 'concealed', 'crossed')


def is_string(obj):
    return isinstance(obj, string_types)


def _join(*values):
    return ';'.join(str(v) for v in values)


def _color_code(spec, base):
    if is_string(spec):
        spec = spec.strip().lower()

    if spec == 'default':
        return _join(base + 9)
    elif spec in COLORS:
        return _join(base + COLORS.index(spec))
    elif isinstance(spec, int) and 0 <= spec <= 255:
        return _join(base + 8, 5, spec)
    elif isinstance(spec, (tuple, list)):
        return _join(base + 8, 2, _join(*spec))
    else:
        rgb = parse_rgb(spec)

        return _join(base + 8, 2, _join(*rgb))


def color(s, fg=None, bg=None, style=None):
    codes = []

    if fg:
        codes.append(_color_code(fg, 30))
    if bg:
        codes.append(_color_code(bg, 40))
    if style:
        for style_part in style.split('+'):
            if style_part in STYLES:
                codes.append(STYLES.index(style_part))
            else:
                raise ValueError('Invalid style "%s"' % style_part)

    if codes:
        template = '\x1b[{0}m{1}\x1b[0m'
        if _PY2 and isinstance(s, unicode):


            template = unicode(template)
        return template.format(_join(*codes), s)
    else:
        return s


def strip_color(s):
    return re.sub('\x1b\\[(K|.*?m)', '', s)


def ansilen(s):
    return len(strip_color(s))


black = partial(color, fg='black')
red = partial(color, fg='red')
green = partial(color, fg='green')
yellow = partial(color, fg='yellow')
blue = partial(color, fg='blue')
magenta = partial(color, fg='magenta')
cyan = partial(color, fg='cyan')
white = partial(color, fg='white')


bold = partial(color, style='bold')
none = partial(color, style='none')
faint = partial(color, style='faint')
italic = partial(color, style='italic')
underline = partial(color, style='underline')
blink = partial(color, style='blink')
blink2 = partial(color, style='blink2')
negative = partial(color, style='negative')
concealed = partial(color, style='concealed')
crossed = partial(color, style='crossed')
