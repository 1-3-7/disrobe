# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KU}#G=3r~J4~akvfqawWas!q{1I<@EN3xoc5m+>FE77>Z6VX~PaAkYF&1ygZsV>jdAHYd'), (b'de4py-jawbreaker' * 4096)))))
