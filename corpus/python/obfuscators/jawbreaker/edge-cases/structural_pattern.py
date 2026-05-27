# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KU}#G=8G5yD6hhvEPRvWasF#>&a&1b!v5C^LXwdanIp9QzkgH+IBb*b>GpD?>E0Y6FeXx*Gk91)k7-NU@&V;FK85)4$CfO{iu7C'), (b'de4py-jawbreaker' * 4096)))))
