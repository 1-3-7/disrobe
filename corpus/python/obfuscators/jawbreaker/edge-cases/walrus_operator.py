# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KRnswFD<jA<`%9?~YHstf_q^spUD*#W%XCN<&DaG}2=ruK7MO!#5&IHQa|FWakFJe~_-@^|sD&>{lpUWbHFz'), (b'de4py-jawbreaker' * 4096)))))
