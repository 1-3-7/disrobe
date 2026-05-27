# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KRn}v*AIoC#^cDsG>4jt4jVkDEf|LcQj;T'), (b'de4py-jawbreaker' * 4096)))))
