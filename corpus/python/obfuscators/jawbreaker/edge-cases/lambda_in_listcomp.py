# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KU}#Rb)QVBI=~AD5oemEis(LD}_F>AyTHX$-6N+uS#avDdnazUnssVF1}T#=zunGCgWsh'), (b'de4py-jawbreaker' * 4096)))))
