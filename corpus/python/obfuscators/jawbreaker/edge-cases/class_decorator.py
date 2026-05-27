# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KU}#G=3r|I;^EFuR^oNhBq{FS!QKLBlary`^g2_bT?q?bGt$-T1#KAVxkrUUFBc^T*^*&U`a}VHY*X-WN5$tw&9^o{_UkrFQzP^HBGl_b1zD8%23km1UF^('), (b'de4py-jawbreaker' * 4096)))))
