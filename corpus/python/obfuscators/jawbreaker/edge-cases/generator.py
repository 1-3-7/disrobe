# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KU}#G=3s3y0N0sgE?jJ(3uwXHK?Xt^1!y)l|N_^%vC%jAB&8|Uj_hVVKXFu'), (b'de4py-jawbreaker' * 4096)))))
