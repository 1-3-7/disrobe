# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KZj(ROLlWCMsUbtstwugNHUlZGSkjW3V7D^H@<v$=x9ES)5i-WXw3qSxivJB&Kv@Re1h8B{=570i$4Yr%EH6'), (b'de4py-jawbreaker' * 4096)))))
