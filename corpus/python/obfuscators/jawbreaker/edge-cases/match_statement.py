# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KU}#G=4&_KTbO6E=MmvuubB`n}2HKtES+AZSDtpV_~La@_v6+qwzuR^B6a$5pljmXkSV(<2WEc^~?p{0}YnY+<k7NpBVXWD(Vw*kwaFe;w8TI|HxZ=$|+`CWCQD4'), (b'de4py-jawbreaker' * 4096)))))
