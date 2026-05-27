# Jawbreaker (de4py target) bake
import base64, zlib
__jawbreaker__ = '1'
exec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode(b'9KQkmvL~ofV<v^1>#|Vuj$$AL(gr=iY)ezoR(UPq6n3$W1TuiQyP|G=rUD}`*6JIGKnld!CPst?YSsamNp88j#^x+mJ?cZfGaD)sM)M1g&?>)Z8!naw?d02NM{Y5vn@*|vO$zt6bmVcH4~y8cfc4$_RHt|W'), (b'de4py-jawbreaker' * 4096)))))
