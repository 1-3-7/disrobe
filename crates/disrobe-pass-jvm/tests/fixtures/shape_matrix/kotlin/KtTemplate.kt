@file:JvmName("KtTemplate")

fun describe(a: Int, b: Long, c: Double, d: Char, flag: Boolean): String =
    "a=$a b=${b + 1} c=$c d=$d f=$flag [${a * 2}]"

fun nested(a: Int): String {
    val inner = "<$a>"
    return "$inner$inner|${inner.length}"
}

fun withNull(a: Int): String {
    val s: String? = if (a > 0) "p$a" else null
    return "v=$s"
}

fun loopConcat(n: Int): String {
    var s = ""
    for (i in 0 until n) {
        s += "$i,"
    }
    return s
}
