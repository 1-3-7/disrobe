@file:JvmName("KtLongCompare")

fun order(a: Long, b: Long): Int = a.compareTo(b)

fun orderPlus(a: Long, b: Long): Int = a.compareTo(b) * 10 + if (a < b) 1 else 0

fun asConditions(a: Long, b: Long): Int {
    var r = 0
    if (a.compareTo(b) > 0) r += 1
    if (a.compareTo(b) <= 0) r += 10
    if (b.compareTo(a) == 0) r += 100
    if (a > b) r += 1000
    if (a != b) r += 10000
    return r
}

fun intOrder(a: Long, b: Long): Int = a.toInt().compareTo(b.toInt())
