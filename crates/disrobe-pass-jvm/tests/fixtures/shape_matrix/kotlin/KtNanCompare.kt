@file:JvmName("KtNanCompare")

fun doubleFlags(a: Double, b: Double): Int {
    var r = 0
    if (a < b) r = r or 1
    if (a <= b) r = r or 2
    if (a > b) r = r or 4
    if (a >= b) r = r or 8
    if (a == b) r = r or 16
    if (a != b) r = r or 32
    if (!(a < b)) r = r or 64
    if (!(a >= b)) r = r or 128
    return r
}

fun floatFlags(a: Float, b: Float): Int {
    var r = 0
    if (a < b) r = r or 1
    if (a <= b) r = r or 2
    if (a > b) r = r or 4
    if (a >= b) r = r or 8
    if (a == b) r = r or 16
    if (a != b) r = r or 32
    if (!(a > b)) r = r or 64
    if (!(a <= b)) r = r or 128
    return r
}

fun lessAsValue(a: Double, b: Double): Boolean = a < b

fun order(a: Double, b: Double): Int = a.compareTo(b)

fun smaller(a: Double, b: Double): Double = if (a < b) a else b
