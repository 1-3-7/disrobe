@file:JvmName("KtFinally")

var counter = 0

fun returnInTry(a: Int): Int {
    try {
        counter += 1
        return 100 / a
    } finally {
        counter += 10
    }
}

fun nestedFinally(a: Int, b: Int): Int {
    var r = 0
    try {
        try {
            r = 100 / a
        } finally {
            r += 1
        }
    } catch (e: ArithmeticException) {
        r = -1
    } finally {
        r += 1000 / (b + 1)
    }
    return r
}

fun tryAsValue(a: Int): Int {
    val v = try {
        10 / a
    } catch (e: ArithmeticException) {
        -1
    } finally {
        counter++
    }
    return v * 2
}
