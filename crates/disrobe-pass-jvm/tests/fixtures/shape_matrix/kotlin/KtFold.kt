@file:JvmName("KtFold")

fun sink(a: Int, b: Int): Int = a * 1000 + b

fun afterIncrement(a: Int): Int {
    var n = 10
    n++
    return sink(a, n * 2)
}

fun incrementAsValue(a: Int): Int {
    var n = a
    val before = n++
    val after = ++n
    return sink(before + after, n)
}

fun incrementInLoop(a: Int): Int {
    var n = 3
    for (i in 0 until a) {
        n += 2
    }
    return sink(a, n * 2)
}

fun incrementOnBranch(b: Boolean): Int {
    var n = 4
    if (b) {
        n--
    }
    return sink(n, n + 1)
}

fun foldAcross(a: Int): Int {
    var n = 7
    val first = n * 3
    n += a
    var acc = 0
    for (i in 1..a) {
        acc += n++
    }
    return sink(first + acc, n * 3)
}
