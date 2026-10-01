@file:JvmName("KtSyncLoop")

private val LOCK = Any()

fun syncSum(n: Int): Int {
    var total = 0
    for (i in 0 until n) {
        synchronized(LOCK) {
            total += i
        }
    }
    return total
}

fun syncBreak(n: Int, stop: Int): Int {
    var total = 0
    for (i in 0 until n) {
        synchronized(LOCK) {
            if (i == stop) break
            total += i * 2
        }
    }
    return total
}

fun syncValue(n: Int): Int {
    var total = 0
    var i = 0
    while (i < n) {
        total += synchronized(LOCK) { i * i + 1 }
        i++
    }
    return total
}
