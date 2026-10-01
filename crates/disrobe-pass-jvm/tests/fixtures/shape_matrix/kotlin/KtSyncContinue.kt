@file:JvmName("KtSyncContinue")

private val LOCK = Any()

fun syncContinue(n: Int): Int {
    var total = 0
    for (i in 0 until n) {
        synchronized(LOCK) {
            if (i % 3 == 0) continue
            total += i
        }
        total *= 2
    }
    return total
}
