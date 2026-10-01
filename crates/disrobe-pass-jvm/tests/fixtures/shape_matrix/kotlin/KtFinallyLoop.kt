@file:JvmName("KtFinallyLoop")

fun finallyInLoop(n: Int): Int {
    var total = 0
    for (i in 0 until n) {
        try {
            if (i == 2) continue
            if (i == 5) break
            total += i
        } finally {
            total += 100
        }
    }
    return total
}
