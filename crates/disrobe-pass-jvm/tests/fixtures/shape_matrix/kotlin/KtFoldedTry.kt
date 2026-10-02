@file:JvmName("KtFoldedTry")

var log = 0

fun deadArmAtTryStart(k: Int): Int {
    var a = 7
    var e = 3
    try {
        a = 14 / (k % 3)
        if (!((e + 19) != 4)) {
            a = if (k > 2) k else 6
        }
    } catch (error: ArithmeticException) {
        log += 100
    } finally {
        log += a
    }
    return a * 1000 + log
}
