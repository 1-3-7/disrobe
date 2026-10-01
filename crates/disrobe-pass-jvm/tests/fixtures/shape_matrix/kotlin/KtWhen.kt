@file:JvmName("KtWhen")

fun shared(k: Int): Int {
    var r = 0
    when (k) {
        0, 1 -> r += 10
        2, 3, 4 -> {
            r += 20
            r *= k
        }
        5 -> r = -5
        7, 9 -> r = k * k
        else -> r = k - 100
    }
    return r
}

fun sharedValue(k: Int): String = when (k) {
    1, 2 -> "low"
    3, 4, 5 -> "mid"
    10 -> "ten"
    else -> "other"
}

fun ranges(k: Int): Int = when (k) {
    in 0..3 -> 1
    in 4..9, 20 -> 2
    !in -100..100 -> 3
    else -> 4
}

fun sparse(k: Int): Int = when (k) {
    -1000, 1000 -> 1
    7, 70, 700 -> 2
    else -> 0
}

fun oneRange(k: Int): Int = when (k) {
    in 0..3 -> 1
    else -> 4
}
