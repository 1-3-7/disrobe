@file:JvmName("KtWhenString")

fun byName(k: Int): Int {
    val name = when (k % 4) {
        0 -> "alpha"
        1 -> "beta"
        2 -> "gamma"
        else -> "delta"
    }
    return when (name) {
        "alpha", "gamma" -> 1
        "beta" -> 2
        else -> 3
    }
}
