@file:JvmName("KtCountLoop")

fun step(x: Int): Int = (x * 3 + 1) and 0xFF

fun checked(x: Int): Int {
    if (x > 100) {
        throw IllegalStateException("big")
    }
    return x * 2 + 1
}

fun countUntilReturn(seed: Int): Int {
    var x = seed
    var count = 0
    while (true) {
        if (x % 2 == 0) count++
        x = step(x)
        if (x > 200) return count * 1000 + x
        if (count > 50) return -count
    }
}

fun countUntilBreak(seed: Int, limit: Int): Int {
    var x = seed
    var count = 0
    var steps = 0
    while (true) {
        if ((x and 1) == 1) count++
        steps++
        x = step(x + steps)
        if (steps >= limit) break
    }
    return count * 100 + steps
}

fun countUntilThrow(seed: Int): Int {
    var count = 0
    var x = seed
    try {
        while (true) {
            if (x % 3 == 0) count++
            x = checked(x)
        }
    } catch (e: IllegalStateException) {
        return count * 1000 + x
    }
}
