@file:JvmName("KtStateMachine")

fun walk(seed: Int): String {
    val sb = StringBuilder()
    var state = 0
    var steps = 0
    while (state != 4 && steps < 20) {
        steps++
        when (state) {
            0 -> {
                sb.append('a')
                state = if (seed % 3 == 0) 2 else 1
            }
            1 -> {
                sb.append(state)
                state = if (state + seed > 3) 3 else 2
            }
            2 -> {
                sb.append('c').append(state * seed)
                state = 3
            }
            3 -> {
                sb.append('d')
                state = if (sb.length > 5) 4 else 0
            }
            else -> state = 4
        }
    }
    return sb.toString() + ":" + steps
}

fun dispatch(seed: Int): Int {
    var state = seed % 3
    var acc = seed
    while (true) {
        when (state) {
            0 -> {
                acc = acc * 7 + 1
                state = if (acc % 2 == 0) 1 else 2
            }
            1 -> {
                acc -= 3
                if (acc < 0) return acc
                state = 2
            }
            2 -> {
                acc += state * 11
                if (acc > 500) return acc
                state = 0
            }
            else -> return -1
        }
    }
}
