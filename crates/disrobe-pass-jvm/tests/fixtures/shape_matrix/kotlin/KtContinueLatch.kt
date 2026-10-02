@file:JvmName("KtContinueLatch")

fun continueLatch(seed: Int, sink: StringBuilder) {
    var b = seed
    var c: Int
    l1@ for (i in 1 until 7 step 2) {
        c = (seed + i) % 1000
        if (c > 9) {
            var n = 0
            do {
                n++
                sink.append('a')
                b = b * b % 1000
                if (b > 300) continue@l1
            } while (n < 1 && (b % 3 >= 1 || n == 1))
            sink.append('d')
        }
        sink.append(c).append(' ')
    }
    sink.append(b)
}
