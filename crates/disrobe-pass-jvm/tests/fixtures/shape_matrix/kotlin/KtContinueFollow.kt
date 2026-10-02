@file:JvmName("KtContinueFollow")

fun continueFollow(seed: Int, sink: StringBuilder) {
    var c = seed
    var n = 0
    l1@ while (n < 4) {
        n++
        for (i in 2 until 9 step 3) {
            c = (c * 7 + i) % 100
            if (c < 30) continue@l1
        }
        sink.append(c).append(' ')
    }
    sink.append(-c)
}
