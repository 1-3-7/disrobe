@file:JvmName("KtFinallyBreak")

fun breakThroughFinally(seed: Int, sink: StringBuilder) {
    val seen: MutableList<Int> = mutableListOf()
    var c = seed
    var d = 1
    for (i in 1 until 8 step 2) {
        d += i
        try {
            c = 6 / ((d + seed) % 3)
            if (seen.contains(c)) break
        } catch (error: ArithmeticException) {
            sink.append('z')
        } finally {
            sink.append(d).append(' ')
        }
        seen.add(c)
    }
    sink.append(c)
}
