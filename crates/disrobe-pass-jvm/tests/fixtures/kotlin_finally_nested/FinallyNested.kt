package probe

object FinallyNested {
    @JvmStatic
    fun compute(value: Int, divisor: Int): Int {
        var result = 0
        try {
            result = 100 / value
        } finally {
            try {
                result += 10 / divisor
            } catch (error: ArithmeticException) {
                result = -1
            }
        }
        return result
    }
}
