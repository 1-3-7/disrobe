package disrobe.sample

class Greeter(val name: String) {
    val greeting: String
        get() = "Hello, $name"

    fun greet(): String = greeting

    fun shout(times: Int): String = greeting.repeat(times)
}
