import kotlin.coroutines.Continuation

suspend fun scriptUnused(): Int = 11

fun scriptRead(continuation: Continuation<Any?>): Any? = continuation.context
