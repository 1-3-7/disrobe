package fixture

import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

var stored: Continuation<Any?>? = null
var storedInt: Continuation<Int>? = null

suspend fun unusedContinuation(): Int = 7

fun readContinuation(continuation: Continuation<Any?>): Any? = continuation.context

fun returnContinuation(continuation: Continuation<Any?>): Any? = continuation

fun forwardContinuation(continuation: Continuation<Any?>): Any? = returnContinuation(continuation)

fun callContinuation(continuation: Continuation<Any?>): Any? {
    continuation.resume(null)
    return null
}

fun storeContinuation(continuation: Continuation<Any?>): Any? {
    stored = continuation
    return null
}

suspend fun suspendedStateMachine(): Int = suspendCoroutine { continuation -> continuation.resume(9) }

suspend fun suspensionPoint(): Int = suspendCoroutine { continuation -> storedInt = continuation }

suspend fun actualStateMachine(): Int = suspensionPoint() + suspensionPoint()
