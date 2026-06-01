@file:JvmName("EdgeCasesKt")

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.fold
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sqrt

const val GREETING_KT: String = "hello from kotlin"
const val MAGIC_KT: Int = 0xCAFEBABE.toInt()
val GOLDEN_KT: Double = 1.6180339887498949

data class Point(val x: Double, val y: Double) {
    val magnitude: Double get() = sqrt(x * x + y * y)
    operator fun plus(other: Point): Point = Point(x + other.x, y + other.y)
    operator fun minus(other: Point): Point = Point(x - other.x, y - other.y)
    operator fun times(k: Double): Point = Point(x * k, y * k)
    infix fun dot(other: Point): Double = x * other.x + y * other.y
}

data class User(val id: Long, val name: String, val tags: Set<String>) {
    fun renameTo(newName: String): User = copy(name = newName)
}

sealed interface ApiResult<out T> {
    data class Ok<T>(val value: T) : ApiResult<T>
    data class Err(val code: Int, val message: String) : ApiResult<Nothing>
    data object Pending : ApiResult<Nothing>
}

fun <T> ApiResult<T>.unwrapOr(default: T): T = when (this) {
    is ApiResult.Ok -> value
    is ApiResult.Err -> default
    ApiResult.Pending -> default
}

fun <T, R> ApiResult<T>.mapOk(transform: (T) -> R): ApiResult<R> = when (this) {
    is ApiResult.Ok -> ApiResult.Ok(transform(value))
    is ApiResult.Err -> this
    ApiResult.Pending -> ApiResult.Pending
}

@JvmInline
value class UserId(val raw: Long) {
    init {
        require(raw >= 0) { "negative user id" }
    }
    fun next(): UserId = UserId(raw + 1)
}

@JvmInline
value class Money(val cents: Long) {
    operator fun plus(other: Money): Money = Money(cents + other.cents)
    operator fun times(k: Int): Money = Money(cents * k)
    fun asFloat(): Double = cents / 100.0
}

sealed class Shape {
    abstract fun area(): Double

    class Circle(val radius: Double) : Shape() {
        override fun area(): Double = PI * radius * radius
    }

    class Rectangle(val width: Double, val height: Double) : Shape() {
        override fun area(): Double = width * height
    }

    class Triangle(val base: Double, val height: Double) : Shape() {
        override fun area(): Double = 0.5 * base * height
    }

    data object Empty : Shape() {
        override fun area(): Double = 0.0
    }
}

fun describeShape(s: Shape): String = when (s) {
    is Shape.Circle -> "circle:${s.area()}"
    is Shape.Rectangle -> "rect:${s.area()}"
    is Shape.Triangle -> "tri:${s.area()}"
    Shape.Empty -> "empty"
}

fun totalArea(shapes: List<Shape>): Double = shapes.sumOf(Shape::area)

enum class Direction(val dx: Int, val dy: Int) {
    NORTH(0, 1),
    EAST(1, 0),
    SOUTH(0, -1),
    WEST(-1, 0);

    fun turn(): Direction = when (this) {
        NORTH -> EAST
        EAST -> SOUTH
        SOUTH -> WEST
        WEST -> NORTH
    }

    fun opposite(): Direction = turn().turn()
}

class CountingMap<K> {
    private val store: MutableMap<K, Int> = mutableMapOf()

    fun bump(k: K): Int {
        val v: Int = (store[k] ?: 0) + 1
        store[k] = v
        return v
    }

    fun snapshot(): Map<K, Int> = store.toMap()
    fun keys(): Set<K> = store.keys

    operator fun get(k: K): Int = store[k] ?: 0
    operator fun set(k: K, v: Int) { store[k] = v }

    companion object {
        fun <K> of(vararg pairs: Pair<K, Int>): CountingMap<K> {
            val cm: CountingMap<K> = CountingMap()
            pairs.forEach { (k: K, v: Int) -> cm[k] = v }
            return cm
        }
    }
}

fun String.shoutLike(): String = "$this!!"
fun String.wordCount(): Int = trim().split(Regex("\\s+")).count { it.isNotEmpty() }

fun Int.isPrime(): Boolean {
    if (this < 2) return false
    if (this < 4) return true
    if (this and 1 == 0) return false
    var i: Int = 3
    while (i.toLong() * i <= this) {
        if (this % i == 0) return false
        i += 2
    }
    return true
}

fun <T> List<T>.second(): T = this[1]
fun <T> List<T>.thirdOrNull(): T? = getOrNull(2)

inline fun <T, R> withTiming(label: String, block: () -> R): Pair<R, Long> {
    val start: Long = System.nanoTime()
    val result: R = block()
    return result to (System.nanoTime() - start)
}

inline fun <reified T> Any?.cast(): T? = this as? T

inline fun <reified T : Enum<T>> enumValues2(): List<T> = enumValues<T>().toList()

fun fanout(n: Int): List<Int> = (0 until n).map { it * it }

fun <T> List<T>.chunked2(size: Int): List<List<T>> {
    require(size > 0) { "size must be positive" }
    val result: MutableList<List<T>> = mutableListOf()
    var i: Int = 0
    while (i < this.size) {
        result.add(this.subList(i, min(i + size, this.size)))
        i += size
    }
    return result
}

fun <T> Iterable<T>.windowed2(): List<Pair<T, T>> {
    val out: MutableList<Pair<T, T>> = mutableListOf()
    var prev: T? = null
    var seen: Boolean = false
    for (t: T in this) {
        if (seen) {
            @Suppress("UNCHECKED_CAST")
            out.add((prev as T) to t)
        }
        prev = t
        seen = true
    }
    return out
}

suspend fun asyncDouble(x: Int): Int {
    delay(1)
    return x * 2
}

suspend fun asyncSum(items: List<Int>): Int = coroutineScope {
    val deferreds: List<kotlinx.coroutines.Deferred<Int>> = items.map { async { asyncDouble(it) } }
    deferreds.awaitAll().sum()
}

suspend fun parallelMap(items: List<Int>): List<Int> = coroutineScope {
    items.map { async(Dispatchers.Default) { it * it + 1 } }.awaitAll()
}

fun simpleFlow(n: Int): Flow<Int> = flow {
    for (i: Int in 0 until n) {
        emit(i)
    }
}

suspend fun consumeFlow(): Int {
    var acc: Int = 0
    simpleFlow(10).collect { v: Int -> acc += v }
    return acc
}

suspend fun chainFlow(): List<String> = flowOf(1, 2, 3, 4)
    .map { it * it }
    .map { "v=$it" }
    .toList()

fun safeDivide(a: Int, b: Int): Int? = if (b == 0) null else a / b

fun describeNumber(n: Int): String = when {
    n < 0 -> "negative:$n"
    n == 0 -> "zero"
    n in 1..9 -> "tiny:$n"
    n in 10..99 -> "small:$n"
    n in 100..999 -> "medium:$n"
    else -> "large:$n"
}

fun typeTag(any: Any?): String = when (any) {
    null -> "null"
    is Int -> "int:$any"
    is Long -> "long:$any"
    is Double -> "double:$any"
    is String -> if (any.isEmpty()) "empty-str" else "str:${any.length}"
    is IntArray -> "iarr:${any.size}"
    is List<*> -> "list:${any.size}"
    is Map<*, *> -> "map:${any.size}"
    is Pair<*, *> -> "pair"
    is Triple<*, *, *> -> "triple"
    else -> "other:${any::class.simpleName}"
}

fun safeCast(): String {
    val any: Any = "hello"
    val asStr: String? = any as? String
    val asInt: Int? = any as? Int
    return "str=$asStr int=$asInt"
}

fun smartCast(o: Any): Int = when (o) {
    is String -> o.length
    is List<*> -> o.size
    is IntArray -> o.size
    is Map<*, *> -> o.size
    else -> -1
}

fun destructureMap(m: Map<String, Int>): String {
    val sb: StringBuilder = StringBuilder()
    for ((k: String, v: Int) in m) {
        sb.append("$k=$v;")
    }
    return sb.toString()
}

fun useTriple(): String {
    val t: Triple<Int, String, Double> = Triple(1, "two", 3.0)
    val (a: Int, b: String, c: Double) = t
    return "$a/$b/$c"
}

fun nullableChain(s: String?): Int = s?.trim()?.takeIf { it.isNotEmpty() }?.length ?: -1

fun elvis(): String {
    val x: String? = null
    return x ?: "default"
}

fun letApplyAlso(): String {
    val sb: StringBuilder = StringBuilder().apply {
        append("a")
        append("b")
    }
    val s: String = sb.toString().let { it.uppercase() }
    return s.also {  }
}

fun useScope(): String {
    val data: Map<String, Int> = buildMap {
        put("one", 1)
        put("two", 2)
        put("three", 3)
    }
    val sum: Int = data.values.sum()
    return "size=${data.size} sum=$sum"
}

fun useRunWith(): Int {
    val result: Int = with(StringBuilder()) {
        append("123")
        append("456")
        length
    }
    return result
}

fun rangeProgression(): Int = (1..100 step 2).sum()

fun stringInterp(name: String, value: Int): String = "$name => ${value * 2 + 1}"

fun lambdas(): Int {
    val add: (Int, Int) -> Int = { a: Int, b: Int -> a + b }
    val mul: (Int, Int) -> Int = { a: Int, b: Int -> a * b }
    val composed: (Int, Int) -> Int = { a: Int, b: Int -> add(a, b) * mul(a, b) }
    return composed(3, 4)
}

fun higherOrder(xs: List<Int>, f: (Int) -> Int): List<Int> = xs.map(f)

fun closureCapture(): Int {
    var counter: Int = 0
    val inc: () -> Int = { counter += 1; counter }
    repeat(5) { inc() }
    return counter
}

fun useTryCatch(): String {
    return try {
        "abc".toInt()
        "parsed"
    } catch (e: NumberFormatException) {
        "caught:${e::class.simpleName}"
    } finally {

    }
}

class Resource(val name: String) : AutoCloseable {
    private var closed: Boolean = false
    fun read(): String {
        check(!closed) { "already closed" }
        return name
    }
    override fun close() { closed = true }
}

fun useResource(): String = Resource("r1").use { r: Resource -> r.read() }

class TreeNode<T>(val value: T, val children: MutableList<TreeNode<T>> = mutableListOf()) {
    fun add(child: TreeNode<T>) { children.add(child) }
    fun depth(): Int = if (children.isEmpty()) 1 else 1 + children.maxOf { it.depth() }
    fun size(): Int = 1 + children.sumOf { it.size() }
}

fun buildTree(): TreeNode<Int> {
    val root: TreeNode<Int> = TreeNode(1)
    val a: TreeNode<Int> = TreeNode(2)
    val b: TreeNode<Int> = TreeNode(3)
    val c: TreeNode<Int> = TreeNode(4)
    a.add(TreeNode(5))
    a.add(TreeNode(6))
    root.add(a)
    root.add(b)
    root.add(c)
    return root
}

abstract class Animal(val name: String) {
    abstract fun speak(): String
    open fun describe(): String = "${this::class.simpleName}:$name says ${speak()}"
}

class Dog(name: String, val breed: String) : Animal(name) {
    override fun speak(): String = "woof"
    override fun describe(): String = "${super.describe()} (breed=$breed)"
}

class Cat(name: String) : Animal(name) {
    override fun speak(): String = "meow"
}

interface Greeter {
    fun greet(): String
    fun greetLoud(): String = "${greet()}!!"
}

interface Named {
    val displayName: String
}

class Robot(override val displayName: String) : Greeter, Named {
    override fun greet(): String = "beep $displayName"
}

object SingletonRegistry {
    private val store: MutableMap<String, Any> = mutableMapOf()
    fun put(k: String, v: Any) { store[k] = v }
    fun get(k: String): Any? = store[k]
    fun size(): Int = store.size
}

class Counter {
    private var n: Int = 0
    val current: Int get() = n
    fun inc(): Int { n += 1; return n }

    companion object {
        const val MAX: Int = 1_000_000
        fun new(start: Int = 0): Counter = Counter().also { it.n = start }
    }
}

fun useCompanion(): Int = Counter.new(10).apply { inc(); inc() }.current

annotation class Marked(val tag: String, val priority: Int = 0)

@Marked(tag = "hot", priority = 9)
class MarkedThing(val id: Int)

class GenericBox<T : Comparable<T>>(val value: T) {
    fun compareWith(other: GenericBox<T>): Int = value.compareTo(other.value)
}

fun <T : Number> sumNumbers(xs: List<T>): Double = xs.sumOf { it.toDouble() }

fun <T : Any> notNullChain(value: T?, fallback: () -> T): T = value ?: fallback()

inline fun <reified T : Any> isInstance(any: Any?): Boolean = any is T

class LazyHolder {
    val cached: String by lazy {
        Thread.sleep(0)
        "computed-lazily"
    }
}

class Property {
    var stored: String = "default"
        set(value) {
            field = value.trim()
        }
        get() = field.uppercase()
}

class FibSeq : Iterable<Long> {
    override fun iterator(): Iterator<Long> = object : Iterator<Long> {
        var a: Long = 0L
        var b: Long = 1L
        override fun hasNext(): Boolean = true
        override fun next(): Long {
            val r: Long = a
            val t: Long = a + b
            a = b
            b = t
            return r
        }
    }
}

fun fibFirst(n: Int): List<Long> = FibSeq().take(n).toList()

fun moneyMath(): Double {
    val a: Money = Money(1099)
    val b: Money = Money(250)
    val c: Money = (a + b) * 3
    return c.asFloat()
}

fun userIdProgression(): Long {
    var u: UserId = UserId(100)
    repeat(5) { u = u.next() }
    return u.raw
}

class StateMachine {
    sealed class State {
        data object Idle : State()
        data class Running(val ticks: Int) : State()
        data class Failed(val reason: String) : State()
    }

    private var state: State = State.Idle

    fun start(): State {
        state = State.Running(0)
        return state
    }

    fun tick(): State {
        val cur: State = state
        state = when (cur) {
            State.Idle -> State.Failed("not started")
            is State.Running -> State.Running(cur.ticks + 1)
            is State.Failed -> cur
        }
        return state
    }

    fun fail(reason: String): State {
        state = State.Failed(reason)
        return state
    }

    val current: State get() = state
}

class CachedSquare {
    private val cache: MutableMap<Int, Int> = mutableMapOf()
    fun get(n: Int): Int = cache.getOrPut(n) { n * n }
}

fun fastSumOfSquares(n: Int): Int {
    val c: CachedSquare = CachedSquare()
    return (1..n).sumOf { c.get(it) }
}

fun useStrings(): String {
    val parts: List<String> = listOf("alpha", "beta", "gamma")
    return parts.joinToString(separator = "/", prefix = "[", postfix = "]") { it.uppercase() }
}

fun mapTransform(): Map<String, Int> = mapOf("a" to 1, "b" to 2, "c" to 3)
    .mapValues { (_, v: Int) -> v * 10 }
    .filterValues { it > 10 }

fun groupExample(): Map<Boolean, List<Int>> = (1..10).groupBy { it % 2 == 0 }

fun foldExample(): Int = (1..10).fold(0) { acc: Int, x: Int -> acc + x }

fun runningExample(): List<Int> = (1..5).runningFold(0) { acc: Int, x: Int -> acc + x }

fun zipExample(): List<Pair<Int, String>> = listOf(1, 2, 3).zip(listOf("a", "b", "c"))

fun partitionExample(): Pair<List<Int>, List<Int>> = (1..10).partition { it % 2 == 0 }

fun distinctExample(): List<Int> = listOf(1, 2, 2, 3, 3, 3, 4).distinct()

fun sortedByExample(): List<String> = listOf("aaa", "b", "cc").sortedBy { it.length }

fun fold2D(grid: Array<IntArray>): Int = grid.sumOf { row: IntArray -> row.sum() }

fun makeGrid(rows: Int, cols: Int): Array<IntArray> =
    Array(rows) { r: Int -> IntArray(cols) { c: Int -> r * cols + c } }

fun usePair(): String {
    val p: Pair<Int, String> = 7 to "hello"
    val (n: Int, s: String) = p
    return "$s($n)"
}

fun lambdaAsValue(): Int {
    val ops: Map<String, (Int, Int) -> Int> = mapOf(
        "+" to { a: Int, b: Int -> a + b },
        "-" to { a: Int, b: Int -> a - b },
        "*" to { a: Int, b: Int -> a * b }
    )
    val op: (Int, Int) -> Int = ops["+"] ?: error("missing")
    return op(2, 3)
}

fun varargsUse(vararg ns: Int): Int = ns.sum()
fun spreadCall(): Int = varargsUse(*intArrayOf(1, 2, 3, 4))

infix fun Int.power(exp: Int): Int {
    var acc: Int = 1
    repeat(exp) { acc *= this }
    return acc
}

fun infixCall(): Int = 2 power 10

operator fun Int.times(s: String): String = s.repeat(this)
fun operatorOverload(): String = 3 * "ab"

class Container<T> {
    private val items: MutableList<T> = mutableListOf()
    fun add(t: T) { items.add(t) }
    operator fun get(i: Int): T = items[i]
    operator fun set(i: Int, t: T) { items[i] = t }
    operator fun contains(t: T): Boolean = items.contains(t)
    operator fun iterator(): Iterator<T> = items.iterator()
    val size: Int get() = items.size
}

fun useContainer(): Int {
    val c: Container<Int> = Container()
    c.add(1)
    c.add(2)
    c.add(3)
    var s: Int = 0
    for (v: Int in c) s += v
    return s + if (2 in c) 100 else 0
}

class Person(val name: String, val age: Int) : Comparable<Person> {
    override fun compareTo(other: Person): Int = age.compareTo(other.age)
}

fun sortPeople(): String = listOf(Person("a", 30), Person("b", 20)).sorted().joinToString { it.name }

@Suppress("RemoveRedundantBackticks")
fun `function with spaces in name`(): String = "weird"

fun useLabels(): Int {
    var acc: Int = 0
    outer@ for (i: Int in 1..10) {
        for (j: Int in 1..10) {
            if (i + j > 15) break@outer
            acc++
        }
    }
    return acc
}

fun useReturn(): Int {
    listOf(1, 2, 3, 4).forEach { x: Int ->
        if (x == 2) return@forEach
    }
    return 42
}

fun arithmetic(a: Double, b: Double): Map<String, Double> = mapOf(
    "+" to a + b,
    "-" to a - b,
    "*" to a * b,
    "/" to if (b != 0.0) a / b else Double.NaN,
    "min" to min(a, b),
    "max" to max(a, b),
    "abs" to abs(a - b),
    "sqrt" to sqrt(abs(a)),
    "ln" to ln(abs(a) + 1.0),
    "pow" to a.pow(2.0)
)

fun usePolymorphism(): String {
    val animals: List<Animal> = listOf(Dog("rex", "lab"), Cat("whiskers"))
    return animals.joinToString { it.describe() }
}

fun useInterfaceDefault(): String = Robot("R-100").greetLoud()

fun useSingleton(): Int {
    SingletonRegistry.put("a", 1)
    SingletonRegistry.put("b", 2)
    return SingletonRegistry.size()
}

fun useGenericBox(): Int {
    val a: GenericBox<Int> = GenericBox(10)
    val b: GenericBox<Int> = GenericBox(20)
    return a.compareWith(b)
}

fun useGenericFn(): Double = sumNumbers(listOf(1, 2.5, 3L))

fun useNotNull(): String = notNullChain<String>(null) { "fallback" }

fun useInline(): Boolean = isInstance<String>("hello")

fun useLazy(): String = LazyHolder().cached

fun useProperty(): String {
    val p: Property = Property()
    p.stored = "  hello  "
    return p.stored
}

fun useFib(): List<Long> = fibFirst(10)

fun useStateMachine(): String {
    val sm: StateMachine = StateMachine()
    sm.start()
    sm.tick()
    sm.tick()
    val final: StateMachine.State = sm.tick()
    return when (final) {
        is StateMachine.State.Running -> "running:${final.ticks}"
        is StateMachine.State.Failed -> "failed:${final.reason}"
        StateMachine.State.Idle -> "idle"
    }
}

fun coroutineMain(): String = runBlocking {
    val sum: Int = asyncSum(listOf(1, 2, 3, 4))
    val sq: List<Int> = parallelMap(listOf(1, 2, 3, 4))
    val flowSum: Int = consumeFlow()
    val chained: List<String> = chainFlow()
    "sum=$sum sq=${sq.sum()} flow=$flowSum chain=${chained.size}"
}

fun launchExample(): Int = runBlocking {
    var counter: Int = 0
    val jobs: List<kotlinx.coroutines.Job> = (0 until 5).map {
        launch {
            counter += 1
        }
    }
    jobs.forEach { it.join() }
    counter
}

fun withContextExample(): Int = runBlocking {
    withContext(Dispatchers.Default) {
        (1..10).sum()
    }
}

fun flowFoldExample(): Int = runBlocking {
    simpleFlow(5).fold(0) { acc: Int, v: Int -> acc + v }
}

fun apiResultDemo(): String {
    val ok: ApiResult<Int> = ApiResult.Ok(42)
    val err: ApiResult<Int> = ApiResult.Err(500, "oops")
    val pending: ApiResult<Int> = ApiResult.Pending
    val mapped: ApiResult<String> = ok.mapOk { "v=$it" }
    return "${ok.unwrapOr(0)}/${err.unwrapOr(-1)}/${pending.unwrapOr(-2)}/${mapped.unwrapOr("?")}"
}

fun main() {
    println(GREETING_KT)
    println("magic=$MAGIC_KT golden=$GOLDEN_KT")

    val p1: Point = Point(1.0, 2.0)
    val p2: Point = Point(3.0, 4.0)
    println("point=${p1 + p2} dot=${p1 dot p2} mag=${p1.magnitude}")

    val u: User = User(1L, "alice", setOf("admin", "beta"))
    val u2: User = u.renameTo("bob")
    println("user=$u u2=$u2")

    val shapes: List<Shape> = listOf(
        Shape.Circle(1.0),
        Shape.Rectangle(2.0, 3.0),
        Shape.Triangle(4.0, 5.0),
        Shape.Empty
    )
    println("shapes=${shapes.map { describeShape(it) }}")
    println("total=${totalArea(shapes)}")

    println("dir=${Direction.NORTH.turn().opposite()}")

    val cm: CountingMap<String> = CountingMap.of("a" to 1, "b" to 2)
    cm.bump("a")
    cm.bump("c")
    println("cm=${cm.snapshot()}")

    println("shout=${"hello".shoutLike()}")
    println("words=${"hello world foo bar".wordCount()}")
    println("prime=${17.isPrime()} ${24.isPrime()}")

    val (res: Int, ns: Long) = withTiming<Int, Int>("sum") { (1..100).sum() }
    println("timing=$res took=$ns")

    println("safe-div=${safeDivide(10, 0)}")
    println("desc=${describeNumber(42)}")
    println("tag=${typeTag(42)} ${typeTag("hi")} ${typeTag(null)}")
    println(safeCast())
    println("smart=${smartCast(listOf(1, 2, 3))}")

    println(destructureMap(mapOf("a" to 1, "b" to 2)))
    println(useTriple())
    println("nc=${nullableChain("  hello  ")} ${nullableChain(null)}")
    println("elvis=${elvis()}")
    println("apply=${letApplyAlso()}")
    println("scope=${useScope()}")
    println("with=${useRunWith()}")
    println("range=${rangeProgression()}")
    println("interp=${stringInterp("x", 7)}")

    println("lambdas=${lambdas()}")
    println("ho=${higherOrder(listOf(1, 2, 3)) { it * 10 }}")
    println("closure=${closureCapture()}")
    println("try=${useTryCatch()}")
    println("res=${useResource()}")

    val t: TreeNode<Int> = buildTree()
    println("tree size=${t.size()} depth=${t.depth()}")

    println(usePolymorphism())
    println(useInterfaceDefault())
    println("singleton=${useSingleton()}")
    println("companion=${useCompanion()}")
    println("box-cmp=${useGenericBox()}")
    println("sum-nums=${useGenericFn()}")
    println("nn=${useNotNull()}")
    println("inline=${useInline()}")
    println("lazy=${useLazy()}")
    println("prop=${useProperty()}")

    println("fib=${useFib()}")
    println("money=${moneyMath()}")
    println("uid=${userIdProgression()}")
    println("sm=${useStateMachine()}")

    println("ss=${fastSumOfSquares(10)}")
    println("ustr=${useStrings()}")
    println("mt=${mapTransform()}")
    println("gx=${groupExample().size}")
    println("fx=${foldExample()}")
    println("rx=${runningExample()}")
    println("zx=${zipExample()}")
    println("px=${partitionExample()}")
    println("dx=${distinctExample()}")
    println("sx=${sortedByExample()}")
    println("g2d=${fold2D(makeGrid(3, 4))}")
    println("pair=${usePair()}")
    println("lav=${lambdaAsValue()}")
    println("spr=${spreadCall()}")
    println("inf=${infixCall()}")
    println("op=${operatorOverload()}")
    println("cont=${useContainer()}")
    println("sort=${sortPeople()}")
    println("ws=${`function with spaces in name`()}")
    println("lab=${useLabels()}")
    println("ret=${useReturn()}")
    println("arith=${arithmetic(9.0, 3.0).size}")
    println("api=${apiResultDemo()}")
    println("cor=${coroutineMain()}")
    println("lex=${launchExample()}")
    println("wcx=${withContextExample()}")
    println("ffx=${flowFoldExample()}")
    println("KT-DONE")
}
