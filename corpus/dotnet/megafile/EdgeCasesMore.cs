using System;
using System.Buffers;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EdgeCases.More;

public interface IShape
{
    double Area { get; }
    double Perimeter { get; }
}

public sealed record Circle(double Radius) : IShape
{
    public double Area => Math.PI * Radius * Radius;
    public double Perimeter => 2.0d * Math.PI * Radius;
}

public sealed record Rectangle(double Width, double Height) : IShape
{
    public double Area => Width * Height;
    public double Perimeter => 2.0d * (Width + Height);
}

public sealed record Triangle(double A, double B, double C) : IShape
{
    public double Area
    {
        get
        {
            double s = (A + B + C) / 2.0d;
            double radicand = s * (s - A) * (s - B) * (s - C);
            return radicand > 0.0d ? Math.Sqrt(radicand) : 0.0d;
        }
    }

    public double Perimeter => A + B + C;
}

public static class ShapeKit
{
    public static double TotalArea(IEnumerable<IShape> shapes) =>
        shapes.Sum(static s => s.Area);

    public static IShape Largest(IEnumerable<IShape> shapes) =>
        shapes.OrderByDescending(static s => s.Area).First();

    public static string Describe(IShape shape) => shape switch
    {
        Circle { Radius: > 0.0d } c => $"circle:r={c.Radius:F2}:a={c.Area:F2}",
        Rectangle { Width: var w, Height: var h } when w == h => $"square:s={w:F2}",
        Rectangle r => $"rect:{r.Width:F2}x{r.Height:F2}",
        Triangle { A: var a, B: var b, C: var c } when a == b && b == c => $"equilateral:s={a:F2}",
        Triangle t => $"triangle:{t.A:F2}/{t.B:F2}/{t.C:F2}",
        _ => "unknown",
    };
}

public sealed class CircularBuffer<T> : IEnumerable<T>
{
    private readonly T[] storage;
    private int head;
    private int tail;
    private int count;

    public CircularBuffer(int capacity)
    {
        if (capacity <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity));
        }
        storage = new T[capacity];
    }

    public int Capacity => storage.Length;
    public int Count => count;
    public bool IsFull => count == Capacity;

    public void Push(T item)
    {
        storage[head] = item;
        head = (head + 1) % Capacity;
        if (IsFull)
        {
            tail = (tail + 1) % Capacity;
        }
        else
        {
            count++;
        }
    }

    public bool TryPop(out T value)
    {
        if (count == 0)
        {
            value = default!;
            return false;
        }
        head = (head - 1 + Capacity) % Capacity;
        value = storage[head];
        storage[head] = default!;
        count--;
        return true;
    }

    public IEnumerator<T> GetEnumerator()
    {
        int idx = tail;
        for (int i = 0; i < count; i++)
        {
            yield return storage[idx];
            idx = (idx + 1) % Capacity;
        }
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

public sealed class Trie
{
    private sealed class Node
    {
        public Dictionary<char, Node> Children { get; } = new();
        public bool IsTerminal { get; set; }
        public int Frequency { get; set; }
    }

    private readonly Node root = new();

    public void Insert(string word)
    {
        Node node = root;
        foreach (char c in word)
        {
            if (!node.Children.TryGetValue(c, out Node? next))
            {
                next = new Node();
                node.Children[c] = next;
            }
            node = next;
        }
        node.IsTerminal = true;
        node.Frequency++;
    }

    public bool Contains(string word)
    {
        Node? node = Walk(word);
        return node is { IsTerminal: true };
    }

    public bool StartsWith(string prefix)
    {
        return Walk(prefix) is not null;
    }

    public IEnumerable<string> WordsWithPrefix(string prefix)
    {
        Node? node = Walk(prefix);
        if (node is null)
        {
            yield break;
        }
        Stack<(Node Node, string Path)> stack = new();
        stack.Push((node, prefix));
        while (stack.Count > 0)
        {
            (Node n, string p) = stack.Pop();
            if (n.IsTerminal)
            {
                yield return p;
            }
            foreach (KeyValuePair<char, Node> kv in n.Children)
            {
                stack.Push((kv.Value, p + kv.Key));
            }
        }
    }

    private Node? Walk(string text)
    {
        Node node = root;
        foreach (char c in text)
        {
            if (!node.Children.TryGetValue(c, out Node? next))
            {
                return null;
            }
            node = next;
        }
        return node;
    }
}

public sealed class GraphAdjacency<T> where T : notnull
{
    private readonly Dictionary<T, HashSet<T>> outgoing = new();

    public void AddEdge(T from, T to)
    {
        GetOrCreate(from).Add(to);
        GetOrCreate(to);
    }

    public IReadOnlyCollection<T> Neighbors(T node) =>
        outgoing.TryGetValue(node, out HashSet<T>? set)
            ? set
            : (IReadOnlyCollection<T>)Array.Empty<T>();

    public IReadOnlyCollection<T> Nodes => outgoing.Keys;

    public IEnumerable<T> Bfs(T start)
    {
        if (!outgoing.ContainsKey(start))
        {
            yield break;
        }
        HashSet<T> visited = new() { start };
        Queue<T> queue = new();
        queue.Enqueue(start);
        while (queue.Count > 0)
        {
            T node = queue.Dequeue();
            yield return node;
            foreach (T neighbor in Neighbors(node))
            {
                if (visited.Add(neighbor))
                {
                    queue.Enqueue(neighbor);
                }
            }
        }
    }

    public IEnumerable<T> Dfs(T start)
    {
        if (!outgoing.ContainsKey(start))
        {
            yield break;
        }
        HashSet<T> visited = new();
        Stack<T> stack = new();
        stack.Push(start);
        while (stack.Count > 0)
        {
            T node = stack.Pop();
            if (!visited.Add(node))
            {
                continue;
            }
            yield return node;
            foreach (T neighbor in Neighbors(node))
            {
                stack.Push(neighbor);
            }
        }
    }

    private HashSet<T> GetOrCreate(T node)
    {
        if (!outgoing.TryGetValue(node, out HashSet<T>? set))
        {
            set = new HashSet<T>();
            outgoing[node] = set;
        }
        return set;
    }
}

public static class StringExtras
{
    public static string Reverse(this string source)
    {
        char[] chars = source.ToCharArray();
        Array.Reverse(chars);
        return new string(chars);
    }

    public static bool IsPalindrome(this string source)
    {
        for (int i = 0, j = source.Length - 1; i < j; i++, j--)
        {
            if (source[i] != source[j])
            {
                return false;
            }
        }
        return true;
    }

    public static IEnumerable<string> NGrams(this string source, int size)
    {
        if (size <= 0 || size > source.Length)
        {
            yield break;
        }
        for (int i = 0; i <= source.Length - size; i++)
        {
            yield return source.Substring(i, size);
        }
    }

    public static int LevenshteinDistance(this string a, string b)
    {
        if (a.Length == 0) { return b.Length; }
        if (b.Length == 0) { return a.Length; }
        int[,] dp = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) { dp[i, 0] = i; }
        for (int j = 0; j <= b.Length; j++) { dp[0, j] = j; }
        for (int i = 1; i <= a.Length; i++)
        {
            for (int j = 1; j <= b.Length; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                dp[i, j] = Math.Min(
                    Math.Min(dp[i - 1, j] + 1, dp[i, j - 1] + 1),
                    dp[i - 1, j - 1] + cost);
            }
        }
        return dp[a.Length, b.Length];
    }
}

public static class NumericExtras
{
    public static bool IsPrime(this int value)
    {
        if (value < 2) { return false; }
        if (value < 4) { return true; }
        if ((value & 1) == 0) { return false; }
        int bound = (int)Math.Sqrt(value);
        for (int i = 3; i <= bound; i += 2)
        {
            if (value % i == 0) { return false; }
        }
        return true;
    }

    public static IEnumerable<int> PrimesUpTo(int max)
    {
        if (max < 2) { yield break; }
        bool[] sieve = new bool[max + 1];
        for (int i = 2; i <= max; i++)
        {
            if (sieve[i]) { continue; }
            yield return i;
            for (long j = (long)i * i; j <= max; j += i)
            {
                sieve[j] = true;
            }
        }
    }

    public static int GreatestCommonDivisor(int a, int b)
    {
        a = Math.Abs(a);
        b = Math.Abs(b);
        while (b != 0)
        {
            (a, b) = (b, a % b);
        }
        return a;
    }

    public static int LeastCommonMultiple(int a, int b)
    {
        if (a == 0 || b == 0) { return 0; }
        return Math.Abs(a / GreatestCommonDivisor(a, b) * b);
    }

    public static long Factorial(int n)
    {
        if (n < 0) { throw new ArgumentOutOfRangeException(nameof(n)); }
        long acc = 1;
        for (int i = 2; i <= n; i++)
        {
            acc *= i;
        }
        return acc;
    }

    public static long Fibonacci(int n)
    {
        if (n < 0) { throw new ArgumentOutOfRangeException(nameof(n)); }
        long a = 0;
        long b = 1;
        for (int i = 0; i < n; i++)
        {
            (a, b) = (b, a + b);
        }
        return a;
    }
}

public sealed class ObjectPool<T> where T : class
{
    private readonly ConcurrentBag<T> bag = new();
    private readonly Func<T> factory;
    private readonly Action<T>? reset;
    private int created;

    public ObjectPool(Func<T> factory, Action<T>? reset = null)
    {
        this.factory = factory ?? throw new ArgumentNullException(nameof(factory));
        this.reset = reset;
    }

    public int Created => created;

    public T Rent()
    {
        if (bag.TryTake(out T? item))
        {
            return item;
        }
        Interlocked.Increment(ref created);
        return factory();
    }

    public void Return(T item)
    {
        reset?.Invoke(item);
        bag.Add(item);
    }
}

public readonly struct Result<TOk, TErr>
{
    private readonly TOk ok;
    private readonly TErr err;

    private Result(TOk ok, TErr err, bool isOk)
    {
        this.ok = ok;
        this.err = err;
        IsOk = isOk;
    }

    public bool IsOk { get; }
    public bool IsErr => !IsOk;

    public TOk Unwrap() => IsOk ? ok : throw new InvalidOperationException("unwrap on err");
    public TErr UnwrapErr() => IsErr ? err : throw new InvalidOperationException("unwrap_err on ok");

    public Result<TNext, TErr> Map<TNext>(Func<TOk, TNext> mapper) =>
        IsOk ? Result<TNext, TErr>.Ok(mapper(ok)) : Result<TNext, TErr>.Err(err);

    public Result<TOk, TNextErr> MapErr<TNextErr>(Func<TErr, TNextErr> mapper) =>
        IsOk ? Result<TOk, TNextErr>.Ok(ok) : Result<TOk, TNextErr>.Err(mapper(err));

    public Result<TNext, TErr> AndThen<TNext>(Func<TOk, Result<TNext, TErr>> binder) =>
        IsOk ? binder(ok) : Result<TNext, TErr>.Err(err);

    public TOut Match<TOut>(Func<TOk, TOut> onOk, Func<TErr, TOut> onErr) =>
        IsOk ? onOk(ok) : onErr(err);

    public static Result<TOk, TErr> Ok(TOk value) => new(value, default!, true);
    public static Result<TOk, TErr> Err(TErr error) => new(default!, error, false);
}

public readonly struct Maybe<T>
{
    private readonly T value;

    private Maybe(T value, bool hasValue)
    {
        this.value = value;
        HasValue = hasValue;
    }

    public bool HasValue { get; }

    public T ValueOrThrow() => HasValue ? value : throw new InvalidOperationException("no value");
    public T ValueOrDefault(T fallback) => HasValue ? value : fallback;

    public Maybe<TNext> Map<TNext>(Func<T, TNext> mapper) =>
        HasValue ? Maybe<TNext>.Some(mapper(value)) : Maybe<TNext>.None;

    public Maybe<TNext> Bind<TNext>(Func<T, Maybe<TNext>> binder) =>
        HasValue ? binder(value) : Maybe<TNext>.None;

    public static Maybe<T> Some(T value) => new(value, true);
    public static Maybe<T> None { get; } = new(default!, false);
}

public sealed class EventBus
{
    private readonly Dictionary<Type, List<Delegate>> handlers = new();
    private readonly object gate = new();

    public IDisposable Subscribe<T>(Action<T> handler)
    {
        lock (gate)
        {
            if (!handlers.TryGetValue(typeof(T), out List<Delegate>? list))
            {
                list = new List<Delegate>();
                handlers[typeof(T)] = list;
            }
            list.Add(handler);
        }
        return new DisposableSubscription(() => Unsubscribe(handler));
    }

    public int Publish<T>(T evt)
    {
        Delegate[] snapshot;
        lock (gate)
        {
            if (!handlers.TryGetValue(typeof(T), out List<Delegate>? list))
            {
                return 0;
            }
            snapshot = list.ToArray();
        }
        int delivered = 0;
        foreach (Delegate d in snapshot)
        {
            ((Action<T>)d)(evt);
            delivered++;
        }
        return delivered;
    }

    private void Unsubscribe<T>(Action<T> handler)
    {
        lock (gate)
        {
            if (handlers.TryGetValue(typeof(T), out List<Delegate>? list))
            {
                list.Remove(handler);
            }
        }
    }

    private sealed class DisposableSubscription : IDisposable
    {
        private readonly Action onDispose;
        private bool disposed;

        public DisposableSubscription(Action onDispose) { this.onDispose = onDispose; }

        public void Dispose()
        {
            if (disposed) { return; }
            disposed = true;
            onDispose();
        }
    }
}

public sealed class StateMachine<TState, TTrigger>
    where TState : struct, Enum
    where TTrigger : struct, Enum
{
    private readonly Dictionary<(TState, TTrigger), TState> transitions = new();
    private readonly List<Action<TState, TTrigger, TState>> observers = new();

    public TState State { get; private set; }

    public StateMachine(TState initial)
    {
        State = initial;
    }

    public StateMachine<TState, TTrigger> Permit(TState from, TTrigger trigger, TState to)
    {
        transitions[(from, trigger)] = to;
        return this;
    }

    public StateMachine<TState, TTrigger> OnTransition(Action<TState, TTrigger, TState> observer)
    {
        observers.Add(observer);
        return this;
    }

    public bool Fire(TTrigger trigger)
    {
        if (!transitions.TryGetValue((State, trigger), out TState next))
        {
            return false;
        }
        TState prev = State;
        State = next;
        foreach (Action<TState, TTrigger, TState> observer in observers)
        {
            observer(prev, trigger, next);
        }
        return true;
    }
}

public static class ReflectionPlayground
{
    public static IReadOnlyDictionary<string, object?> Snapshot<T>(T instance) where T : notnull
    {
        Dictionary<string, object?> map = new();
        Type t = typeof(T);
        foreach (PropertyInfo prop in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (prop.GetIndexParameters().Length > 0) { continue; }
            map[prop.Name] = prop.GetValue(instance);
        }
        return map;
    }

    public static T Construct<T>(params object?[] args) where T : class
    {
        Type t = typeof(T);
        object? obj = Activator.CreateInstance(t, args);
        return (T?)obj ?? throw new InvalidOperationException("ctor returned null");
    }

    public static IEnumerable<MethodInfo> FindByAttribute<TAttr>(Type type)
        where TAttr : Attribute
    {
        foreach (MethodInfo m in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
        {
            if (m.GetCustomAttribute<TAttr>() is not null)
            {
                yield return m;
            }
        }
    }
}

public sealed class RateLimiter
{
    private readonly Queue<DateTime> events = new();
    private readonly object gate = new();
    private readonly int max;
    private readonly TimeSpan window;

    public RateLimiter(int max, TimeSpan window)
    {
        if (max <= 0) { throw new ArgumentOutOfRangeException(nameof(max)); }
        this.max = max;
        this.window = window;
    }

    public bool TryAcquire()
    {
        DateTime now = DateTime.UtcNow;
        lock (gate)
        {
            while (events.Count > 0 && (now - events.Peek()) > window)
            {
                events.Dequeue();
            }
            if (events.Count >= max)
            {
                return false;
            }
            events.Enqueue(now);
            return true;
        }
    }
}

public static class BufferPlayground
{
    public static byte[] CopyChunked(ReadOnlySpan<byte> source, int chunkSize)
    {
        byte[] sink = new byte[source.Length];
        int offset = 0;
        while (offset < source.Length)
        {
            int remaining = source.Length - offset;
            int take = remaining < chunkSize ? remaining : chunkSize;
            source.Slice(offset, take).CopyTo(sink.AsSpan(offset, take));
            offset += take;
        }
        return sink;
    }

    public static int RentAndUse(int size)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(size);
        try
        {
            for (int i = 0; i < size; i++)
            {
                buffer[i] = (byte)(i & 0xFF);
            }
            int sum = 0;
            for (int i = 0; i < size; i++)
            {
                sum += buffer[i];
            }
            return sum;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static int Crc32Simple(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
            {
                uint mask = (uint)-(int)(crc & 1u);
                crc = (crc >> 1) ^ (0xEDB88320u & mask);
            }
        }
        return (int)~crc;
    }
}

public static class TaskPlayground
{
    public static async Task<int> WithTimeoutAsync(Func<CancellationToken, Task<int>> work, TimeSpan timeout)
    {
        using CancellationTokenSource cts = new(timeout);
        try
        {
            return await work(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return -1;
        }
    }

    public static async Task<T> WithRetryAsync<T>(Func<Task<T>> work, int maxAttempts, TimeSpan delay)
    {
        Exception? last = null;
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            try
            {
                return await work().ConfigureAwait(false);
            }
            catch (Exception ex) when (attempt < maxAttempts - 1)
            {
                last = ex;
                await Task.Delay(delay).ConfigureAwait(false);
            }
        }
        throw last ?? new InvalidOperationException("no attempts");
    }

    public static async Task<List<T>> BatchAsync<T>(IEnumerable<Func<Task<T>>> work, int concurrency)
    {
        SemaphoreSlim sem = new(concurrency);
        List<Task<T>> running = new();
        foreach (Func<Task<T>> w in work)
        {
            await sem.WaitAsync().ConfigureAwait(false);
            running.Add(Task.Run(async () =>
            {
                try
                {
                    return await w().ConfigureAwait(false);
                }
                finally
                {
                    sem.Release();
                }
            }));
        }
        T[] results = await Task.WhenAll(running).ConfigureAwait(false);
        return results.ToList();
    }
}

public sealed class Mediator
{
    private readonly Dictionary<Type, Func<object, Task<object?>>> handlers = new();

    public void Register<TRequest, TResponse>(Func<TRequest, Task<TResponse>> handler) where TRequest : notnull
    {
        handlers[typeof(TRequest)] = async raw => await handler((TRequest)raw).ConfigureAwait(false);
    }

    public async Task<TResponse> SendAsync<TRequest, TResponse>(TRequest request) where TRequest : notnull
    {
        if (!handlers.TryGetValue(typeof(TRequest), out Func<object, Task<object?>>? handler))
        {
            throw new InvalidOperationException($"no handler for {typeof(TRequest)}");
        }
        object? response = await handler(request).ConfigureAwait(false);
        return (TResponse)response!;
    }
}

public sealed class CommandDispatcher
{
    public delegate Task<int> CommandHandler(IReadOnlyList<string> args, CancellationToken token);

    private readonly Dictionary<string, CommandHandler> commands = new(StringComparer.OrdinalIgnoreCase);

    public CommandDispatcher Register(string name, CommandHandler handler)
    {
        commands[name] = handler;
        return this;
    }

    public Task<int> InvokeAsync(string name, IReadOnlyList<string> args, CancellationToken token = default)
    {
        if (!commands.TryGetValue(name, out CommandHandler? handler))
        {
            return Task.FromResult(127);
        }
        return handler(args, token);
    }

    public IReadOnlyCollection<string> Names => commands.Keys;
}

public static class ListPatternKit
{
    public static string Describe(int[] arr) => arr switch
    {
        [] => "empty",
        [var single] => $"one:{single}",
        [var first, var second] => $"two:{first},{second}",
        [1, 2, 3] => "exact-123",
        [1, .., 99] => "starts1-ends99",
        [_, _, _] => "three",
        _ => $"many:{arr.Length}",
    };

    public static int Score(int[] arr) => arr switch
    {
        [] => 0,
        [var only] => only,
        [var a, var b] => a + b,
        [var a, var b, var c] => a + b + c,
        _ => arr.Sum(),
    };
}

public static class TypeKit
{
    public static T DeepClone<T>(T value) where T : ICloneable
    {
        return (T)value.Clone();
    }

    public static bool TryCast<T>(object? source, out T cast)
    {
        if (source is T t)
        {
            cast = t;
            return true;
        }
        cast = default!;
        return false;
    }

    public static IEnumerable<Type> ImplementingTypes<TInterface>(Assembly assembly)
    {
        foreach (Type t in assembly.GetTypes())
        {
            if (!t.IsAbstract && typeof(TInterface).IsAssignableFrom(t))
            {
                yield return t;
            }
        }
    }
}

public sealed class TimeWindow
{
    public TimeWindow(DateTimeOffset start, DateTimeOffset end)
    {
        if (end < start)
        {
            throw new ArgumentException("end before start");
        }
        Start = start;
        End = end;
    }

    public DateTimeOffset Start { get; }
    public DateTimeOffset End { get; }
    public TimeSpan Duration => End - Start;

    public bool Contains(DateTimeOffset point) => point >= Start && point <= End;

    public bool Overlaps(TimeWindow other) => Start < other.End && other.Start < End;

    public TimeWindow? Intersection(TimeWindow other)
    {
        DateTimeOffset s = Start > other.Start ? Start : other.Start;
        DateTimeOffset e = End < other.End ? End : other.End;
        return s <= e ? new TimeWindow(s, e) : null;
    }
}

public sealed record Money2(decimal Amount, string Currency)
{
    public static Money2 Zero(string currency) => new(0m, currency);

    public Money2 Add(Money2 other)
    {
        if (other.Currency != Currency)
        {
            throw new InvalidOperationException("currency mismatch");
        }
        return this with { Amount = Amount + other.Amount };
    }

    public Money2 Multiply(decimal factor) => this with { Amount = Amount * factor };
}

public static class HtmlEscape
{
    public static string Escape(string input)
    {
        StringBuilder sb = new(input.Length);
        foreach (char c in input)
        {
            switch (c)
            {
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '&': sb.Append("&amp;"); break;
                case '"': sb.Append("&quot;"); break;
                case '\'': sb.Append("&#39;"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }
}

public static class Utf8Kit
{
    public static byte[] Encode(string input) => Encoding.UTF8.GetBytes(input);

    public static string Decode(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    public static byte[] EncodeAll(IEnumerable<string> inputs)
    {
        MemoryStream ms = new();
        foreach (string s in inputs)
        {
            byte[] b = Encode(s);
            ms.Write(BitConverter.GetBytes(b.Length), 0, 4);
            ms.Write(b, 0, b.Length);
        }
        return ms.ToArray();
    }
}

public sealed class Base64Streamer
{
    public string Encode(byte[] data) => Convert.ToBase64String(data);

    public byte[] Decode(string text) => Convert.FromBase64String(text);
}

public sealed class HmacLite
{
    private readonly byte[] key;

    public HmacLite(byte[] key)
    {
        this.key = key ?? throw new ArgumentNullException(nameof(key));
    }

    public int Compute(ReadOnlySpan<byte> message)
    {
        int hash = 17;
        foreach (byte b in key) { hash = (hash * 31) ^ b; }
        foreach (byte b in message) { hash = (hash * 31) ^ b; }
        return hash;
    }
}

public static class EnumKit
{
    public static IEnumerable<T> Values<T>() where T : struct, Enum
    {
        return Enum.GetValues(typeof(T)).Cast<T>();
    }

    public static T Parse<T>(string source) where T : struct, Enum
    {
        return (T)Enum.Parse(typeof(T), source, ignoreCase: true);
    }

    public static bool TryParse<T>(string source, out T value) where T : struct, Enum
    {
        return Enum.TryParse(source, ignoreCase: true, out value);
    }
}

public sealed class FixedSlots<T> where T : new()
{
    private readonly T[] slots;
    private readonly bool[] used;

    public FixedSlots(int count)
    {
        slots = new T[count];
        used = new bool[count];
        for (int i = 0; i < count; i++)
        {
            slots[i] = new T();
        }
    }

    public int Capacity => slots.Length;

    public int Acquire()
    {
        for (int i = 0; i < used.Length; i++)
        {
            if (!used[i])
            {
                used[i] = true;
                return i;
            }
        }
        return -1;
    }

    public void Release(int idx)
    {
        if (idx >= 0 && idx < used.Length)
        {
            used[idx] = false;
        }
    }

    public T this[int idx] => slots[idx];
}

public sealed class LruCache<TKey, TValue> where TKey : notnull
{
    private readonly int capacity;
    private readonly Dictionary<TKey, LinkedListNode<KeyValuePair<TKey, TValue>>> map;
    private readonly LinkedList<KeyValuePair<TKey, TValue>> order;

    public LruCache(int capacity)
    {
        if (capacity <= 0) { throw new ArgumentOutOfRangeException(nameof(capacity)); }
        this.capacity = capacity;
        map = new Dictionary<TKey, LinkedListNode<KeyValuePair<TKey, TValue>>>(capacity);
        order = new LinkedList<KeyValuePair<TKey, TValue>>();
    }

    public int Count => map.Count;

    public bool TryGet(TKey key, out TValue value)
    {
        if (map.TryGetValue(key, out LinkedListNode<KeyValuePair<TKey, TValue>>? node))
        {
            order.Remove(node);
            order.AddFirst(node);
            value = node.Value.Value;
            return true;
        }
        value = default!;
        return false;
    }

    public void Set(TKey key, TValue value)
    {
        if (map.TryGetValue(key, out LinkedListNode<KeyValuePair<TKey, TValue>>? existing))
        {
            order.Remove(existing);
        }
        if (map.Count >= capacity)
        {
            LinkedListNode<KeyValuePair<TKey, TValue>>? tail = order.Last;
            if (tail is not null)
            {
                order.RemoveLast();
                map.Remove(tail.Value.Key);
            }
        }
        LinkedListNode<KeyValuePair<TKey, TValue>> node = new(new KeyValuePair<TKey, TValue>(key, value));
        order.AddFirst(node);
        map[key] = node;
    }
}

public sealed class WeightedRandom<T>
{
    private readonly List<(T Item, double Weight)> entries = new();
    private readonly Random random;
    private double totalWeight;

    public WeightedRandom(Random random)
    {
        this.random = random ?? throw new ArgumentNullException(nameof(random));
    }

    public WeightedRandom<T> Add(T item, double weight)
    {
        if (weight < 0.0d) { throw new ArgumentOutOfRangeException(nameof(weight)); }
        entries.Add((item, weight));
        totalWeight += weight;
        return this;
    }

    public T Sample()
    {
        if (entries.Count == 0) { throw new InvalidOperationException("empty"); }
        double pick = random.NextDouble() * totalWeight;
        double cumulative = 0.0d;
        foreach ((T item, double weight) in entries)
        {
            cumulative += weight;
            if (pick <= cumulative) { return item; }
        }
        return entries[entries.Count - 1].Item;
    }
}

public static class BitTwiddling
{
    public static int PopCount(uint value)
    {
        int count = 0;
        while (value != 0)
        {
            value &= value - 1;
            count++;
        }
        return count;
    }

    public static uint NextPowerOfTwo(uint value)
    {
        if (value == 0) { return 1; }
        value--;
        value |= value >> 1;
        value |= value >> 2;
        value |= value >> 4;
        value |= value >> 8;
        value |= value >> 16;
        return value + 1;
    }

    public static int LeadingZeros(uint value)
    {
        if (value == 0) { return 32; }
        int count = 0;
        while ((value & 0x8000_0000u) == 0)
        {
            value <<= 1;
            count++;
        }
        return count;
    }

    public static int TrailingZeros(uint value)
    {
        if (value == 0) { return 32; }
        int count = 0;
        while ((value & 1u) == 0)
        {
            value >>= 1;
            count++;
        }
        return count;
    }
}
