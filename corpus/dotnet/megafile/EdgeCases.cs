using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

#if NET7_0_OR_GREATER
using System.Numerics;
#endif

namespace EdgeCases;

public delegate TResult Transform<in TIn, out TResult>(TIn input);

public delegate void RefAction<T>(ref T value);

public enum Severity : byte
{
    Trace = 0,
    Debug = 10,
    Info = 20,
    Warn = 30,
    Error = 40,
    Fatal = 50,
}

[Flags]
public enum Capabilities : uint
{
    None = 0,
    Read = 1u << 0,
    Write = 1u << 1,
    Execute = 1u << 2,
    Delete = 1u << 3,
    All = Read | Write | Execute | Delete,
}

public interface IIdentifiable
{
    long Id { get; }
}

public interface IAuditable : IIdentifiable
{
    DateTime CreatedAt { get; }
    DateTime? ModifiedAt { get; }
}

public interface IRepository<T> where T : class, IIdentifiable
{
    Task<T?> FindAsync(long id, CancellationToken token = default);
    Task<IReadOnlyList<T>> ListAsync(int skip, int take, CancellationToken token = default);
    ValueTask<long> CountAsync(CancellationToken token = default);
}

public sealed record User(long Id, string Username, string Email, DateTime CreatedAt) : IAuditable
{
    public DateTime? ModifiedAt { get; init; }
    public required Severity DefaultSeverity { get; init; }
    public IReadOnlyList<string> Roles { get; init; } = Array.Empty<string>();
}

public readonly record struct Coordinate(double Latitude, double Longitude)
{
    public static Coordinate Origin { get; } = new(0.0d, 0.0d);

    public double DistanceTo(Coordinate other)
    {
        double dx = Latitude - other.Latitude;
        double dy = Longitude - other.Longitude;
        return Math.Sqrt((dx * dx) + (dy * dy));
    }
}

public record Vehicle
{
    public required string Vin { get; init; }
    public required string Make { get; init; }
    public required string Model { get; init; }
    public int Year { get; init; }
}

public record Truck : Vehicle
{
    public int PayloadKg { get; init; }
}

public class Container<T> where T : notnull
{
    private readonly List<T> items = new();

    public int Count => items.Count;

    public T this[int index]
    {
        get => items[index];
        set => items[index] = value;
    }

    public void Add(T item) => items.Add(item);

    public bool Remove(T item) => items.Remove(item);

    public IReadOnlyList<T> Snapshot() => items.ToArray();
}

public class CountedList<T> : IEnumerable<T>
{
    private readonly List<T> backing = new();

    public int AddCount { get; private set; }

    public void Add(T item)
    {
        backing.Add(item);
        AddCount++;
    }

    public IEnumerator<T> GetEnumerator() => backing.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

public class PrimaryCtorService(IRepository<User> repository, Severity threshold)
{
    private readonly IRepository<User> _repository = repository;

    public Severity Threshold { get; } = threshold;

    public async Task<IReadOnlyList<User>> AboveThresholdAsync(CancellationToken token = default)
    {
        IReadOnlyList<User> all = await _repository.ListAsync(0, int.MaxValue, token).ConfigureAwait(false);
        List<User> filtered = new();
        foreach (User u in all)
        {
            if (u.DefaultSeverity >= Threshold)
            {
                filtered.Add(u);
            }
        }
        return filtered;
    }
}

public static class PatternKit
{
    public static string Classify(object? value) => value switch
    {
        null => "null",
        int n when n < 0 => $"negative-int:{n}",
        int n when n == 0 => "zero",
        int n => $"positive-int:{n}",
        string { Length: 0 } => "empty-string",
        string { Length: > 0 and < 10 } s => $"short-string:{s}",
        string s => $"long-string:{s.Length}",
        int[] { Length: 0 } => "empty-int-array",
        int[] { Length: 1 } => "single-int-array",
        int[] { Length: 2 } => "pair-int-array",
        int[] arr => $"int-array-rest:{arr.Length - 2}",
        Coordinate { Latitude: > 0.0d, Longitude: > 0.0d } c => $"ne-quadrant:{c}",
        Coordinate c => $"other-coord:{c}",
        User { Username.Length: > 0 } u => $"user:{u.Username}",
        _ => $"other:{value.GetType().Name}",
    };

    public static int Bucket(int score) => score switch
    {
        < 0 => -1,
        0 => 0,
        > 0 and <= 10 => 1,
        > 10 and <= 100 => 2,
        > 100 and < 1000 => 3,
        _ => 4,
    };

    public static bool IsCardinal(Coordinate c) => c is
    {
        Latitude: 0.0d or > 89.99d or < -89.99d,
        Longitude: 0.0d or 180.0d or -180.0d,
    };

    public static string DescribeList(IReadOnlyList<int> values) => values switch
    {
        [] => "empty",
        [var single] => $"one:{single}",
        [var first, var last] => $"pair:{first}/{last}",
        [var first, .., var last] => $"flanks:{first}/{last}",
    };
}

public static class CollectionPlayground
{
    public static int[] CreateRange(int start, int count)
    {
        int[] arr = new int[count];
        for (int i = 0; i < count; i++)
        {
            arr[i] = start + i;
        }
        return arr;
    }

    public static List<int> Doubled(IEnumerable<int> source)
    {
        return source.Select(static x => x * 2).ToList();
    }

    public static Dictionary<TKey, List<TValue>> GroupBy<TKey, TValue>(
        IEnumerable<TValue> source,
        Func<TValue, TKey> selector) where TKey : notnull
    {
        Dictionary<TKey, List<TValue>> map = new();
        foreach (TValue v in source)
        {
            TKey key = selector(v);
            if (!map.TryGetValue(key, out List<TValue>? list))
            {
                list = new List<TValue>();
                map[key] = list;
            }
            list.Add(v);
        }
        return map;
    }

    public static IReadOnlyList<int> CollectionExpression()
    {
        int[] head = [1, 2, 3];
        int[] tail = [9, 10, 11];
        int[] combined = [..head, 4, 5, 6, 7, 8, ..tail];
        return combined;
    }

    public static List<T> SpreadInto<T>(params T[] items)
    {
        List<T> list = [..items];
        return list;
    }
}

public static class LinqPlayground
{
    public static IEnumerable<int> EvenSquares(IEnumerable<int> source) =>
        from x in source
        where (x % 2) == 0
        let sq = x * x
        orderby sq descending
        select sq;

    public static IEnumerable<(int Outer, int Inner)> CrossJoin(IEnumerable<int> a, IEnumerable<int> b) =>
        from x in a
        from y in b
        where x != y
        select (x, y);

    public static Dictionary<string, double> Aggregate(IEnumerable<User> users) =>
        users
            .GroupBy(u => u.Username.Substring(0, 1).ToUpperInvariant())
            .ToDictionary(g => g.Key, g => g.Count() / 1.0d);

    public static int Reduce(IEnumerable<int> source) =>
        source.Aggregate(0, static (acc, x) => acc + x);
}

public static class AsyncPlayground
{
    public static async Task<int> SumAsync(IEnumerable<int> source, CancellationToken token = default)
    {
        int total = 0;
        foreach (int v in source)
        {
            token.ThrowIfCancellationRequested();
            await Task.Yield();
            total += v;
        }
        return total;
    }

    public static async ValueTask<int> ValueTaskSumAsync(IEnumerable<int> source)
    {
        if (source is ICollection<int> coll && coll.Count == 0)
        {
            return 0;
        }
        int total = 0;
        foreach (int v in source)
        {
            await Task.Yield();
            total += v;
        }
        return total;
    }

    public static async IAsyncEnumerable<int> RangeAsync(
        int start,
        int count,
        [EnumeratorCancellation] CancellationToken token = default)
    {
        for (int i = 0; i < count; i++)
        {
            token.ThrowIfCancellationRequested();
            await Task.Yield();
            yield return start + i;
        }
    }

    public static async Task<List<int>> ConsumeAsync(IAsyncEnumerable<int> stream, CancellationToken token = default)
    {
        List<int> sink = new();
        await foreach (int v in stream.WithCancellation(token).ConfigureAwait(false))
        {
            sink.Add(v);
        }
        return sink;
    }

    public static Task<int[]> WhenAllResultsAsync(IEnumerable<Task<int>> tasks)
    {
        return Task.WhenAll(tasks);
    }

    public static async Task<int> RaceAsync(IEnumerable<Task<int>> tasks)
    {
        Task<int> first = await Task.WhenAny(tasks).ConfigureAwait(false);
        return await first.ConfigureAwait(false);
    }
}

public sealed class Cache<TKey, TValue> : IDisposable where TKey : notnull
{
    private readonly ConcurrentDictionary<TKey, Lazy<TValue>> store = new();
    private readonly Func<TKey, TValue> factory;
    private bool disposed;

    public Cache(Func<TKey, TValue> factory)
    {
        this.factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    public TValue GetOrAdd(TKey key)
    {
        ThrowIfDisposed();
        return store.GetOrAdd(key, k => new Lazy<TValue>(() => factory(k))).Value;
    }

    public bool TryRemove(TKey key, [MaybeNullWhen(false)] out TValue value)
    {
        ThrowIfDisposed();
        if (store.TryRemove(key, out Lazy<TValue>? lazy))
        {
            value = lazy.Value;
            return true;
        }
        value = default;
        return false;
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        store.Clear();
    }

    private void ThrowIfDisposed()
    {
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(Cache<TKey, TValue>));
        }
    }
}

public ref struct SpanWalker<T>
{
    private readonly ReadOnlySpan<T> span;
    private int position;

    public SpanWalker(ReadOnlySpan<T> span)
    {
        this.span = span;
        this.position = 0;
    }

    public bool HasNext => position < span.Length;

    public T Next()
    {
        if (!HasNext)
        {
            throw new InvalidOperationException("exhausted");
        }
        T value = span[position];
        position++;
        return value;
    }

    public ReadOnlySpan<T> Remaining => span.Slice(position);
}

public static class SpanPlayground
{
    public static int SumSpan(ReadOnlySpan<int> values)
    {
        int total = 0;
        foreach (int v in values)
        {
            total += v;
        }
        return total;
    }

    public static int FirstIndexOf(ReadOnlySpan<byte> haystack, byte needle)
    {
        for (int i = 0; i < haystack.Length; i++)
        {
            if (haystack[i] == needle)
            {
                return i;
            }
        }
        return -1;
    }

    public static void ReverseInPlace(Span<int> span)
    {
        int left = 0;
        int right = span.Length - 1;
        while (left < right)
        {
            (span[left], span[right]) = (span[right], span[left]);
            left++;
            right--;
        }
    }

    public static unsafe int UnsafeStackalloc(int count)
    {
        int* buffer = stackalloc int[count];
        int total = 0;
        for (int i = 0; i < count; i++)
        {
            buffer[i] = i;
            total += buffer[i];
        }
        return total;
    }

    public static Memory<byte> AllocateBuffer(int size)
    {
        byte[] arr = new byte[size];
        return arr.AsMemory();
    }
}

public static class RefPlayground
{
    public static ref int FindRef(int[] array, int needle)
    {
        for (int i = 0; i < array.Length; i++)
        {
            if (array[i] == needle)
            {
                return ref array[i];
            }
        }
        throw new InvalidOperationException("not found");
    }

    public static void IncrementInPlace(ref int value)
    {
        value++;
    }

    public static int OutTryParse(string input, out int result)
    {
        if (int.TryParse(input, out result))
        {
            return 0;
        }
        result = 0;
        return -1;
    }

    public static int InMaxValue(in int value, int floor)
    {
        return value > floor ? value : floor;
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct PackedHeader
{
    public uint Magic;
    public ushort Version;
    public ushort Flags;
    public uint Length;
    public ulong Checksum;
}

[StructLayout(LayoutKind.Explicit)]
public struct UnionLike
{
    [FieldOffset(0)] public uint AsUint;
    [FieldOffset(0)] public int AsInt;
    [FieldOffset(0)] public float AsFloat;
    [FieldOffset(0)] public byte Byte0;
    [FieldOffset(1)] public byte Byte1;
    [FieldOffset(2)] public byte Byte2;
    [FieldOffset(3)] public byte Byte3;
}

public unsafe struct FixedBufferHolder
{
    public fixed byte Data[256];
    public int Used;
}

public static class StringPlayground
{
    public static readonly string Raw = """
        {
          "name": "edge-cases",
          "lines": 1500,
          "features": ["raw-strings", "utf8", "patterns"]
        }
        """;

    public static readonly string Interpolated = $"""
        timestamp={DateTime.UtcNow:o}
        version={typeof(StringPlayground).Assembly.GetName().Version}
        """;

    public static ReadOnlySpan<byte> Utf8Literal => "edge-cases-utf8"u8;

    public static byte[] MakeUtf8Snapshot()
    {
        ReadOnlySpan<byte> src = Utf8Literal;
        byte[] copy = new byte[src.Length];
        src.CopyTo(copy);
        return copy;
    }

    public static StringBuilder BuildLines(IEnumerable<string> lines)
    {
        StringBuilder sb = new();
        foreach (string line in lines)
        {
            sb.AppendLine(line);
        }
        return sb;
    }

    public static string Repeat(char ch, int times)
    {
        return new string(ch, times);
    }
}

public static class ExpressionPlayground
{
    public static Expression<Func<int, int>> SquareExpr()
    {
        ParameterExpression x = Expression.Parameter(typeof(int), "x");
        BinaryExpression body = Expression.Multiply(x, x);
        return Expression.Lambda<Func<int, int>>(body, x);
    }

    public static Func<int, int> CompiledSquare() => SquareExpr().Compile();

    public static Expression<Func<TIn, bool>> AlwaysTrue<TIn>()
    {
        ParameterExpression p = Expression.Parameter(typeof(TIn), "x");
        return Expression.Lambda<Func<TIn, bool>>(Expression.Constant(true), p);
    }

    public static Expression<Func<TIn, TOut>> Identity<TIn, TOut>() where TIn : TOut
    {
        ParameterExpression p = Expression.Parameter(typeof(TIn), "x");
        return Expression.Lambda<Func<TIn, TOut>>(Expression.Convert(p, typeof(TOut)), p);
    }
}

public sealed class DisposableScope : IDisposable
{
    private readonly Action onDispose;
    private bool disposed;

    public DisposableScope(Action onDispose)
    {
        this.onDispose = onDispose;
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        onDispose();
    }
}

public sealed class AsyncDisposableScope : IAsyncDisposable
{
    private readonly Func<ValueTask> onDispose;
    private bool disposed;

    public AsyncDisposableScope(Func<ValueTask> onDispose)
    {
        this.onDispose = onDispose;
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        await onDispose().ConfigureAwait(false);
    }
}

public static class DisposalPlayground
{
    public static int CountWith(IEnumerable<int> source)
    {
        using DisposableScope scope = new(static () => { });
        int count = 0;
        foreach (int _ in source)
        {
            count++;
        }
        return count;
    }

    public static async Task<int> CountWithAsync(IAsyncEnumerable<int> source)
    {
        await using AsyncDisposableScope scope = new(static () => default);
        int count = 0;
        await foreach (int _ in source.ConfigureAwait(false))
        {
            count++;
        }
        return count;
    }
}

public static partial class PinvokePlayground
{
#if NET7_0_OR_GREATER
    [LibraryImport("kernel32.dll", EntryPoint = "GetTickCount")]
    public static partial uint GetTickCount();

    [LibraryImport("kernel32.dll", EntryPoint = "GetCurrentProcessId")]
    public static partial uint GetCurrentProcessId();

    [LibraryImport("kernel32.dll", EntryPoint = "GetCurrentThreadId")]
    public static partial uint GetCurrentThreadId();
#else
    [DllImport("kernel32.dll", EntryPoint = "GetTickCount", CharSet = CharSet.Unicode)]
    public static extern uint GetTickCount();

    [DllImport("kernel32.dll", EntryPoint = "GetCurrentProcessId", CharSet = CharSet.Unicode)]
    public static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll", EntryPoint = "GetCurrentThreadId", CharSet = CharSet.Unicode)]
    public static extern uint GetCurrentThreadId();
#endif

    [DllImport("kernel32.dll", EntryPoint = "GetEnvironmentVariableW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int GetEnvironmentVariableW(string name, StringBuilder buffer, int size);

    public static string ReadEnvVar(string name)
    {
        StringBuilder sb = new(256);
        int len = GetEnvironmentVariableW(name, sb, sb.Capacity);
        return len > 0 ? sb.ToString(0, len) : string.Empty;
    }
}

public readonly struct Money : IComparable<Money>, IEquatable<Money>
{
    public Money(long pennies)
    {
        Pennies = pennies;
    }

    public long Pennies { get; }

    public static Money Zero { get; } = new(0);

    public static Money One { get; } = new(1);

    public static Money operator +(Money left, Money right) => new(left.Pennies + right.Pennies);

    public static Money operator *(Money left, Money right) => new(left.Pennies * right.Pennies);

    public int CompareTo(Money other) => Pennies.CompareTo(other.Pennies);

    public bool Equals(Money other) => Pennies == other.Pennies;

    public override bool Equals(object? obj) => obj is Money m && Equals(m);

    public override int GetHashCode() => Pennies.GetHashCode();

    public override string ToString() => $"${Pennies / 100.0d:F2}";

    public static bool operator ==(Money left, Money right) => left.Equals(right);

    public static bool operator !=(Money left, Money right) => !left.Equals(right);

    public static bool operator <(Money left, Money right) => left.CompareTo(right) < 0;

    public static bool operator >(Money left, Money right) => left.CompareTo(right) > 0;

    public static bool operator <=(Money left, Money right) => left.CompareTo(right) <= 0;

    public static bool operator >=(Money left, Money right) => left.CompareTo(right) >= 0;
}

#if NET7_0_OR_GREATER
public static class GenericMathPlayground
{
    public static T SumGeneric<T>(IEnumerable<T> source) where T : INumber<T>
    {
        T total = T.Zero;
        foreach (T v in source)
        {
            total = total + v;
        }
        return total;
    }

    public static T Product<T>(IEnumerable<T> source) where T : INumber<T>
    {
        T total = T.One;
        foreach (T v in source)
        {
            total = total * v;
        }
        return total;
    }

    public static int SumInts(IEnumerable<int> source) => SumGeneric(source);

    public static int ProductInts(IEnumerable<int> source) => Product(source);
}
#endif

public static class ConfigParser
{
    public static Dictionary<string, string> Parse(string source)
    {
        Dictionary<string, string> map = new();
        foreach (string raw in source.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }
            int idx = line.IndexOf('=');
            if (idx <= 0)
            {
                continue;
            }
            string key = line.Substring(0, idx).Trim();
            string value = line.Substring(idx + 1).Trim();
            map[key] = value;
        }
        return map;
    }
}

public static class JsonLite
{
    public static string Escape(string input)
    {
        StringBuilder sb = new(input.Length + 2);
        sb.Append('"');
        foreach (char c in input)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20)
                    {
                        sb.Append("\\u");
                        sb.Append(((int)c).ToString("x4"));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    public static string Object(IEnumerable<KeyValuePair<string, string>> entries)
    {
        StringBuilder sb = new("{");
        bool first = true;
        foreach (KeyValuePair<string, string> pair in entries)
        {
            if (!first)
            {
                sb.Append(',');
            }
            first = false;
            sb.Append(Escape(pair.Key));
            sb.Append(':');
            sb.Append(Escape(pair.Value));
        }
        sb.Append('}');
        return sb.ToString();
    }
}

public static class TplPlayground
{
    public static async Task<int> ProducerConsumerAsync(int count)
    {
        BlockingCollection<int> queue = new(boundedCapacity: 16);
        Task producer = Task.Run(() =>
        {
            for (int i = 0; i < count; i++)
            {
                queue.Add(i);
            }
            queue.CompleteAdding();
        });
        int sum = 0;
        await Task.Run(() =>
        {
            foreach (int v in queue.GetConsumingEnumerable())
            {
                sum += v;
            }
        }).ConfigureAwait(false);
        await producer.ConfigureAwait(false);
        return sum;
    }

    public static async Task<int> ParallelForAsync(int count)
    {
        int local = 0;
        await Task.Run(() =>
        {
            Parallel.For(0, count, i =>
            {
                Interlocked.Add(ref local, i);
            });
        }).ConfigureAwait(false);
        return local;
    }
}

public abstract class AnimalBase
{
    protected AnimalBase(string name)
    {
        Name = name;
    }

    public string Name { get; }

    public abstract string Sound();

    public virtual string Describe() => $"{GetType().Name}:{Name}:{Sound()}";
}

public sealed class Dog : AnimalBase
{
    public Dog(string name, string breed) : base(name)
    {
        Breed = breed;
    }

    public string Breed { get; }

    public override string Sound() => "woof";

    public override string Describe() => $"{base.Describe()}:{Breed}";
}

public sealed class Cat : AnimalBase
{
    public Cat(string name) : base(name) { }

    public override string Sound() => "meow";
}

public static class ExceptionPlayground
{
    public static int SafeDivide(int numerator, int denominator)
    {
        try
        {
            return checked(numerator / denominator);
        }
        catch (DivideByZeroException)
        {
            return 0;
        }
        catch (OverflowException) when (numerator == int.MinValue && denominator == -1)
        {
            return int.MaxValue;
        }
        finally
        {
            _ = numerator;
        }
    }

    public static T ThrowIfNull<T>(T? value, [CallerArgumentExpression(nameof(value))] string? argName = null) where T : class
    {
        if (value is null)
        {
            throw new ArgumentNullException(argName);
        }
        return value;
    }
}

public sealed class EventSource
{
    public event EventHandler<int>? Pulse;

    public void Tick(int beat)
    {
        Pulse?.Invoke(this, beat);
    }
}

public static class IteratorPlayground
{
    public static IEnumerable<int> Counting(int from, int to)
    {
        for (int i = from; i <= to; i++)
        {
            yield return i;
        }
    }

    public static IEnumerable<int> WithEarlyExit(IEnumerable<int> source, Func<int, bool> stopWhen)
    {
        foreach (int v in source)
        {
            if (stopWhen(v))
            {
                yield break;
            }
            yield return v;
        }
    }

    public static IEnumerable<(int Index, T Value)> Enumerated<T>(IEnumerable<T> source)
    {
        int i = 0;
        foreach (T v in source)
        {
            yield return (i, v);
            i++;
        }
    }
}

public static class TargetTypedNewPlayground
{
    public static Dictionary<string, List<int>> Build()
    {
        Dictionary<string, List<int>> map = new()
        {
            ["alpha"] = new() { 1, 2, 3 },
            ["beta"] = new() { 4, 5 },
            ["gamma"] = new(),
        };
        return map;
    }
}

public static class WithExpressionPlayground
{
    public static User Promote(User u) => u with
    {
        Roles = new[] { "admin", "moderator", "viewer" },
        ModifiedAt = DateTime.UtcNow,
    };

    public static Coordinate Shift(Coordinate c, double dx, double dy) => c with
    {
        Latitude = c.Latitude + dx,
        Longitude = c.Longitude + dy,
    };
}

public static class DeconstructPlayground
{
    public static (int Min, int Max, double Mean) Stats(IReadOnlyList<int> values)
    {
        int min = int.MaxValue;
        int max = int.MinValue;
        long sum = 0;
        foreach (int v in values)
        {
            if (v < min) { min = v; }
            if (v > max) { max = v; }
            sum += v;
        }
        double mean = values.Count == 0 ? 0.0d : (double)sum / values.Count;
        return (min, max, mean);
    }

    public static void Use(IReadOnlyList<int> values)
    {
        (int min, int max, double mean) = Stats(values);
        _ = (min, max, mean);
    }
}

public static class FileSystemPlayground
{
    public static IEnumerable<string> EnumerateFiles(string root)
    {
        if (!Directory.Exists(root))
        {
            yield break;
        }
        foreach (string path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            yield return path;
        }
    }

    public static long TotalSize(string root)
    {
        long total = 0;
        foreach (string path in EnumerateFiles(root))
        {
            try
            {
                total += new FileInfo(path).Length;
            }
            catch (IOException)
            {
            }
        }
        return total;
    }
}

public static class StaticFinalizationKit
{
    private static readonly Random sharedRandom = new(0xC0FFEE);

    public static int NextInt(int max) => sharedRandom.Next(max);

    public static byte[] NextBytes(int count)
    {
        byte[] buf = new byte[count];
        sharedRandom.NextBytes(buf);
        return buf;
    }
}

public sealed class FrozenSnapshot<T>
{
    private readonly T[] items;

    public FrozenSnapshot(IEnumerable<T> source)
    {
        items = source.ToArray();
    }

    public int Count => items.Length;

    public T this[int index] => items[index];

    public ReadOnlySpan<T> Span => items.AsSpan();
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = false)]
public sealed class TraceableAttribute : Attribute
{
    public TraceableAttribute(string category)
    {
        Category = category;
    }

    public string Category { get; }
    public int Priority { get; set; }
}

[Traceable("infrastructure", Priority = 5)]
public sealed class Pipeline
{
    private readonly Action<string> log;

    public Pipeline(Action<string> log)
    {
        this.log = log;
    }

    [Traceable("execution", Priority = 1)]
    public int RunSteps(IEnumerable<Func<int, int>> steps, int seed)
    {
        int acc = seed;
        foreach (Func<int, int> step in steps)
        {
            acc = step(acc);
            log($"step:{acc}");
        }
        return acc;
    }
}

public static class ConditionalCompilation
{
#if DEBUG
    public const string BuildKind = "debug";
#else
    public const string BuildKind = "release";
#endif

#if NET9_0_OR_GREATER
    public const string Tfm = "net9";
#elif NET7_0_OR_GREATER
    public const string Tfm = "net7";
#elif NETSTANDARD2_0
    public const string Tfm = "netstandard2.0";
#else
    public const string Tfm = "unknown";
#endif
}

public static class EntryPoint
{
    public static int Sum(int a, int b, int c) => a + b + c;

    public static string Greeting(string name) => $"hello, {name}!";

    public static IReadOnlyDictionary<string, object> Snapshot()
    {
        Dictionary<string, object> map = new()
        {
            ["build"] = ConditionalCompilation.BuildKind,
            ["tfm"] = ConditionalCompilation.Tfm,
            ["pid"] = PinvokePlayground.GetCurrentProcessId(),
        };
        return map;
    }
}
