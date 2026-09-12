<?php

declare(strict_types=1);

namespace App\EdgeCases;

use Countable;
use Iterator;
use IteratorAggregate;
use Stringable;
use Throwable;
use WeakMap;
use ArrayObject;

const APP_VERSION = '1.0.0';
const APP_MAX_RETRIES = 5;
const APP_DEFAULTS = ['verbose' => false, 'retries' => 3, 'timeout' => 5000];

enum Status: string
{
    case Active = 'active';
    case Inactive = 'inactive';
    case Pending = 'pending';
    case Archived = 'archived';

    public function label(): string
    {
        return match ($this) {
            self::Active => 'Active user',
            self::Inactive => 'Inactive user',
            self::Pending => 'Pending verification',
            self::Archived => 'Archived account',
        };
    }

    public static function fromLabel(string $label): ?self
    {
        return match ($label) {
            'Active user' => self::Active,
            'Inactive user' => self::Inactive,
            'Pending verification' => self::Pending,
            'Archived account' => self::Archived,
            default => null,
        };
    }
}

enum Priority: int
{
    case Low = 1;
    case Medium = 5;
    case High = 10;
    case Critical = 100;
}

enum LogLevel
{
    case Debug;
    case Info;
    case Warning;
    case Error;
    case Fatal;
}

interface Identifiable
{
    public function getId(): int;
}

interface Nameable
{
    public function getName(): string;
}

interface Serializable
{
    public function serialize(): string;
    public function deserialize(string $data): void;
}

interface Repository
{
    public function find(int $id): ?object;
    public function save(object $entity): void;
    public function delete(int $id): bool;
}

abstract class AbstractEntity implements Identifiable, Nameable, Stringable
{
    public function __construct(
        public readonly int $id,
        public readonly string $name,
        protected ?\DateTimeImmutable $createdAt = null,
    ) {
        $this->createdAt ??= new \DateTimeImmutable();
    }

    public function getId(): int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    abstract public function describe(): string;

    public function __toString(): string
    {
        return $this->describe();
    }
}

readonly class User extends AbstractEntity
{
    public function __construct(
        int $id,
        string $name,
        public string $email,
        public Status $status = Status::Pending,
        public Priority $priority = Priority::Medium,
        public array $roles = [],
    ) {
        parent::__construct($id, $name);
    }

    public function describe(): string
    {
        return sprintf('User#%d %s <%s> (%s)', $this->id, $this->name, $this->email, $this->status->value);
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }

    public function withStatus(Status $status): self
    {
        return new self($this->id, $this->name, $this->email, $status, $this->priority, $this->roles);
    }
}

final class Product extends AbstractEntity
{
    private static int $instances = 0;

    public function __construct(
        int $id,
        string $name,
        public readonly float $price,
        public readonly string $sku,
        private array $tags = [],
        private ?int $stock = null,
    ) {
        parent::__construct($id, $name);
        self::$instances++;
    }

    public static function instanceCount(): int
    {
        return self::$instances;
    }

    public function describe(): string
    {
        return sprintf('Product[%s] %s @ %.2f', $this->sku, $this->name, $this->price);
    }

    public function addTag(string $tag): void
    {
        if (!in_array($tag, $this->tags, true)) {
            $this->tags[] = $tag;
        }
    }

    public function getTags(): array
    {
        return $this->tags;
    }

    public function getStock(): ?int
    {
        return $this->stock;
    }

    public function setStock(?int $stock): void
    {
        $this->stock = $stock;
    }
}

trait Timestamps
{
    private ?\DateTimeImmutable $createdAt = null;
    private ?\DateTimeImmutable $updatedAt = null;

    public function touch(): void
    {
        $now = new \DateTimeImmutable();
        $this->createdAt ??= $now;
        $this->updatedAt = $now;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getUpdatedAt(): ?\DateTimeImmutable
    {
        return $this->updatedAt;
    }
}

trait Loggable
{
    private array $logEntries = [];

    public function log(LogLevel $level, string $message): void
    {
        $this->logEntries[] = ['level' => $level, 'message' => $message, 'at' => microtime(true)];
    }

    public function getLogs(): array
    {
        return $this->logEntries;
    }

    public function clearLogs(): void
    {
        $this->logEntries = [];
    }
}

class Order
{
    use Timestamps;
    use Loggable;

    private array $items = [];

    public function __construct(
        public readonly int $id,
        public readonly User $customer,
    ) {
        $this->touch();
    }

    public function addItem(Product $product, int $quantity): void
    {
        $this->items[] = ['product' => $product, 'quantity' => $quantity];
        $this->log(LogLevel::Info, "added product {$product->sku} x{$quantity}");
        $this->touch();
    }

    public function total(): float
    {
        $sum = 0.0;
        foreach ($this->items as $item) {
            $sum += $item['product']->price * $item['quantity'];
        }
        return $sum;
    }

    public function itemCount(): int
    {
        return count($this->items);
    }
}

class InventoryService
{
    public function __construct(
        private array &$stock,
        private LogLevel $minLogLevel = LogLevel::Info,
    ) {
    }

    public function adjust(string $sku, int $delta): int
    {
        $current = $this->stock[$sku] ?? 0;
        $next = $current + $delta;
        if ($next < 0) {
            throw new \UnderflowException("stock for {$sku} would be negative");
        }
        $this->stock[$sku] = $next;
        return $next;
    }

    public function get(string $sku): int
    {
        return $this->stock[$sku] ?? 0;
    }
}

class FibonacciIterator implements Iterator
{
    private int $current = 0;
    private int $next = 1;
    private int $key = 0;
    private int $max;

    public function __construct(int $max = 20)
    {
        $this->max = $max;
    }

    public function current(): int
    {
        return $this->current;
    }

    public function key(): int
    {
        return $this->key;
    }

    public function next(): void
    {
        [$this->current, $this->next] = [$this->next, $this->current + $this->next];
        $this->key++;
    }

    public function rewind(): void
    {
        $this->current = 0;
        $this->next = 1;
        $this->key = 0;
    }

    public function valid(): bool
    {
        return $this->key < $this->max;
    }
}

class Collection implements IteratorAggregate, Countable
{
    public function __construct(private array $items = [])
    {
    }

    public function add(mixed $item): void
    {
        $this->items[] = $item;
    }

    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->items);
    }

    public function count(): int
    {
        return count($this->items);
    }

    public function map(callable $fn): self
    {
        return new self(array_map($fn, $this->items));
    }

    public function filter(callable $fn): self
    {
        return new self(array_values(array_filter($this->items, $fn)));
    }

    public function reduce(callable $fn, mixed $initial = null): mixed
    {
        return array_reduce($this->items, $fn, $initial);
    }
}

class GeneratorDemo
{
    public function range(int $start, int $end, int $step = 1): \Generator
    {
        for ($i = $start; $i <= $end; $i += $step) {
            yield $i;
        }
    }

    public function keyedRange(int $start, int $end): \Generator
    {
        for ($i = $start; $i <= $end; $i++) {
            yield "k{$i}" => $i * $i;
        }
    }

    public function yieldFrom(): \Generator
    {
        yield 1;
        yield from $this->range(2, 5);
        yield 6;
        yield from [7, 8, 9];
    }

    public function generatorWithReturn(): \Generator
    {
        yield 1;
        yield 2;
        return 'final';
    }

    public function infiniteCounter(): \Generator
    {
        $n = 0;
        while (true) {
            $next = yield $n;
            $n = $next ?? $n + 1;
        }
    }
}

function withClosure(): \Closure
{
    $count = 0;
    return function () use (&$count): int {
        return ++$count;
    };
}

function variadicSum(int ...$values): int
{
    return array_sum($values);
}

function spreadDemo(array $args): array
{
    return [...$args, 'extra'];
}

function namedArgs(string $url, int $timeout = 30, bool $verify = true, array $headers = []): array
{
    return compact('url', 'timeout', 'verify', 'headers');
}

function unionTypes(int|string|null $input): string
{
    return match (true) {
        is_int($input) => "int:{$input}",
        is_string($input) => "str:{$input}",
        is_null($input) => 'null',
    };
}

function intersectionTypes(Identifiable&Nameable $entity): string
{
    return $entity->getId() . ':' . $entity->getName();
}

function neverReturns(string $reason): never
{
    throw new \RuntimeException($reason);
}

function nullsafeDemo(?User $user): ?string
{
    return $user?->status?->label() ?? 'no user';
}

function arrayDestructure(array $row): array
{
    ['id' => $id, 'name' => $name, 'email' => $email] = $row;
    [, , $third] = [10, 20, 30, 40];
    return [$id, $name, $email, $third];
}

function matchExpression(mixed $value): string
{
    return match (true) {
        is_int($value) && $value < 0 => 'negative int',
        is_int($value) && $value === 0 => 'zero int',
        is_int($value) => 'positive int',
        is_string($value) && strlen($value) === 0 => 'empty string',
        is_string($value) => 'nonempty string',
        is_array($value) && count($value) === 0 => 'empty array',
        is_array($value) => 'nonempty array',
        is_object($value) => 'object:' . $value::class,
        default => 'other',
    };
}

function firstClassCallable(): array
{
    $upper = strtoupper(...);
    $explode = explode(...);
    $userDescribe = User::describe(...);
    return [$upper('hi'), $explode(',', 'a,b,c'), $userDescribe::class];
}

function throwExpression(?string $value): string
{
    return $value ?? throw new \InvalidArgumentException('required');
}

function callableArray(): array
{
    $fns = [
        'upper' => strtoupper(...),
        'lower' => strtolower(...),
        'reverse' => strrev(...),
    ];
    return array_map(fn(callable $f) => $f('Hello'), $fns);
}

function genericFold(array $items, callable $reducer, mixed $initial): mixed
{
    $acc = $initial;
    foreach ($items as $item) {
        $acc = $reducer($acc, $item);
    }
    return $acc;
}

function anonClassDemo(int $seed): object
{
    return new class($seed) {
        public function __construct(private int $seed)
        {
        }

        public function next(): int
        {
            return $this->seed = ($this->seed * 1103515245 + 12345) & 0x7fffffff;
        }
    };
}

function weakMapDemo(): WeakMap
{
    $map = new WeakMap();
    $a = new \stdClass();
    $b = new \stdClass();
    $map[$a] = 'alpha';
    $map[$b] = 'beta';
    return $map;
}

function arrayObjectDemo(): ArrayObject
{
    return new ArrayObject(['x' => 1, 'y' => 2, 'z' => 3]);
}

function tryCatchFinally(int $divisor): array
{
    try {
        if ($divisor === 0) {
            throw new \DivisionByZeroError('divide by zero');
        }
        $result = 100 / $divisor;
        return ['ok' => true, 'value' => $result];
    } catch (\DivisionByZeroError $e) {
        return ['ok' => false, 'error' => 'div_zero'];
    } catch (\Throwable $t) {
        return ['ok' => false, 'error' => $t::class];
    } finally {
            }
}

function multiCatch(string $kind): string
{
    try {
        if ($kind === 'arg') {
            throw new \InvalidArgumentException('bad');
        } elseif ($kind === 'logic') {
            throw new \LogicException('logic');
        } else {
            throw new \RuntimeException('runtime');
        }
    } catch (\InvalidArgumentException | \LogicException $e) {
        return 'caught_arg_or_logic';
    } catch (\Throwable $t) {
        return 'caught_other';
    }
}

function tryCatchOnly(string $kind): bool
{
    try {
        if ($kind === 'fail') {
            throw new \Exception();
        }
    } catch (\Throwable) {
        return false;
    }
    return true;
}

function fiberDemo(): array
{
    $fiber = new \Fiber(function (int $start): int {
        $a = $start;
        $b = \Fiber::suspend($a + 1);
        return $a + $b;
    });
    $first = $fiber->start(10);
    $final = $fiber->resume(100);
    return [$first, $final];
}

function generatorWithKeys(): array
{
    $gen = (new GeneratorDemo())->keyedRange(1, 4);
    $out = [];
    foreach ($gen as $k => $v) {
        $out[$k] = $v;
    }
    return $out;
}

function stringInterpolation(string $name, int $age): string
{
    $msg = "Hello, {$name}, you are {$age}";
    $direct = "Direct: $name";
    $heredoc = <<<HEREDOC
Heredoc says hi to {$name}
Age is {$age}
HEREDOC;
    $nowdoc = <<<'NOWDOC'
Nowdoc preserves $name literally
NOWDOC;
    return $msg . '|' . $direct . '|' . $heredoc . '|' . $nowdoc;
}

function regexDemo(string $text): array
{
    $matches = [];
    preg_match_all('/\b([A-Z][a-z]+)\b/', $text, $matches);
    $replaced = preg_replace_callback('/\d+/', fn(array $m) => '[' . $m[0] . ']', $text);
    return ['matches' => $matches[1], 'replaced' => $replaced];
}

function jsonRoundtrip(mixed $value): mixed
{
    $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
    return json_decode($encoded, true, 512, JSON_THROW_ON_ERROR);
}

function sortAndShuffle(array $items): array
{
    $copy = $items;
    sort($copy);
    $rsort = $items;
    rsort($rsort);
    usort($items, fn($a, $b) => strcmp((string)$a, (string)$b));
    return ['sorted' => $copy, 'rsorted' => $rsort, 'usorted' => $items];
}

function complexArrayOps(): array
{
    $items = range(1, 10);
    $mapped = array_map(fn(int $n) => $n * 2, $items);
    $filtered = array_filter($mapped, fn(int $n) => $n > 5);
    $reduced = array_reduce($filtered, fn(int $carry, int $n) => $carry + $n, 0);
    $unique = array_unique([1, 2, 2, 3, 3, 4]);
    $keyed = array_combine(['a', 'b', 'c'], [1, 2, 3]);
    $flipped = array_flip($keyed);
    return compact('mapped', 'filtered', 'reduced', 'unique', 'keyed', 'flipped');
}

function nestedConditions(int $value, ?string $tag, bool $flag): string
{
    if ($value > 0 && ($tag !== null && $tag !== '') && $flag) {
        return 'all positive';
    } elseif ($value === 0 || $tag === null) {
        return 'partial';
    } else {
        return $flag ? 'flag only' : 'none';
    }
}

function switchLikeMatch(int $code): string
{
    return match ($code) {
        100, 101, 102, 103 => 'informational',
        200, 201, 202, 203, 204 => 'success',
        300, 301, 302, 303, 304 => 'redirect',
        400, 401, 403, 404 => 'client error',
        500, 502, 503, 504 => 'server error',
        default => 'unknown',
    };
}

function loopVariety(array $items): array
{
    $out = [];
    for ($i = 0, $n = count($items); $i < $n; $i++) {
        $out['for'][] = $items[$i];
    }
    foreach ($items as $idx => $value) {
        $out['foreach'][$idx] = $value;
    }
    $i = 0;
    while ($i < count($items)) {
        $out['while'][] = $items[$i++];
    }
    $i = 0;
    do {
        $out['dowhile'][] = $items[$i++];
    } while ($i < count($items));
    return $out;
}

function refDemo(array &$values): void
{
    foreach ($values as &$v) {
        $v *= 2;
    }
    unset($v);
}

function magicMethodsDemo(): object
{
    return new class {
        private array $data = [];

        public function __set(string $name, mixed $value): void
        {
            $this->data[$name] = $value;
        }

        public function __get(string $name): mixed
        {
            return $this->data[$name] ?? null;
        }

        public function __isset(string $name): bool
        {
            return isset($this->data[$name]);
        }

        public function __unset(string $name): void
        {
            unset($this->data[$name]);
        }

        public function __call(string $name, array $args): string
        {
            return "called {$name} with " . count($args) . ' args';
        }

        public static function __callStatic(string $name, array $args): string
        {
            return "static called {$name}";
        }

        public function __invoke(mixed $x): mixed
        {
            return $x;
        }
    };
}

function staticPropertyDemo(): int
{
    static $counter = 0;
    return ++$counter;
}

function attributesDemo(): array
{
    $reflection = new \ReflectionClass(AttributedThing::class);
    $attrs = $reflection->getAttributes();
    return array_map(fn(\ReflectionAttribute $a) => $a->getName(), $attrs);
}


class Route
{
    public function __construct(public readonly string $path, public readonly string $method = 'GET')
    {
    }
}


class Cached
{
    public function __construct(public readonly int $ttl = 60)
    {
    }
}


class AttributedThing
{

    public function list(): array
    {
        return [];
    }


    public function compute(int $x): int
    {
        return $x * 2;
    }
}

class InMemoryRepository implements Repository
{
    private array $store = [];

    public function find(int $id): ?object
    {
        return $this->store[$id] ?? null;
    }

    public function save(object $entity): void
    {
        if ($entity instanceof Identifiable) {
            $this->store[$entity->getId()] = $entity;
        }
    }

    public function delete(int $id): bool
    {
        if (isset($this->store[$id])) {
            unset($this->store[$id]);
            return true;
        }
        return false;
    }

    public function all(): array
    {
        return array_values($this->store);
    }
}

function groupUseDemo(): array
{
    return [
        'classes' => [User::class, Product::class, Order::class],
        'enums' => [Status::class, Priority::class, LogLevel::class],
    ];
}

function arrowFnPipeline(array $list): array
{
    $double = fn(int $n): int => $n * 2;
    $square = fn(int $n): int => $n * $n;
    $compose = fn(callable $f, callable $g): callable => fn($x) => $f($g($x));
    return array_map($compose($double, $square), $list);
}

function curryDemo(): callable
{
    return fn(int $a): callable => fn(int $b): callable => fn(int $c): int => $a + $b + $c;
}

function pipelineLike(mixed $value, callable ...$pipes): mixed
{
    foreach ($pipes as $pipe) {
        $value = $pipe($value);
    }
    return $value;
}

function fmtStatusReport(User $user): string
{
    return <<<RPT
=== Status Report ===
Name: {$user->getName()}
Email: {$user->email}
Status: {$user->status->value} ({$user->status->label()})
Priority: {$user->priority->name} = {$user->priority->value}
Roles:
=====================
RPT;
}

function bigIntArithmetic(): array
{
    $a = PHP_INT_MAX;
    $b = $a + 1;
    $float = (float)$a;
    return ['max' => $a, 'overflow' => $b, 'float' => $float];
}

function typedConstantsDemo(): object
{
    return new class {
        public const string GREETING = 'hello';
        public const int VERSION = 1;
        public const array FEATURES = ['caching', 'logging'];
    };
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    echo "edge_cases.php loaded; PHP version " . PHP_VERSION . "\n";
    echo "instances: " . Product::instanceCount() . "\n";
    $user = new User(1, 'alice', 'alice@example.com', Status::Active, Priority::High, ['admin']);
    echo $user->describe() . "\n";
    echo matchExpression(42) . "\n";
    echo matchExpression('hello') . "\n";
    echo jsonRoundtrip(['a' => 1, 'b' => [2, 3]])['a'] . "\n";
}
