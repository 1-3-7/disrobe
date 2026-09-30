<?php

function tick(): int
{
    static $n = 0;
    $n++;

    return $n;
}

function memo(int $x): int
{
    static $cache = [];
    static $misses = 0;
    if (!isset($cache[$x])) {
        $misses++;
        $cache[$x] = $x * $x;
    }

    return $cache[$x] * 1000 + $misses;
}

function seq(string $prefix): string
{
    static $counters = [];
    $counters[$prefix] = ($counters[$prefix] ?? 0) + 1;

    return $prefix . $counters[$prefix];
}

class Registry
{
    private static array $items = [];
    public static int $count = 0;

    public static function add(string $name): void
    {
        static $calls = 0;
        $calls++;
        self::$items[] = "$name#$calls";
        static::$count = count(self::$items);
    }

    public static function all(): string
    {
        return implode(',', self::$items);
    }
}

echo tick(), tick(), tick(), "\n";
echo memo(3), ' ', memo(4), ' ', memo(3), "\n";
echo seq('a'), seq('b'), seq('a'), seq('a'), "\n";
Registry::add('x');
Registry::add('y');
echo Registry::all(), ' ', Registry::$count, "\n";
Registry::$count += 10;
echo Registry::$count, "\n";

$closure = function (): int {
    static $calls = 0;

    return ++$calls;
};
$closure();
echo $closure(), "\n";

function make_ids(): array
{
    $ids = [];
    for ($i = 0; $i < 3; $i++) {
        $ids[] = tick();
    }

    return $ids;
}

echo implode(',', make_ids()), "\n";
