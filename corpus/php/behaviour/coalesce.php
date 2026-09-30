<?php

$config = ['db' => ['host' => 'localhost', 'port' => null], 'debug' => false];

echo $config['db']['host'] ?? 'no host', "\n";
echo $config['db']['port'] ?? 5432, "\n";
echo $config['cache']['ttl'] ?? 'no ttl', "\n";
echo var_export($config['debug'] ?? true, true), "\n";
echo $undefined ?? 'undefined var', "\n";
echo $config['a'] ?? $config['b'] ?? $config['db']['host'] ?? 'none', "\n";

$config['cache']['ttl'] ??= 60;
$config['cache']['ttl'] ??= 120;
$config['db']['port'] ??= 3306;
echo $config['cache']['ttl'], ' ', $config['db']['port'], "\n";

$counter = null;
$counter ??= 0;
$counter += 5;
echo $counter, "\n";

$obj = new stdClass();
$obj->name ??= 'first';
$obj->name ??= 'second';
echo $obj->name, "\n";
echo $obj->missing->deeper ?? 'deep miss', "\n";

$calls = 0;
function side(int &$calls): string
{
    $calls++;

    return 'side';
}

$present = 'here';
echo $present ?? side($calls), " calls=$calls\n";
echo $absent ?? side($calls), " calls=$calls\n";

$zero = 0;
echo $zero ?: 'falsy', ' ', $zero ?? 'null', "\n";

$list = [0 => 'zero', '' => 'empty key'];
echo $list[0] ?? '-', $list[''] ?? '-', $list[1] ?? '-', "\n";

$maybe = null;
echo $maybe?->prop ?? 'nullsafe', "\n";

function pick(?array $opts): string
{
    return $opts['mode'] ?? 'default';
}

echo pick(null), ' ', pick(['mode' => 'fast']), "\n";

$str = 'text';
echo $str[10] ?? 'no char', ' ', $str[0] ?? '?', "\n";

$cache = [];
foreach (['a', 'b', 'a', 'c', 'a'] as $k) {
    $cache[$k] ??= 0;
    $cache[$k]++;
}
echo json_encode($cache), "\n";
