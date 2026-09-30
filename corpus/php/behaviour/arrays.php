<?php

$list = [3, 1, 2];
$list[] = 5;
$list[10] = 'ten';
$list[] = 'eleven';
echo json_encode($list), "\n";

$assoc = ['b' => 2, 'a' => 1, 'c' => 3];
ksort($assoc);
echo json_encode($assoc), "\n";
arsort($assoc);
echo json_encode($assoc), "\n";

$nested = ['users' => [['name' => 'ann', 'age' => 30], ['name' => 'bob', 'age' => 25]]];
$nested['users'][] = ['name' => 'cid', 'age' => 35];
$nested['users'][1]['age']++;
$nested['meta']['count'] = count($nested['users']);
echo json_encode($nested), "\n";

$ages = array_column($nested['users'], 'age', 'name');
echo json_encode($ages), "\n";
usort($nested['users'], fn($l, $r) => $r['age'] <=> $l['age']);
echo implode(',', array_map(fn($u) => $u['name'], $nested['users'])), "\n";

$merged = [...[1, 2], ...['k' => 'v'], ...[3]];
echo json_encode($merged), "\n";
$plus = ['a' => 1, 'b' => 2] + ['b' => 20, 'c' => 30];
echo json_encode($plus), "\n";

$keys = ['1' => 'int key', '01' => 'string key', true => 'bool key', null => 'null key'];
var_dump($keys);

unset($list[0], $list[10]);
echo json_encode($list), ' ', json_encode(array_values($list)), "\n";
echo isset($list[1]) ? 'has 1' : 'no 1', ' ', array_key_exists(0, $list) ? 'has 0' : 'no 0', "\n";

$matrix = [];
for ($r = 0; $r < 3; $r++) {
    for ($c = 0; $c < 3; $c++) {
        $matrix[$r][$c] = $r * 3 + $c;
    }
}
echo json_encode($matrix), "\n";
echo json_encode(array_map(null, [1, 2], ['a', 'b'])), "\n";

$counts = [];
foreach (str_split('mississippi') as $ch) {
    $counts[$ch] = ($counts[$ch] ?? 0) + 1;
}
echo json_encode($counts), "\n";

$stack = [];
array_push($stack, 1, 2, 3);
$top = array_pop($stack);
array_unshift($stack, 0);
$first = array_shift($stack);
echo "$top $first ", json_encode($stack), "\n";

echo json_encode(array_slice([1, 2, 3, 4, 5], 1, 3)), ' ', json_encode(array_splice($stack, 0, 1)), "\n";
echo json_encode(array_combine(['x', 'y'], [1, 2])), ' ', json_encode(array_flip(['a', 'b'])), "\n";
echo json_encode(array_unique([1, '1', 2, 2.0, 'a', 'A'])), "\n";
echo in_array('1e1', [10]) ? 'loose hit' : 'loose miss', ' ', in_array('1e1', [10], true) ? 'strict hit' : 'strict miss', "\n";
$const = [1, 2, [3, 4], 'k' => ['deep' => true]];
echo count($const), ' ', count($const, COUNT_RECURSIVE), "\n";
