<?php

$a = 1;
$b = &$a;
$b = 5;
echo "$a $b\n";
unset($b);
$b = 9;
echo "$a $b\n";

$arr = [1, 2, 3];
$ref = &$arr[1];
$copy = $arr;
$ref = 'changed';
echo json_encode($arr), ' ', json_encode($copy), "\n";

$x = 10;
$y = 20;
$pair = [&$x, &$y];
$pair[0]++;
$pair[1] *= 2;
echo "$x $y\n";

function append(array &$list, mixed $value): int
{
    $list[] = $value;

    return count($list);
}

$items = [];
append($items, 'a');
echo append($items, 'b'), ' ', implode('', $items), "\n";

function set_nested(array &$tree, array $path, mixed $value): void
{
    $node = &$tree;
    foreach ($path as $key) {
        if (!isset($node[$key]) || !is_array($node[$key])) {
            $node[$key] = [];
        }
        $node = &$node[$key];
    }
    $node = $value;
}

$tree = [];
set_nested($tree, ['a', 'b', 'c'], 1);
set_nested($tree, ['a', 'd'], 2);
echo json_encode($tree), "\n";

$matrix = [[1, 2], [3, 4]];
foreach ($matrix as &$row) {
    foreach ($row as &$cell) {
        $cell = $cell * $cell;
    }
    unset($cell);
}
unset($row);
echo json_encode($matrix), "\n";

$obj = new stdClass();
$obj->val = 1;
$alias = $obj;
$alias->val = 2;
$clone = clone $obj;
$clone->val = 3;
echo $obj->val, $alias->val, $clone->val, "\n";

$config = ['level' => 1];
$level = &$config['level'];
$level = 7;
$config2 = $config;
$config2['level'] = 8;
echo $config['level'], ' ', $config2['level'], "\n";

$swap = function (&$l, &$r): void {
    [$l, $r] = [$r, $l];
};
$m = 'M';
$n = 'N';
$swap($m, $n);
echo "$m$n\n";

$data = ['k' => ['v' => 1]];
$inner = &$data['k']['v'];
$inner += 41;
echo $data['k']['v'], "\n";
