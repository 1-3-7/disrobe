<?php

$list = ['a', 'b', 'c'];
foreach ($list as $v) {
    echo $v;
}
echo "\n";

$map = ['one' => 1, 'two' => 2, 'three' => 3];
foreach ($map as $k => $v) {
    echo "$k=$v;";
}
echo "\n";

$nums = [1, 2, 3, 4];
foreach ($nums as &$n) {
    $n *= 10;
}
unset($n);
echo implode(',', $nums), "\n";

$grid = [[1, 2, 3], [4, 5, 6], [7, 8, 9]];
foreach ($grid as $r => $row) {
    foreach ($row as $c => $cell) {
        if ($cell === 5) {
            continue 2;
        }
        if ($cell === 8) {
            break 2;
        }
        echo "[$r,$c]=$cell ";
    }
}
echo "\n";

$totals = ['x' => 1, 'y' => 2];
foreach ($totals as $key => &$total) {
    $total = $key . ':' . ($total + 100);
}
unset($total);
var_dump($totals);

$pairs = [[1, 'one'], [2, 'two']];
foreach ($pairs as [$num, $word]) {
    echo "$num is $word\n";
}
foreach ([['id' => 7, 'tag' => 'q']] as ['id' => $id, 'tag' => $tag]) {
    echo "$id/$tag\n";
}

$obj = new stdClass();
$obj->first = 'F';
$obj->second = 'S';
foreach ($obj as $prop => $val) {
    echo "$prop->$val\n";
}

$empty = [];
foreach ($empty as $v) {
    echo "never\n";
}
echo "after empty\n";

$copy = [1, 2];
foreach ($copy as $v) {
    $copy[] = $v + 10;
}
echo implode(',', $copy), "\n";

function gen_keys(): iterable
{
    return ['p' => 'P', 5 => 'five', 'q' => 'Q'];
}
foreach (gen_keys() as $k => $v) {
    echo gettype($k), ":$k=$v ";
}
echo "\n";
