<?php

[$a, $b] = [1, 2];
echo "$a $b\n";

[$a, $b] = [$b, $a];
echo "swapped $a $b\n";

list($x, , $z) = ['X', 'Y', 'Z'];
echo "$x $z\n";

['id' => $id, 'name' => $nm] = ['name' => 'widget', 'id' => 42];
echo "$id $nm\n";

[[$p, $q], [$r, $s]] = [[1, 2], [3, 4]];
echo $p + $q + $r + $s, "\n";

['point' => [$px, $py], 'label' => $label] = ['label' => 'origin', 'point' => [0, 5]];
echo "$label ($px, $py)\n";

list('k' => list($deep)) = ['k' => ['deep value']];
echo $deep, "\n";

function pair(int $n): array
{
    return [$n * 2, $n * 3];
}

[$double, $triple] = pair(7);
echo "$double $triple\n";

$rows = [['a', 1], ['b', 2], ['c', 3]];
$out = [];
foreach ($rows as [$letter, $num]) {
    $out[] = str_repeat($letter, $num);
}
echo implode(',', $out), "\n";

$data = [];
[$data['first'], $data['second']] = ['one', 'two'];
echo json_encode($data), "\n";

$obj = new stdClass();
[$obj->left, $obj->right] = ['L', 'R'];
echo $obj->left, $obj->right, "\n";

[, $second] = explode(':', 'k:v');
echo $second, "\n";

$missing = [1];
[$m1, $m2] = $missing + [1 => 'default'];
echo "$m1 $m2\n";

$src = [10, 20];
[$r1, &$r2] = $src;
$r2 = 99;
echo implode(',', $src), "\n";

$idx = 1;
[$idx => $picked] = ['zero', 'one'];
echo $picked, "\n";
