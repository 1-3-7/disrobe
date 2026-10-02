<?php
function f(int $x): int
{
    return $x > 3 ? $x - 3 : $x + 3;
}

function run(int $a, int $b, int $c): array
{
    $out = [];
    $t = [];
    $t[] = $a * 2;
    $t[] = $c;
    $d = 1;
    $e = 2;
    if (in_array($a, $t, true)) {
        $e = 18;
        $out[] = $e;
    } else {
        $d = $t[0] ?? 4;
        $d = 9;
        $e = $t[3] ?? intdiv($c, 3);
        $e = $c + 1;
    }
    $out[] = $d + $e;
    $g = match (intdiv($b, 3) % 3) { 0 => $b, 1, -1 => $c, default => 4 };
    $g = $c * 2;
    $out[] = $g;
    for ($i = 0; $i < 2; $i++) {
        $h = match (($b + $i) % 3) { 0 => $i, 1, -1 => $c, default => $b };
        $h = f($i);
        $out[] = $h;
    }
    return $out;
}

echo implode(' ', run(2, 5, 6)), "\n";
echo implode(' ', run(6, 7, 6)), "\n";
echo implode(' ', run(1, 2, 0)), "\n";
