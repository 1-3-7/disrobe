<?php
function run(int $a, int $b, int $e): array
{
    $out = [];
    $k = 4;
    $n = 0;
    do {
        $n++;
        $c = (intdiv($a, 5) >= $b - $e || $k === 7) ? 15 + $b : 9 - 5;
        $out[] = $c;
        $out[] = ($a - $b !== 9 || $k === 2) ? 4 + $c : ($b * 14) % 97;
        $out[] = ($e !== 14 || $k === 1) ? 6 : intdiv($e, 1);
        $b++;
    } while ($n < 3);
    return $out;
}

echo implode(' ', run(30, 1, 2)), "\n";
echo implode(' ', run(3, 7, 14)), "\n";
echo implode(' ', run(12, 3, 0)), "\n";
