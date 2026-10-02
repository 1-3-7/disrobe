<?php
function run(int $a, int $b, int $c): array
{
    $out = [];
    $t = [];
    $t[] = $b;
    if ($a > $c) {
        $out[] = 'then';
        try {
            $out[] = $c % ($a - $b);
            $n = 0;
            while ($n < 2 && ((8 < ((16 * 17) % 97)) || $c === 7 || $n === 0)) {
                $n++;
                $out[] = $t[2] ?? $n * $a;
                if ($b >= 19) {
                    continue;
                }
                $out[] = $a;
            }
        } catch (DivisionByZeroError $error) {
            $out[] = 'zero';
        }
    } else {
        $t[] = 1;
        $out[] = 'else';
    }
    $out[] = count($t);
    return $out;
}

echo implode(' ', run(5, 1, 2)), "\n";
echo implode(' ', run(5, 5, 2)), "\n";
echo implode(' ', run(30, 20, 2)), "\n";
echo implode(' ', run(1, 1, 2)), "\n";
