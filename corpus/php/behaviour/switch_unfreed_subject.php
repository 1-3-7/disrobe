<?php
function run(int $x, int $y): array
{
    $out = [];
    switch (($x % 4 + 4) % 4) {
        case 0:
            $out[] = 'zero';
            if ($y > 2) {
                $out[] = $y;
            }
            break;
        case 1:
        case 2:
            $out[] = 'low';
            $y += $x;
            break;
        default:
            $n = 0;
            while ($n < $y) {
                $n++;
                $out[] = $n;
            }
    }
    $out[] = $x + $y;
    return $out;
}

echo implode(' ', run(4, 3)), "\n";
echo implode(' ', run(5, 1)), "\n";
echo implode(' ', run(-2, 6)), "\n";
echo implode(' ', run(7, 2)), "\n";
