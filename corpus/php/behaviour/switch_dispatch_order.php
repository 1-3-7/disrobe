<?php
function nested(int $k, int $a, int $c): array
{
    $out = [];
    $t = [];
    $t[] = $c;
    $e = 0;
    switch ((($k) % 4 + 4) % 4) {
        case 0:
            $out[] = 'zero';
            break;
        case 1:
        case 2:
            switch ((($a) % 4 + 4) % 4) {
                case 0:
                    $out[] = ($a % 6) + $c;
                    break;
                case 1:
                case 2:
                    $out[] = $a - $c;
                    break;
                default:
                    $e = $t[1] ?? ($c % 9);
                    $t[] = 17;
            }
            break;
    }
    $out[] = $e;
    $out[] = count($t);
    return $out;
}

function leading(int $k, int $b): array
{
    $out = [];
    $d = 2;
    switch ((($k - $b) % 4 + 4) % 4) {
        case 0:
            break;
        case 1:
        case 2:
            $out[] = $b + $b;
            $out[] = 'low';
            break;
        default:
            $out[] = 'other';
            if ($b > $d) {
                $out[] = $b;
            }
    }
    $out[] = 'end';
    return $out;
}

foreach ([[0, 1, 2], [1, 0, 3], [2, 1, 4], [5, 3, 1], [6, 2, 7], [3, 7, 8]] as [$k, $a, $c]) {
    echo implode(' ', nested($k, $a, $c)), ' | ', implode(' ', leading($k, $a)), "\n";
}
