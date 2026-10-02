<?php
function dead_ternary(int $b, int $c, int $e): array
{
    $out = [];
    $t = [];
    $d = 9;
    foreach (range(1, 2) as $i) {
        $a = ($c + $i) % 1000;
        if (in_array($d - 18, $t, true)) {
            $out[] = 'listed';
        } elseif (14 >= $a) {
            $e *= (4 * $e) % 97;
            $e %= 1000;
            $t[] = ($d * $b) % 97;
            $a = ((13 !== ($e * 15) % 97) && $e > 6) ? intdiv($d, 1) : $b;
        } else {
            $out[] = intdiv($e, 3);
        }
        $out[] = $e;
    }
    return $out;
}

function dead_break(int $a, int $b, int $d): array
{
    $out = [];
    $t = [];
    foreach (range(0, 2) as $i) {
        $out[] = $a + $i;
        $n = 0;
        do {
            $n++;
            foreach (range(3, 4) as $j) {
                $c = ($b + $j) % 1000;
                $a -= $c;
                $a %= 1000;
                $t[] = $a;
            }
            if (($a + $c) >= ($b % 9) && $d > 3) {
                break;
            }
        } while ($n < 1 && (in_array(1 + $b, $t, true) || $n === 1));
        if ($d > (19 % 4)) {
            break;
        }
    }
    $out[] = $a;
    return $out;
}

function chain_fallback(int $c, int $e): array
{
    $out = [];
    $d = 2;
    foreach (range(1, 3) as $i) {
        $out[] = $i;
        if ($c * $c % 97 < 4 || $c === 7) {
            $out[] = $c;
            if ($e <= intdiv($e, 7)) {
                $out[] = 1;
            }
        }
        if (83 !== $d) {
            continue;
        }
        $out[] = $d;
    }
    return $out;
}

foreach ([[1, 2, 3], [9, 7, 5], [2, 13, 8]] as [$x, $y, $z]) {
    echo implode(' ', dead_ternary($x, $y, $z)), ' | ', implode(' ', dead_break($x, $y, $z)), ' | ', implode(' ', chain_fallback($x, $z)), "\n";
}
