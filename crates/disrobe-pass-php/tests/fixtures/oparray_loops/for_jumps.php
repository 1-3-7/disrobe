<?php

$even = 0;
$rounds = 0;
for ($i = 0; $i < 10; $i++) {
    if ($i % 2 === 0) {
        if ($i === 6) {
            continue;
        }
        $even = $even + $i;
    }
    $rounds = $rounds + 1;
}
echo "for-continue ", $even, " ", $rounds, "\n";

$early = 0;
for ($j = 0; $j < 10; $j++) {
    if ($j === 4) {
        break;
    }
    $early = $early + $j;
}
echo "for-break ", $early, " ", $j, "\n";

$mixed = 0;
for ($k = 0; $k < 12; $k++) {
    if ($k % 3 === 0) {
        if ($k === 9) {
            continue;
        }
        $mixed = $mixed + 1;
    }
    if ($k === 10) {
        break;
    }
    $mixed = $mixed + 100;
}
echo "for-mixed ", $mixed, " ", $k, "\n";

$pairs = 0;
for ($a = 0, $b = 9; $a < $b; $a++, $b--) {
    if ($a === 1) {
        if ($b === 8) {
            continue;
        }
        $pairs = $pairs + 1000;
    }
    $pairs = $pairs + 1;
}
echo "for-comma ", $pairs, " ", $a, " ", $b, "\n";
