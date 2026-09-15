<?php

$total = 0;
$index = 0;
while ($index < 12) {
    $index = $index + 1;
    if ($index === 3) {
        continue;
    }
    if ($index === 4) {
        continue;
    }
    if ($index > 8) {
        break;
    }
    $total = $total + $index;
}
echo "while ", $total, " ", $index, "\n";

$seen = 0;
$step = 0;
do {
    $step = $step + 1;
    if ($step === 2) {
        continue;
    }
    if ($step > 5) {
        break;
    }
    $seen = $seen + $step * 10;
} while ($step < 20);
echo "dowhile ", $seen, " ", $step, "\n";

$guard = 0;
$sum = 0;
while (true) {
    $guard = $guard + 1;
    if ($guard === 2) {
        continue;
    }
    if ($guard >= 7) {
        break;
    }
    $sum = $sum + $guard;
}
echo "infinite ", $sum, " ", $guard, "\n";
