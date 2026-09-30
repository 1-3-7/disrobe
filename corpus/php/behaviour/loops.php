<?php

$sum = 0;
for ($i = 0; $i < 10; $i++) {
    if ($i === 2) {
        continue;
    }
    if ($i === 7) {
        break;
    }
    $sum += $i;
}
echo "for: $sum\n";

for ($i = 0, $j = 10; $i < $j; $i += 3, $j--) {
    echo $i, '-', $j, ' ';
}
echo "\n";

$n = 20;
$steps = 0;
while ($n !== 1) {
    $n = $n % 2 === 0 ? intdiv($n, 2) : 3 * $n + 1;
    $steps++;
}
echo "collatz steps: $steps\n";

$k = 0;
do {
    echo 'do ', $k, "\n";
    $k++;
} while ($k < 3);

$once = 10;
do {
    echo "ran once with $once\n";
} while ($once < 5);

$found = [];
for ($a = 1; $a <= 4; $a++) {
    for ($b = 1; $b <= 4; $b++) {
        if ($b === $a) {
            continue 2;
        }
        if ($a * $b > 6) {
            break 2;
        }
        $found[] = "$a*$b";
    }
}
echo implode(',', $found), "\n";

$outer = 0;
while (true) {
    $outer++;
    $inner = 0;
    while (true) {
        $inner++;
        if ($inner > 2) {
            continue 2;
        }
        if ($outer > 3) {
            break 2;
        }
        echo "o$outer i$inner ";
    }
}
echo "\n";

$x = 0;
do {
    $x++;
    if ($x % 2) {
        continue;
    }
    echo "even $x ";
} while ($x < 6);
echo "\n";

for (;;) {
    $x--;
    if ($x < 3) {
        break;
    }
}
echo "x=$x\n";
