<?php

$seed = 1;
$rows = [];
$rows[] = $seed;
$rows[] = 2;
$rows[] = 3;
$cols = [];
$cols[] = 4;
$cols[] = 5;

$grid = 0;
foreach ($rows as $row) {
    foreach ($cols as $col) {
        if ($col === 5) {
            continue 2;
        }
        if ($row === 3) {
            break 2;
        }
        $grid = $grid + $row * $col;
    }
    $grid = $grid + 1000;
}
echo "foreach2 ", $grid, "\n";

$keyed = 0;
foreach ($rows as $key => $row) {
    if ($row === 2) {
        continue;
    }
    if ($row === 3) {
        break;
    }
    $keyed = $keyed + $key + $row;
}
echo "keyed ", $keyed, "\n";

$outer = 0;
$inner = 0;
while ($outer < 4) {
    $outer = $outer + 1;
    foreach ($cols as $col) {
        if ($col === 5) {
            break 2;
        }
        $inner = $inner + $col;
    }
}
echo "foreach-in-while ", $outer, " ", $inner, "\n";

$ticks = 0;
foreach ($rows as $row) {
    $q = 0;
    while ($q < 5) {
        $q = $q + 1;
        if ($q === 2) {
            continue 2;
        }
        $ticks = $ticks + 1;
    }
}
echo "while-in-foreach ", $ticks, "\n";

$deep = 0;
for ($x = 0; $x < 3; $x++) {
    for ($y = 0; $y < 3; $y++) {
        for ($z = 0; $z < 3; $z++) {
            if ($z === 1) {
                continue 3;
            }
            if ($y === 2) {
                break 3;
            }
            $deep = $deep + 1;
        }
        $deep = $deep + 100;
    }
    $deep = $deep + 10000;
}
echo "triple ", $deep, " ", $x, " ", $y, " ", $z, "\n";
