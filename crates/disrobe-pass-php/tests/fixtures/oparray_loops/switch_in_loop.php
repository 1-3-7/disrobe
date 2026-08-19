<?php

$seed = 0;
$codes = [];
$codes[] = $seed;
$codes[] = 1;
$codes[] = 2;
$codes[] = 3;
$codes[] = 4;

$score = 0;
foreach ($codes as $code) {
    switch ($code) {
        case 1:
            $score = $score + 1;
            break;
        case 2:
            $score = $score + 20;
            continue 2;
        case 3:
            $score = $score + 300;
            break 2;
        default:
            $score = $score + 4000;
    }
    $score = $score + 50000;
}
echo "switch-foreach ", $score, "\n";

$tally = 0;
$n = 0;
while ($n < 6) {
    $n = $n + 1;
    switch ($n) {
        case 2:
            $tally = $tally + 1;
            break;
        case 4:
            continue 2;
        case 5:
            break 2;
        default:
            $tally = $tally + 10;
    }
    $tally = $tally + 100;
}
echo "switch-while ", $tally, " ", $n, "\n";
