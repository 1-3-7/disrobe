<?php

$n = 0;
$sum = 0;
do {
    $sum = $sum + $n;
    $n = $n + 1;
} while ($n < 5);
echo $sum, "\n";

$count = 10;
do {
    $count = $count - 3;
    echo $count, "\n";
} while ($count > 0);
