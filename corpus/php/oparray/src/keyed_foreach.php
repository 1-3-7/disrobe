<?php

$seed = 100;
$rows = [];
$rows[] = $seed;
$rows[] = 200;
$rows[] = 300;
$acc = 0;
foreach ($rows as $idx => $value) {
    $acc = $acc + $value;
    echo $idx . ":" . $value, "\n";
}
echo "acc=" . $acc, "\n";

$labels = [];
$labels[] = "a";
$labels[] = "b";
foreach ($labels as $pos => $label) {
    echo $pos . "->" . $label, "\n";
}
