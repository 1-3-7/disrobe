<?php

$limit = 8;
$total = 0;
$i = 1;
while ($i <= $limit) {
    $total = $total + $i;
    $i = $i + 1;
}
echo $total, "\n";

if ($total > 30) {
    echo "over", "\n";
} else {
    echo "under", "\n";
}

$seed = 4;
$values = [$seed, 11, 22, 33];
$acc = 0;
foreach ($values as $value) {
    $acc = $acc + $value;
}
echo $acc, "\n";

$message = "len=" . $acc;
echo strlen($message), "\n";
echo count($values), "\n";
