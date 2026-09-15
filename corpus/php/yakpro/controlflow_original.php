<?php
function classify($n) {
    if ($n > 10) {
        return "big";
    } else {
        return "small";
    }
}
$sum = 0;
for ($i = 1; $i <= 5; $i++) {
    $sum += $i;
}
echo classify(15);
echo "\n";
echo "sum=" . $sum;
