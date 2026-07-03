<?php

$a = 6;
$b = 7;
$sum = $a + $b;
$diff = $a - $b;
$prod = $a * $b;
$quot = ($a * 10) / $b;
$rem = $b % $a;
$pow = $a ** 2;
echo $sum, "\n";
echo $diff, "\n";
echo $prod, "\n";
echo $quot, "\n";
echo $rem, "\n";
echo $pow, "\n";
$flag = ($sum > 10) && ($diff < 0);
echo $flag ? "yes" : "no", "\n";
