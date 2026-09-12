<?php

require __DIR__ . '/lib/greeter.php';
require __DIR__ . '/lib/math.php';

use PharBz2\Greeter;
use PharBz2\Math;

$greeter = new Greeter('phar bzip2 world');
echo $greeter->salute(), "\n";

$math = new Math();
echo 'sum=', $math->sum([1, 2, 3, 4, 5]), "\n";
echo 'fact=', $math->factorial(6), "\n";
