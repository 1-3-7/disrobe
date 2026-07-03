<?php

$name = "greeting";
$$name = "hello";
echo $greeting, "\n";

$prop = "count";
$$prop = 5;
$$prop = $$prop + 3;
echo $count, "\n";

$first = "alpha";
$second = "beta";
$$first = 1;
$$second = 2;
echo $alpha + $beta, "\n";
