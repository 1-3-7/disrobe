<?php

function doubler(int $n): int
{
    return $n + $n;
}

$base = 21;
$twice = doubler($base);
echo $twice, "\n";
echo strlen("disrobe"), "\n";
echo ($twice > 40) ? "big" : "small", "\n";
