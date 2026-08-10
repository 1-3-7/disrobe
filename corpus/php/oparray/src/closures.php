<?php

$double = static fn (int $value): int => $value * 2;
$offset = fn (int $value): int => $value + 3;

echo "closures\n";
