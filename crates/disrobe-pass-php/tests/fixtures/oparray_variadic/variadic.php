<?php

function collect_args($first, ...$rest)
{
    return json_encode([$first, $rest], JSON_THROW_ON_ERROR);
}

function mark($label, $value)
{
    echo $label;
    return $value;
}

$spread = json_decode(
    '{"0":"one","bonus":"three"}',
    true,
    flags: JSON_THROW_ON_ERROR,
);
echo collect_args(...$spread), "\n";
echo collect_args(
    bonus: mark('B', 'named'),
    first: mark('F', 'zero'),
), "\n";
