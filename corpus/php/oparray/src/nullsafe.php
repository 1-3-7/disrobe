<?php

function read_one(?object $box): string
{
    return (string) ($box?->label ?? 'none');
}

function read_chain(?object $box): string
{
    return (string) ($box?->inner?->label ?? 'none');
}

function read_deep(?object $box): string
{
    return (string) ($box?->inner?->inner?->label ?? 'none');
}

function read_plain(?object $box): string
{
    return (string) ($box?->label ?? '');
}

function boxed(string $label): object
{
    $box = new stdClass();
    $box->label = $label;

    return $box;
}

function nested(string $outer, string $inner): object
{
    $box = boxed($outer);
    $box->inner = boxed($inner);

    return $box;
}

$flat = boxed('outer');
$two = nested('outer', 'inner');
$three = nested('outer', 'middle');
$three->inner->inner = boxed('deep');

echo read_one($flat), "\n";
echo read_one(null), "\n";
echo read_chain($two), "\n";
echo read_chain($flat), "\n";
echo read_chain(null), "\n";
echo read_deep($three), "\n";
echo read_deep($two), "\n";
echo read_deep(null), "\n";
echo read_plain($flat), "\n";
echo read_plain(null), "\n";
