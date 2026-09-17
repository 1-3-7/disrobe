<?php

function values(array $items): Generator
{
    yield 'first';
    yield 'label' => 'keyed';
    yield from $items;
}

$items = range(1, 1);
foreach (values($items) as $value) {
    echo $value, PHP_EOL;
}
