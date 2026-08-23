<?php

function seed_box(int $start): object
{
    $box = new stdClass();
    $box->count = $start;
    $box->label = 'box';
    $box->rows = [];

    return $box;
}

function walk(object $box, int $by): object
{
    $box->count += $by;
    $box->count *= 2;
    $box->count -= 1;
    $box->count++;
    ++$box->count;
    $box->count--;
    --$box->count;

    $box->label .= ':walked';
    $box->label .= (string) $by;

    return $box;
}

function stash(object $box, string $key, int $amount): object
{
    $box->rows[$key] = $amount;
    $box->rows[$key] += 5;
    $box->rows[$key] *= 3;

    return $box;
}

function bump_slot(array $rows, int $index, int $by): array
{
    $rows[$index] += $by;
    $rows[$index]++;

    return $rows;
}

function build_list(int $seed): array
{
    return [$seed, $seed + 1, $seed + 2];
}

function join_flat(array $rows): string
{
    $out = '';
    foreach ($rows as $key => $row) {
        $out = $out . $key . '=' . $row . ',';
    }

    return $out;
}

$box = seed_box(4);
$box = walk($box, 3);
echo $box->count, "\n";
echo $box->label, "\n";

$box = stash($box, 'a', 2);
$box = stash($box, 'b', 10);
echo join_flat($box->rows), "\n";

echo join_flat(bump_slot(build_list(1), 1, 100)), "\n";

echo PHP_ROUND_HALF_UP, "\n";
echo DateTime::ATOM, "\n";
