<?php
function run(array $items, int $k): array
{
    $out = [];
    foreach ($items as $item) {
        $out[] = $item * $k;
        break;
    }
    foreach ($items as $key => $item) {
        if ($item < $k) {
            continue;
        }
        $n = 0;
        do {
            $n++;
            $out[] = $key . ':' . $n;
        } while ($n < $k);
        break;
    }
    $out[] = count($items);
    return $out;
}

echo implode(' ', run([3, 1, 4], 2)), "\n";
echo implode(' ', run([1, 1, 5, 6], 3)), "\n";
echo implode(' ', run([], 1)), "\n";
echo implode(' ', run([0, 0], 4)), "\n";
