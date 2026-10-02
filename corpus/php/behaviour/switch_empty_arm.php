<?php
function classify(int $k, int $a): array
{
    $out = [];
    switch ((($k * $a) % 4 + 4) % 4) {
        case 0:
            $out[] = 'zero';
            for ($j = 0; $j < $a; $j++) {
                $out[] = $j;
            }
            break;
        case 1:
        case 2:
            break;
        default:
            $out[] = 'other';
            if ($a > 1) {
                $out[] = 'wide';
            }
    }
    $out[] = 'end';
    return $out;
}

function shared(int $k, int $a): array
{
    $out = [];
    switch ((($k - $a) % 4 + 4) % 4) {
        case 0:
            $out[] = 'zero';
            for ($j = 0; $j < $a; $j++) {
                $out[] = $j * 2;
            }
            break;
        case 1:
        case 2:
            break;
    }
    $out[] = 'end';
    return $out;
}

foreach ([[0, 2], [1, 1], [1, 2], [3, 1], [4, 3], [7, 5]] as [$k, $a]) {
    echo implode(' ', classify($k, $a)), ' | ', implode(' ', shared($k, $a)), "\n";
}
