<?php
function run(int $n, int $m): array
{
    $out = [];
    $i = 0;
    while ($i < $n) {
        $i++;
        switch (($i * $m) % 4) {
            case 0:
                if ($i > 2) {
                    $out[] = 'big';
                } else {
                    $out[] = 'small';
                }
                break;
            case 1:
            case 2:
                $out[] = 'mid';
                break;
        }
    }
    return $out;
}

function nested(int $k, int $m): array
{
    $out = [];
    switch ($k % 4) {
        case 0:
            $out[] = 'zero';
            break;
        case 1:
        case 2:
            $out[] = 'low';
            break;
        default:
            $out[] = 'other';
            switch (($k * $m) % 3) {
                case 0:
                    $out[] = 'inner zero';
                    break;
                case 1:
                    $out[] = 'inner one';
                    break;
            }
    }
    $out[] = 'end';
    return $out;
}

echo implode(' ', run(6, 1)), "\n";
echo implode(' ', run(5, 2)), "\n";
echo implode(' ', run(3, 4)), "\n";
foreach ([0, 1, 3, 7, 11] as $k) {
    echo implode(' ', nested($k, 2)), "\n";
}
