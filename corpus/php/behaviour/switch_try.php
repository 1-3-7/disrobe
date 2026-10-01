<?php
function run(int $x): array
{
    $out = [];
    switch ($x % 3) {
        case 0:
            try {
                $out[] = intdiv(10, $x);
            } catch (DivisionByZeroError $error) {
                $out[] = 'zero';
            }
            break;
        case 1:
            try {
                $out[] = 7 % ($x - 1);
            } catch (DivisionByZeroError $error) {
                $out[] = 'zero';
            } finally {
                $out[] = 'finally';
            }
            break;
        default:
            $out[] = 'default';
    }
    $out[] = 'after';
    return $out;
}

foreach ([0, 1, 2, 3, 4, 5, 7] as $value) {
    echo implode(',', run($value)), "\n";
}
