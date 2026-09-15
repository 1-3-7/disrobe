<?php

namespace PharBz2;

final class Math
{
    public function sum(array $values): int
    {
        return array_sum($values);
    }

    public function factorial(int $n): int
    {
        $acc = 1;
        for ($i = 2; $i <= $n; $i++) {
            $acc *= $i;
        }

        return $acc;
    }
}
