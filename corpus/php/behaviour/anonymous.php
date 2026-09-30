<?php

interface Shape
{
    public function area(): float;
}

function square(float $side): Shape
{
    return new class ($side) implements Shape {
        public function __construct(private float $side)
        {
        }

        public function area(): float
        {
            return $this->side * $this->side;
        }
    };
}

function total(Shape ...$shapes): float
{
    $sum = 0.0;
    foreach ($shapes as $shape) {
        $sum += $shape->area();
    }

    return $sum;
}

echo total(square(2), square(3)), "\n";
echo square(1.5)->area(), "\n";
