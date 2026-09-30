<?php

interface Shape
{
    public function area(): float;
}

abstract class Base implements Shape
{
    public const UNIT = 'cm';
    protected static int $made = 0;

    public function __construct(protected string $name)
    {
        static::$made++;
        self::log("made $name");
    }

    public static function made(): int
    {
        return self::$made;
    }

    protected static function log(string $msg): void
    {
        echo "log: $msg\n";
    }

    public function describe(?string $prefix = null, int $precision = 2): string
    {
        $p = $prefix ?? 'shape';

        return sprintf('%s %s %.' . $precision . 'f%s', $p, $this->name, $this->area(), static::UNIT);
    }

    abstract public function scale(float $by): static;
}

class Rect extends Base
{
    public function __construct(private float $w, private float $h)
    {
        parent::__construct('rect');
    }

    public function area(): float
    {
        return $this->w * $this->h;
    }

    public function scale(float $by): static
    {
        return new static($this->w * $by, $this->h * $by);
    }
}

final class Circle extends Base
{
    public const UNIT = 'mm';

    public function __construct(public readonly float $r = 1.0)
    {
        parent::__construct('circle');
    }

    public function area(): float
    {
        return 3.0 * $this->r ** 2;
    }

    public function scale(float $by): static
    {
        return new self($this->r * $by);
    }

    public function __toString(): string
    {
        return "Circle({$this->r})";
    }
}

class Counter
{
    private array $items = [];
    public ?Counter $next = null;

    public function add(string $key, int $by = 1): self
    {
        $this->items[$key] = ($this->items[$key] ?? 0) + $by;

        return $this;
    }

    public function get(string $key): int
    {
        return $this->items[$key] ?? 0;
    }

    public function __get(string $name): string
    {
        return "magic:$name";
    }
}

$r = new Rect(2, 3.5);
$c = new Circle();
echo $r->describe(), "\n";
echo $c->describe('round', 3), "\n";
echo $r->scale(2)->describe(precision: 0), "\n";
echo Base::made(), " made\n";
echo Rect::UNIT, ' ', Circle::UNIT, "\n";
echo $c, "\n";
echo $c instanceof Shape ? 'shape' : 'not', "\n";

$k = new Counter();
$k->add('a')->add('a', 5)->add('b');
echo $k->get('a'), ' ', $k->get('b'), ' ', $k->get('z'), "\n";
echo $k->whatever, "\n";
echo $k->next?->get('a') ?? 'no next', "\n";
$k->next = new Counter();
echo $k->next?->add('q', 2)->get('q'), "\n";

try {
    $c->r = 5.0;
} catch (Error $e) {
    echo get_class($e), ': ', $e->getMessage(), "\n";
}

$class = 'Rect';
$dyn = new $class(1, 1);
echo get_class($dyn), ' ', $dyn->area(), "\n";
$method = 'area';
echo $dyn->$method(), "\n";
echo call_user_func([Base::class, 'made']), "\n";
