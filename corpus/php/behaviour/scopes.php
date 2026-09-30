<?php

$config = ['mode' => 'fast', 'level' => 3];
$counter = 10;

function bump_global(int $by): int
{
    global $counter;
    $counter += $by;

    return $counter;
}

function read_globals(): string
{
    return $GLOBALS['config']['mode'] . '/' . $GLOBALS['counter'];
}

function dynamic_names(): string
{
    $first = 'alpha';
    $second = 'beta';
    $name = 'first';
    $out = $$name;
    $name = 'second';
    $$name = 'gamma';

    return $out . ',' . $second;
}

trait Greets
{
    public function greet(): string
    {
        return 'hello from ' . static::class . ' ' . $this->label();
    }
}

interface Labelled
{
    public const PREFIX = 'L:';

    public function label(): string;
}

class Widget implements Labelled
{
    use Greets;

    private array $calls = [];

    public function __construct(private string $name)
    {
    }

    public function label(): string
    {
        return self::PREFIX . $this->name;
    }

    public function __call(string $method, array $args): string
    {
        $this->calls[] = $method;

        return $method . '(' . implode(',', $args) . ')';
    }

    public static function __callStatic(string $method, array $args): string
    {
        return 'static ' . $method . ':' . count($args);
    }

    public function __invoke(int $x): int
    {
        return $x * 2;
    }

    public function __clone(): void
    {
        $this->name .= '-copy';
    }

    public function calls(): int
    {
        return count($this->calls);
    }

    public function isSame(object $other): bool
    {
        return $other instanceof self;
    }
}

function describe_color(string $color): string
{
    switch ($color) {
        case 'red':
            return 'warm';
        case 'blue':
        case 'green':
            return 'cool';
        case 'black':
            $out = 'dark';
            break;
        default:
            $out = 'unknown';
    }

    return $out;
}

if (!function_exists('late_helper')) {
    function late_helper(): string
    {
        return 'declared at runtime';
    }
}

echo bump_global(5), ' ', bump_global(1), ' ', $counter, "\n";
echo read_globals(), "\n";
echo dynamic_names(), "\n";

$w = new Widget('box');
echo $w->greet(), "\n";
echo $w->resize(3, 4), ' ', $w->paint('red'), ' ', $w->calls(), "\n";
echo Widget::build(1, 2, 3), "\n";
echo $w(21), "\n";
$copy = clone $w;
echo $copy->label(), ' ', $w->label(), "\n";
echo var_export($w->isSame($copy), true), ' ', var_export($w->isSame(new stdClass()), true), "\n";
echo Labelled::PREFIX, Widget::PREFIX, "\n";
$label = $w->label(...);
echo $label(), "\n";

foreach (['red', 'green', 'black', 'pink'] as $color) {
    echo describe_color($color), ' ';
}
echo "\n";
echo late_helper(), "\n";

$data = ['a' => ['b' => ['c' => 1]], 'list' => [1, 2, 3]];
unset($data['a']['b']['c'], $data['list'][1]);
echo json_encode($data), ' ', isset($data['a']['b']) ? 'b stays' : 'b gone', ' ', empty($data['a']['b']) ? 'empty' : 'full', "\n";
$obj = (object) ['x' => 1, 'y' => 2];
unset($obj->x);
echo json_encode($obj), ' ', json_encode((array) $obj), "\n";
print "printed\n";
$printed = print '';
echo $printed, "\n";

$i = 0;
$log = '';
while ($i < 10 && ($i % 7 !== 6 || $i < 3)) {
    $log .= $i;
    $i++;
}
echo $log, "\n";

$n = 0;
retry:
$n++;
if ($n < 3) {
    goto retry;
}
echo "retried $n\n";
