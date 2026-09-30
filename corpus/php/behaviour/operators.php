<?php

class Node
{
    public static int $made = 0;
    public ?Node $next = null;
    public array $tags = [];
    public int $hits = 0;

    public function __construct(public string $name)
    {
        self::$made++;
    }

    public function child(): ?Node
    {
        return $this->next;
    }

    public function link(Node $next): static
    {
        $this->next = $next;

        return $this;
    }
}

$root = (new Node('root'))->link((new Node('mid'))->link(new Node('leaf')));
echo $root->child()?->child()?->name, ' ', var_export($root->child()?->child()?->child()?->name, true), "\n";
echo $root?->next?->next?->next?->name ?? 'end', "\n";

$x = 7;
$x += 3;
$x -= 1;
$x *= 4;
$x /= 3;
$x %= 5;
$x **= 3;
$x |= 16;
$x &= 0x1F;
$x ^= 3;
$x <<= 2;
$x >>= 1;
echo $x, "\n";
$s = 'ab';
$s .= 'cd';
echo $s, "\n";

$arr = ['n' => 1, 'list' => [5]];
$arr['n']++;
++$arr['n'];
$arr['list'][0]--;
$arr['new'] ??= 'fresh';
$arr['list'][] = 9;
echo json_encode($arr), "\n";

$root->hits++;
++$root->hits;
$root->tags[] = 'first';
$root->tags['k'] = 'v';
Node::$made += 10;
Node::$made--;
echo $root->hits, ' ', json_encode($root->tags), ' ', Node::$made, "\n";

$post = $x++;
$pre = ++$x;
echo "$post $pre $x\n";

$version = 'a9';
$version++;
$z = 'Zz';
$z++;
echo "$version $z\n";

$a = 1;
$b = null;
echo var_export(isset($a, $b), true), ' ', var_export(isset($a, $root->name), true), "\n";
echo var_export(empty($root->tags), true), ' ', var_export(empty($root->child()?->tags), true), "\n";

$class = 'Node';
echo var_export($root instanceof $class, true), ' ', var_export($root instanceof Countable, true), "\n";
echo 5 <=> 3, 3 <=> 5, 4 <=> 4, "\n";
echo intdiv(17, 5), ' ', 17 % 5, ' ', -17 % 5, ' ', fmod(-17, 5), ' ', 2 ** 0.5 > 1.41 ? 'root' : 'no', "\n";
echo !empty($arr) && !isset($arr['missing']) ? 'guarded' : 'open', "\n";
echo (int) '42abc' + (float) '0.5', ' ', 10 / 4, ' ', 10 <=> 10.0, "\n";
$flags = 0;
foreach ([1, 4, 16] as $bit) {
    $flags |= $bit;
}
echo $flags, ' ', $flags & 4 ? 'has4' : 'no4', ' ', ~$flags & 0xFF, "\n";
$text = null;
echo $text?->length ?? 'null text', "\n";
echo str_repeat('=', 3) . PHP_EOL;
