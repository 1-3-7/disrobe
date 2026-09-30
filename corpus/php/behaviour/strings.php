<?php

$name = 'World';
$user = ['first' => 'Ada', 'tags' => ['x', 'y']];
$obj = new stdClass();
$obj->title = 'Dr';
$obj->inner = new stdClass();
$obj->inner->city = 'Paris';
$n = 3;

echo "Hello $name!\n";
echo "Braced {$name}s and {$name}\n";
echo "Array $user[first] and {$user['first']} and {$user['tags'][1]}\n";
echo "Object $obj->title and {$obj->inner->city}\n";
echo "Math {$n}x, escaped \$name, tab\tend\n";
echo 'Single $name {$n}\n', "\n";

$heredoc = <<<TXT
    Name: $name
    Title: {$obj->title} {$user['first']}
      indented line with {$n}
    Literal \$dollar and "quotes"
    TXT;
echo $heredoc, "\n";

$nowdoc = <<<'RAW'
Raw $name {$n} \t
RAW;
echo $nowdoc, "\n";

$list = '';
for ($i = 0; $i < $n; $i++) {
    $list .= "item$i,";
}
echo rtrim($list, ','), "\n";

$fmt = sprintf("%05.1f|%-6s|%x|%b|%'*8s", 3.14159, 'ab', 255, 5, 'pad');
echo $fmt, "\n";
echo str_pad('7', 3, '0', STR_PAD_LEFT), ' ', strtoupper('mixed Case'), ' ', ucfirst('word'), "\n";
echo "concat " . $n . ' + ' . ($n + 1) . "\n";
echo "multi
line
string\n";
echo "unicode \u{1F600} and \x41\101\n";
$key = 'first';
echo "dynamic {$user[$key]}\n";
echo strlen("abc\0def"), "\n";
echo implode(',', str_split('abcdef', 2)), "\n";
$s = 'abc';
$s[1] = 'X';
echo $s, ' ', $s[0], ' ', $s[-1], "\n";
