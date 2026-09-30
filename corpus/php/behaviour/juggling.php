<?php

$pairs = [
    [0, '0'],
    [0, ''],
    [0, 'a'],
    ['1', '01'],
    ['10', '1e1'],
    [100, '1e2'],
    [null, false],
    [null, 0],
    [[], false],
    ['abc', 'ABC'],
    [1.0, 1],
    ['1.5', 1.5],
    [' 1', 1],
    ['1 ', 1],
    [true, 'false'],
    [-0.0, 0],
    ['null', null],
];

foreach ($pairs as [$l, $r]) {
    echo str_pad(var_export($l, true), 6), ' ',
        str_pad(var_export($r, true), 7), ' ',
        '== ', var_export($l == $r, true), ' ',
        '=== ', var_export($l === $r, true), ' ',
        '<=> ', $l <=> $r, ' ',
        '< ', var_export($l < $r, true), "\n";
}

var_dump('5' + '5', '5' . '5', '1.5' + 1, 7 / 2, 6 / 2, 7 % 3, -7 % 3, 2 ** 10, 2 ** -1, 2 ** 63);
var_dump(PHP_INT_MAX + 1, intdiv(-7, 2), fmod(7.5, 2), 0.1 + 0.2 == 0.3, abs(0.1 + 0.2 - 0.3) < PHP_FLOAT_EPSILON);
var_dump((int) '12abc', (float) '3.5e2x', (bool) '0', (bool) '0.0', (bool) [], (bool) [0], (string) false, (string) 1.0);
var_dump(intval('0x1A', 16), intval('012', 0), octdec('17'), bindec('101'), (int) 9.99, (int) -9.99);
var_dump(1 <=> 2, 'b' <=> 'a', [1, 2] <=> [1, 3], null ?? 0);
var_dump('abc' == 0, '1' == '1.0', '10' == '10.0', 'abc' < 'abd', '9' < '10', '9a' < '10a');
var_dump(1 + 1.5, 10 - 0.5, 3 * '3', '2' * '2.5', -'5', +'-3');
var_dump(0.1 + 0.7, 1e100, 1.5e-7, -0.0, 1 / 3, round(2.5), round(-2.5), floor(-1.5), 1e15, 1e16);
var_dump(is_numeric('1e5'), is_numeric(' 5'), is_numeric('5 '), is_numeric('0x1A'), is_numeric('.5'));
var_dump(max('apple', 'banana'), max([1, 2], [1, 3]), max(1, '2', 3.5), min(null, -1));
var_dump(7 <=> 7.0, 'Z' < 'a', '' < 'a', null < -1, true > 10);
$i = PHP_INT_MAX;
$i++;
var_dump($i);
$s = 'z';
$s++;
var_dump($s);
$s = 'Az';
$s++;
var_dump($s);
var_dump(0b101 | 0x10, 6 & 3, 6 ^ 3, ~5, 1 << 3, -16 >> 2, '12' & '6', 'a' . 1 + 2);
