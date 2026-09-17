<?php

$one = 1;
$two = 2;
$three = 3;

function grouped($kind, $one, $two, $three) {
    switch ($kind) {
        case $one:
        case $two:
            echo "low:", $kind, "\n";
        case $three:
            echo "seen:", $kind, "\n";
            break;
        case $one + 3:
            echo "computed:", $kind, "\n";
            break;
        default:
            echo "other:", $kind, "\n";
    }
    echo "done:", $kind, "\n";
}

grouped(1, $one, $two, $three);
grouped(2, $one, $two, $three);
grouped(3, $one, $two, $three);
grouped(4, $one, $two, $three);

switch ($two) {
    case $one:
        echo "first\n";
        break;
    default:
        echo "middle-default\n";
        break;
    case $two:
        echo "second\n";
        break;
}

switch ($three + 0) {
    case $one:
        echo "temp-first\n";
        break;
    case $three:
        echo "temp-third\n";
        break;
}

switch ($three) {
    case $one + 2:
        echo "computed-first\n";
        break;
    default:
        echo "computed-first-default\n";
}
