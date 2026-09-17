<?php

function long_table($value) {
    switch ($value) {
        case 1:
        case 2:
            echo "low\n";
            break;
        case 4:
            echo "four\n";
            break;
        case 7:
            echo "seven\n";
        case 9:
            echo "nine\n";
            break;
        case -12:
            echo "negative-twelve\n";
            break;
        default:
            echo "other\n";
    }
    echo "long-done\n";
}

function string_table($value) {
    switch ($value) {
        case "one":
        case "two":
            echo "small\n";
            break;
        case "four":
            echo "four\n";
            break;
        case "seven":
            echo "seven\n";
            break;
        case "nine":
            echo "nine\n";
            break;
        case "twelve":
            echo "twelve\n";
            break;
        default:
            echo "other\n";
    }
    echo "string-done\n";
}

long_table(1);
long_table(7);
long_table(-12);
long_table(3);
string_table("two");
string_table("seven");
string_table("missing");
