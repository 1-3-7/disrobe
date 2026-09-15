#!/usr/bin/perl
use strict;
use warnings;

sub greet {
    my ($name) = @_;
    return "Hello, " . $name . "!";
}

sub add {
    my ($a, $b) = @_;
    return $a + $b;
}

my $who = "disrobe";
print greet($who), "\n";
print "sum=", add(2, 40), "\n";
