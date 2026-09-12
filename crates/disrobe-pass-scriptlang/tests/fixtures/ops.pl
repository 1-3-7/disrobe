use strict;
use warnings;

sub cmps {
    my ($a, $b) = @_;
    my $p = $a == $b;
    my $q = $a < $b;
    my $r = $a >= $b;
    my $s = $a . $b;
    my $u = $a % $b;
    return $p;
}

sub assigns {
    my ($x) = @_;
    my $y = $x * 2;
    $y = $y - 1;
    my $z = $x;
    return $z;
}

my $g = cmps(1, 2);
print $g;
