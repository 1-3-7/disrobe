use strict;
use warnings;

sub greet {
    my ($name) = @_;
    return "Hello, $name!";
}

sub add {
    my ($a, $b) = @_;
    return $a + $b;
}

sub area {
    my ($w, $h) = @_;
    return $w * $h;
}

my $msg = greet("disrobe");
print $msg;
my $sum = add(2, 3);
print $sum;
