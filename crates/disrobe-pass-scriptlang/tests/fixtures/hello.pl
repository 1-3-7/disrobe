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

my $msg = greet("disrobe");
print "$msg\n";
print add(2, 3), "\n";
