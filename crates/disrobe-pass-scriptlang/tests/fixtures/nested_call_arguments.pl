use strict;
use warnings;

sub inner {
    my ($input) = @_;
    return $input;
}

sub outer {
    my ($first, $second, $third) = @_;
    return $first;
}

my $value = outer(1, inner(7), 2);
print $value;
