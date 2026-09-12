use strict;
use warnings;

sub inner {
    my ($input) = @_;
    return $input;
}

sub outer {
    my ($input) = @_;
    return $input;
}

outer(inner(7));
