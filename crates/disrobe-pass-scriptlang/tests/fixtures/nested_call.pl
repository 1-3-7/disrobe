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

my $value = outer(inner(7));
print $value;
