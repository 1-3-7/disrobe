use strict;
use warnings;

sub bare_if {
    my ($flag) = @_;
    if ($flag) {
        return 1;
    }
    return 0;
}

sub use_unless {
    my ($n) = @_;
    unless ($n == 0) {
        return $n;
    }
    return 99;
}

bare_if(1);
use_unless(5);
