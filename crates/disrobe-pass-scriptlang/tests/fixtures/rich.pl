use strict;
use warnings;

sub classify {
    my ($n) = @_;
    if ($n > 10) {
        return "big";
    }
    return "small";
}

sub total {
    my ($a, $b, $c) = @_;
    my $sum = $a + $b;
    $sum = $sum + $c;
    return $sum;
}

sub loop_sum {
    my ($limit) = @_;
    my $acc = 0;
    while ($acc < $limit) {
        $acc = $acc + 1;
    }
    return $acc;
}

my $x = classify(20);
print "$x\n";
my $t = total(1, 2, 3);
print "$t\n";
my $count = 4;
print "$count\n";
