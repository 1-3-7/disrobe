-module(recursion).

-export([test/0, fac/1, fib/1, sum_acc/2, is_even/1, is_odd/1, range/2, ackermann/2]).

fac(0) -> 1;
fac(N) when N > 0 -> N * fac(N - 1).

fib(0) -> 0;
fib(1) -> 1;
fib(N) when N > 1 -> fib(N - 1) + fib(N - 2).

sum_acc([], Acc) -> Acc;
sum_acc([H | T], Acc) -> sum_acc(T, Acc + H).

is_even(0) -> true;
is_even(N) when N > 0 -> is_odd(N - 1).

is_odd(0) -> false;
is_odd(N) when N > 0 -> is_even(N - 1).

range(Lo, Hi) when Lo > Hi -> [];
range(Lo, Hi) -> [Lo | range(Lo + 1, Hi)].

ackermann(0, N) -> N + 1;
ackermann(M, 0) when M > 0 -> ackermann(M - 1, 1);
ackermann(M, N) when M > 0, N > 0 -> ackermann(M - 1, ackermann(M, N - 1)).

test() ->
    {
        fac(6),
        fib(10),
        sum_acc([1, 2, 3, 4, 5, 6], 0),
        is_even(10),
        is_odd(7),
        range(1, 8),
        ackermann(2, 3)
    }.
