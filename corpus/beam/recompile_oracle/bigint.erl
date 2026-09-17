-module(bigint).

-export([test/0, factorial/1, power/2, big_sum/1]).

factorial(0) -> 1;
factorial(N) when N > 0 -> N * factorial(N - 1).

power(_, 0) -> 1;
power(Base, Exp) when Exp > 0 -> Base * power(Base, Exp - 1).

big_sum(N) ->
    big_sum(N, 0).

big_sum(0, Acc) -> Acc;
big_sum(N, Acc) when N > 0 -> big_sum(N - 1, Acc + N * N * N).

test() ->
    {
        factorial(25),
        power(2, 100),
        power(3, 50),
        big_sum(1000),
        999999999999999999999 * 888888888888888888888,
        1 bsl 128
    }.
