-module(shortcircuit).

-export([test/0]).

f(X) when X > 1 -> X - 1;
f(X) -> X + 1.

folded() ->
    A = 3,
    B = lists:foldl(fun(X, Acc) -> (Acc * 3 + X) rem 1000 end, (A * A) rem 97, lists:seq(1, 3)),
    C = (13 - A) + (A * 9) rem 97,
    D = case (f(B) < B rem 10 andalso A + 14 >= f(14)) orelse 7 > f(C) of
        true -> B;
        false -> A rem 2
    end,
    {A, B, C, D, if B >= A -> 8; true -> A end}.

chained() ->
    A = 1,
    B = lists:sum([f(X) || X <- lists:seq(0, 6), X rem 2 =:= 1]),
    C = case ((A * B) rem 97 =/= B - A andalso f(A) =< (A * B) rem 97) orelse (B * A) rem 97 < (B * B) rem 97 of
        true -> f(A);
        false -> A - A
    end,
    D = case (3 + 0 > (C * C) rem 97 andalso A - C > 14) orelse f(A) > f(C) of
        true -> C - B;
        false -> A + A
    end,
    {A, B, C, D, case B =/= B - D of true -> (7 * D) rem 97; false -> C + A end}.

test() ->
    {folded(), chained()}.
