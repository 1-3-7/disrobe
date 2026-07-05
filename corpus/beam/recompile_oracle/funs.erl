-module(funs).

-export([test/0, adder/1, compose/2, apply_all/2, named_sum/1, multi/1, capture2/2]).

adder(N) ->
    fun(X) -> X + N end.

compose(F, G) ->
    fun(X) -> F(G(X)) end.

apply_all(Fs, X) ->
    [F(X) || F <- Fs].

named_sum(L) ->
    Sum = fun Rec([]) -> 0; Rec([H | T]) -> H + Rec(T) end,
    Sum(L).

multi(X) ->
    F = fun
        (0) -> zero;
        (N) when N > 0 -> pos;
        (_) -> neg
    end,
    F(X).

capture2(A, B) ->
    F = fun(X) -> X * A + B end,
    {F(0), F(1), F(10)}.

test() ->
    Add5 = adder(5),
    Inc = adder(1),
    Double = fun(X) -> X * 2 end,
    IncThenDouble = compose(Double, Inc),
    {
        Add5(10),
        apply_all([Add5, Inc, Double], 100),
        named_sum([1, 2, 3, 4, 5]),
        multi(0),
        multi(7),
        multi(-3),
        capture2(3, 2),
        IncThenDouble(4)
    }.
