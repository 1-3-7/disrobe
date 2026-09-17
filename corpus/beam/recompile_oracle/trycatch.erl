-module(trycatch).

-export([test/0, divide/2, classify_ex/1, of_after/1, chain/1, nested/1]).

divide(A, B) ->
    try A div B of
        R -> {ok, R}
    catch
        error:badarith -> {error, divzero}
    end.

classify_ex(F) ->
    try F() of
        V -> {value, V}
    catch
        throw:T -> {throw, T};
        error:E -> {error, E};
        exit:X -> {exit, X}
    end.

of_after(X) ->
    Ref = make_ref(),
    put(Ref, 0),
    try
        case X of
            neg when X < 0 -> throw(negative);
            _ -> X * 2
        end
    of
        N when N > 10 -> {big, N};
        N -> {ok, N}
    catch
        throw:R -> {caught, R}
    after
        erase(Ref)
    end.

chain(0) -> throw(zero);
chain(N) when N < 0 -> error({neg, N});
chain(N) -> N.

nested(X) ->
    try
        try chain(X) of
            V -> {inner_ok, V}
        catch
            error:R -> {inner_err, R}
        end
    catch
        throw:T -> {outer_throw, T}
    end.

test() ->
    {
        divide(10, 2),
        divide(10, 0),
        classify_ex(fun() -> 42 end),
        classify_ex(fun() -> throw(boom) end),
        classify_ex(fun() -> error(bad) end),
        of_after(3),
        of_after(10),
        of_after(-1),
        nested(5),
        nested(-2),
        nested(0)
    }.
