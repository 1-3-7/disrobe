-module(joins).
-export([test/0]).

log(Tag, Value) ->
    put(log, [{Tag, Value} | case get(log) of undefined -> []; Old -> Old end]),
    Value.

drain() ->
    case erase(log) of
        undefined -> [];
        Entries -> lists:reverse(Entries)
    end.

chain(X) ->
    A = case X > 1 andalso X < 10 of true -> log(a, 1); false -> 2 end,
    B = case X > 2 orelse X < -5 of true -> 3; false -> log(b, 4) end,
    C = case X > 3 andalso X < 8 of true -> 5; false -> 6 end,
    D = case X < 0 orelse X > 6 of true -> log(d, 7); false -> 8 end,
    E = case X =/= 5 andalso X =/= 6 of true -> 9; false -> 10 end,
    F = case X rem 2 =:= 0 orelse X > 4 of true -> 11; false -> log(f, 12) end,
    log(sum, A + B + C + D + E + F).

hoisted(X) ->
    W = log(w, X * 2),
    case X > 3 of
        true -> W;
        false -> 0
    end.

ordered(X) ->
    R = log(r, X),
    S = log(s, X + 1),
    {S, R}.

snapshot(X) ->
    Old = get(log),
    log(o, X),
    Old =:= get(log).

unused_division(X, Y) ->
    try
        _ = X div Y,
        log(division, ok)
    catch
        error:badarith -> log(division, raised)
    end.

joined_try(X, Y) ->
    Q = try X div Y catch error:badarith -> log(q, infinite) end,
    log(after_try, Q),
    Q.

pair(X) ->
    {P, Q} = case X of
        1 -> {log(p, one), 10};
        2 -> {two, log(q, 20)};
        _ -> {other, 30}
    end,
    {Q, P}.

caught(Y) ->
    X = (catch case Y of a -> log(c, a); b -> 2 end),
    {is_tuple(X), log(after_catch, Y)}.

scoped(X) ->
    V = try 10 div X catch error:badarith -> 0 end,
    try 1 div (V - 2) catch error:badarith -> log(scope, V) end.

test() ->
    Results = [{X, chain(X), hoisted(X), ordered(X), snapshot(X),
                unused_division(X, X - 3), joined_try(10, X - 4), pair(X rem 4),
                scoped(X)}
               || X <- lists:seq(-7, 12)],
    Caught = [caught(Y) || Y <- [a, b, c]],
    {Results, Caught, drain()}.
