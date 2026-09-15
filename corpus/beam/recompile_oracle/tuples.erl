-module(tuples).

-export([test/0, swap/1, nth/2, rebuild/1, tag/2, unpack/1]).

swap({A, B}) -> {B, A};
swap({A, B, C}) -> {C, B, A}.

nth(T, N) -> element(N, T).

rebuild(T) ->
    setelement(1, T, replaced).

tag(Tag, Val) -> {Tag, Val, erlang:tuple_size({Tag, Val})}.

unpack({ok, {X, Y}, Z}) -> X + Y + Z;
unpack(_) -> none.

test() ->
    {
        swap({1, 2}),
        swap({1, 2, 3}),
        nth({a, b, c, d}, 3),
        rebuild({first, second, third}),
        tag(mytag, 99),
        unpack({ok, {3, 4}, 5}),
        unpack(other),
        list_to_tuple([10, 20, 30]),
        tuple_to_list({x, y, z})
    }.
