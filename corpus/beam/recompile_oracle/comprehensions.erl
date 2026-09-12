-module(comprehensions).

-export([test/0, cartesian/2, filtered/1, flatten_pairs/1, matrix/2, zip_sum/2]).

cartesian(Xs, Ys) ->
    [{X, Y} || X <- Xs, Y <- Ys].

filtered(Pairs) ->
    [{K, V} || {K, V} <- Pairs, is_atom(K), is_integer(V), V > 0].

flatten_pairs(Lists) ->
    [X || Sub <- Lists, X <- Sub].

matrix(N, M) ->
    [[I * M + J || J <- lists:seq(0, M - 1)] || I <- lists:seq(0, N - 1)].

zip_sum(As, Bs) ->
    [A + B || {A, B} <- lists:zip(As, Bs)].

test() ->
    {
        cartesian([1, 2], [a, b]),
        filtered([{a, 1}, {b, -2}, {c, 3}, {"x", 4}]),
        flatten_pairs([[1, 2], [3], [4, 5, 6]]),
        matrix(3, 3),
        zip_sum([1, 2, 3], [10, 20, 30])
    }.
