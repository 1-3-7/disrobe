-module(probe).
-export([add/2, fac/1, greet/1, classify/1, sumlist/1, mapkv/1, tup/0]).

add(A, B) -> A + B.

fac(0) -> 1;
fac(N) when N > 0 -> N * fac(N - 1).

greet(Name) -> "hello " ++ Name.

classify(X) when is_integer(X) -> integer;
classify(X) when is_atom(X) -> atom;
classify(_) -> other.

sumlist(L) -> lists:foldl(fun(X, Acc) -> X + Acc end, 0, L).

mapkv(M) -> maps:get(key, M, default).

tup() -> {ok, 42, "str"}.
