-module(lists_ops).

-export([test/0, append/2, subtract/2, member/2, sumsq/1, evens/1, pairs/2, flatten1/1]).

append(A, B) -> A ++ B.
subtract(A, B) -> A -- B.
member(X, L) -> lists:member(X, L).
sumsq(L) -> lists:sum([X * X || X <- L]).
evens(L) -> [X || X <- L, X rem 2 =:= 0].
pairs(Xs, Ys) -> [{X, Y} || X <- Xs, Y <- Ys, X < Y].
flatten1(L) -> lists:append(L).

test() ->
    {
        append([1, 2, 3], [4, 5]),
        subtract([1, 2, 3, 2, 1], [2, 1]),
        member(3, [1, 2, 3, 4]),
        member(9, [1, 2, 3, 4]),
        sumsq([1, 2, 3, 4]),
        evens([1, 2, 3, 4, 5, 6]),
        pairs([1, 2, 3], [2, 3]),
        flatten1([[1, 2], [3], [4, 5, 6]]),
        lists:reverse([1, 2, 3]),
        lists:sort([3, 1, 2, 5, 4]),
        lists:map(fun(X) -> X + 1 end, [10, 20, 30]),
        lists:foldl(fun(X, A) -> X + A end, 0, [1, 2, 3, 4, 5])
    }.
