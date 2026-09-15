-module(arith).

-export([test/0, add/2, sub/2, mul/2, idiv/2, imod/2, neg/1, mixed/2, poly/3]).

add(A, B) -> A + B.
sub(A, B) -> A - B.
mul(A, B) -> A * B.
idiv(A, B) -> A div B.
imod(A, B) -> A rem B.
neg(A) -> -A.
mixed(A, B) -> A * 1.5 + B / 2.
poly(A, B, C) -> A * A + B * A + C.

test() ->
    {
        add(3, 4),
        sub(10, 3),
        mul(6, 7),
        idiv(17, 5),
        imod(17, 5),
        idiv(-17, 5),
        imod(-17, 5),
        neg(9),
        neg(-4),
        mixed(4, 10),
        poly(2, 3, 5),
        (1 + 2) * 3 - 4 div 2 + 7 rem 3
    }.
