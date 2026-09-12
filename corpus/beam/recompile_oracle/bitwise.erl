-module(bitwise).

-export([test/0, band2/2, bor2/2, bxor2/2, bnot1/1, shl/2, shr/2, mask/1]).

band2(A, B) -> A band B.
bor2(A, B) -> A bor B.
bxor2(A, B) -> A bxor B.
bnot1(A) -> bnot A.
shl(A, N) -> A bsl N.
shr(A, N) -> A bsr N.
mask(A) -> (A band 16#FF) bor 16#100.

test() ->
    {
        band2(12, 10),
        bor2(12, 10),
        bxor2(12, 10),
        bnot1(0),
        bnot1(255),
        shl(1, 8),
        shr(1024, 3),
        mask(16#1234),
        (5 bxor 3) band 6 bor (1 bsl 4)
    }.
