-module(boolean).

-export([test/0, all_true/2, any_true/2, xor2/2, not1/1, both_ways/2]).

all_true(A, B) -> A andalso B.

any_true(A, B) -> A orelse B.

xor2(A, B) -> A xor B.

not1(A) -> not A.

both_ways(A, B) ->
    {A and B, A or B, A andalso B, A orelse B}.

test() ->
    {
        all_true(true, true),
        all_true(true, false),
        all_true(false, undefined_would_shortcircuit) == false,
        any_true(false, true),
        any_true(true, would_shortcircuit) == true,
        xor2(true, false),
        xor2(true, true),
        not1(false),
        both_ways(true, false),
        both_ways(true, true),
        (1 < 2) andalso (3 > 2) andalso not (4 =:= 5)
    }.
