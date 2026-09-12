-module(guards).

-export([test/0, classify/1, clamp/1, either/1, typ/1, both/2]).

classify(X) when is_integer(X), X > 100 -> big;
classify(X) when is_integer(X), X > 0 -> small;
classify(X) when is_integer(X) -> nonpos;
classify(X) when is_float(X); is_atom(X) -> other;
classify(_) -> unknown.

clamp(X) when X < 0 -> 0;
clamp(X) when X > 255 -> 255;
clamp(X) -> X.

either(X) when X =:= a; X =:= b; X =:= c -> yes;
either(_) -> no.

typ(X) when is_list(X) -> list;
typ(X) when is_tuple(X) -> tuple;
typ(X) when is_map(X) -> map;
typ(X) when is_binary(X) -> binary;
typ(_) -> scalar.

both(A, B) when is_integer(A) andalso is_integer(B) andalso A + B > 10 -> big_sum;
both(_, _) -> other.

test() ->
    {
        classify(500),
        classify(50),
        classify(-3),
        classify(3.14),
        classify(hello),
        clamp(-5),
        clamp(300),
        clamp(128),
        either(b),
        either(z),
        typ([1, 2]),
        typ({1, 2}),
        typ(#{a => 1}),
        typ(<<1, 2>>),
        typ(42),
        both(7, 8),
        both(1, 2)
    }.
