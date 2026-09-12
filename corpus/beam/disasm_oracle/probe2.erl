-module(probe2).
-export([
    safe_div/2, loop/1, build_bin/1, match_bin/1, comp/1, recform/0,
    bigm/0, floats/2, catcher/1, sel/1, mapbuild/2, send_msg/2, fapply/3,
    nested_try/1, recget/1
]).

-record(point, {x = 0, y = 0, label = none}).

safe_div(A, B) ->
    try A / B of
        R -> {ok, R}
    catch
        error:badarith -> {error, divzero}
    end.

loop(0) -> done;
loop(N) when N > 0 -> loop(N - 1).

build_bin(X) -> <<1, X:16, "tail">>.

match_bin(<<A:8, B:8, Rest/binary>>) -> {A, B, Rest};
match_bin(_) -> nomatch.

comp(L) -> [X * 2 || X <- L, X > 0].

recform() -> #point{x = 1, y = 2, label = origin}.

recget(P) -> P#point.x.

bigm() -> 123456789012345678901234567890.

floats(A, B) -> A * 2.0 + B / 3.0.

catcher(F) -> catch F().

sel(1) -> one;
sel(2) -> two;
sel(3) -> three;
sel(_) -> other.

mapbuild(K, V) -> #{K => V, fixed => 1}.

send_msg(Pid, Msg) -> Pid ! Msg.

fapply(M, F, A) -> apply(M, F, A).

nested_try(X) ->
    try
        try X() catch _:_ -> inner end
    catch
        _:_ -> outer
    end.
