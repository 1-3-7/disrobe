-module(catchexpr).

-export([test/0, safe/1, guarded/1, val/1, trigger/1]).

safe(F) ->
    case catch F() of
        {'EXIT', R} -> {error, R};
        V -> {ok, V}
    end.

guarded(X) ->
    R = (catch trigger(X)),
    case R of
        {'EXIT', Reason} -> {exited, Reason};
        N -> {value, N}
    end.

trigger(0) -> exit(zero_divisor);
trigger(N) when N > 0 -> 10 div N.

val(X) ->
    catch X * 2.

test() ->
    {
        safe(fun() -> 21 * 2 end),
        safe(fun() -> throw(boom) end),
        safe(fun() -> exit(kaboom) end),
        guarded(5),
        guarded(0),
        val(21)
    }.
