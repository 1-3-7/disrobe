-module(recv_timeouts).

-export([
    idle/0,
    prompt/0,
    literal_timeout/0,
    variable_timeout/1,
    infinite/0,
    timeout_after_skip/0,
    nested_timeout/0,
    drain/1,
    computed_timeout/1,
    called_timeout/0,
    shared_tail/1
]).

idle() ->
    receive
        never -> no
    after 0 ->
        idle
    end.

prompt() ->
    self() ! ready,
    receive
        ready -> got_ready
    after 1000 ->
        timed_out
    end.

literal_timeout() ->
    receive
        {reply, V} -> {got, V}
    after 25 ->
        {timed_out, 25}
    end.

variable_timeout(Ms) ->
    receive
        {reply, V} -> {got, V}
    after Ms ->
        {timed_out, Ms}
    end.

infinite() ->
    self() ! go,
    receive
        go -> went
    after infinity ->
        never
    end.

timeout_after_skip() ->
    self() ! {other, 1},
    receive
        {wanted, V} -> {got, V}
    after 25 ->
        still_waiting
    end.

nested_timeout() ->
    self() ! {outer, 7},
    receive
        {outer, A} ->
            receive
                {inner, B} -> {A, B}
            after 25 ->
                {A, none}
            end
    after 25 ->
        nothing
    end.

drain(Count) ->
    [self() ! {item, N} || N <- lists:seq(1, Count)],
    collect([]).

collect(Acc) ->
    receive
        {item, N} -> collect([N | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.

computed_timeout(Ms) ->
    receive
        {reply, V} -> {got, V}
    after Ms * 2 + 1 ->
        {timed_out, Ms * 2 + 1}
    end.

called_timeout() ->
    receive
        {reply, V} -> {got, V}
    after budget() ->
        timed_out
    end.

budget() ->
    12.

shared_tail(Tag) ->
    Result = receive
        {reply, V} -> V
    after 25 ->
        default
    end,
    {Tag, Result}.
