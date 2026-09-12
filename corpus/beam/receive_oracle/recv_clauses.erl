-module(recv_clauses).

-export([
    atoms/1,
    tagged/1,
    selective/0,
    guarded/1,
    catch_all/1,
    nested/0,
    sequential/0,
    server_roundtrip/0,
    arith_guard/1,
    accessor_guard/1
]).

atoms(Which) ->
    self() ! Which,
    receive
        red -> {picked, 1};
        green -> {picked, 2};
        blue -> {picked, 3}
    end.

tagged(N) ->
    self() ! {add, N},
    receive
        {add, V} -> {sum, V + 1};
        {sub, V} -> {diff, V - 1};
        reset -> zero
    end.

selective() ->
    self() ! {first, 1},
    self() ! {second, 2},
    self() ! {third, 3},
    A = receive {third, X} -> X end,
    B = receive {first, Y} -> Y end,
    C = receive {second, Z} -> Z end,
    {A, B, C}.

guarded(N) ->
    self() ! {n, N},
    receive
        {n, V} when V > 10 -> {big, V};
        {n, V} when V > 0 -> {small, V};
        {n, V} -> {nonpos, V}
    end.

catch_all(Term) ->
    self() ! Term,
    receive
        stop -> stopped;
        Other -> {other, Other}
    end.

nested() ->
    self() ! {outer, 1},
    self() ! {inner, 2},
    receive
        {outer, A} ->
            receive
                {inner, B} -> {A, B}
            end
    end.

sequential() ->
    self() ! a,
    self() ! b,
    First = receive
        a -> first_a;
        b -> first_b
    end,
    Second = receive
        a -> second_a;
        b -> second_b
    end,
    {First, Second}.

arith_guard(Term) ->
    self() ! Term,
    receive
        M when M + 1 > 3 -> big_enough;
        _ -> too_small
    end.

accessor_guard(Term) ->
    self() ! Term,
    receive
        M when hd(M) =:= 1 -> head_one;
        M when M =:= plain -> plain_atom
    end.

server(Acc) ->
    receive
        {add, N} -> server(Acc + N);
        {get, From} -> From ! {sum, Acc}, server(Acc);
        stop -> Acc
    end.

server_roundtrip() ->
    Pid = spawn(fun() -> server(0) end),
    Pid ! {add, 3},
    Pid ! {add, 4},
    Pid ! {get, self()},
    Sum = receive
        {sum, S} -> S
    end,
    Pid ! stop,
    Sum.
