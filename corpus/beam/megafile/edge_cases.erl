-module(edge_cases).

-behaviour(gen_server).

-export([
    main/0,
    start_link/0,
    start_link/1,
    stop/0,
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3,
    format_status/2,
    bit_syntax_decode/1,
    bit_syntax_encode/1,
    binary_comprehension/1,
    list_comprehension/1,
    list_comprehension_filtered/1,
    nested_comprehensions/2,
    pattern_match_args/1,
    pattern_match_args/2,
    guarded_dispatch/1,
    record_ops/0,
    map_ops/0,
    map_update/1,
    nested_map_match/1,
    tuple_pivot/1,
    string_ops/1,
    char_list_ops/1,
    fun_capture/1,
    higher_order/2,
    fold_examples/1,
    foldl_with_anon/1,
    spawn_demo/0,
    spawn_link_demo/0,
    spawn_monitor_demo/0,
    receive_demo/0,
    receive_after/1,
    send_pattern/2,
    selective_receive/0,
    ets_demo/0,
    dets_demo/0,
    try_demo/1,
    try_catch_of_after/1,
    exception_chain/1,
    error_with_stacktrace/0,
    process_dict_demo/0,
    hot_code_reload/0,
    apply_demo/3,
    catch_old_school/1,
    proc_lib_demo/0,
    registered_name_demo/0,
    monitor_node_demo/0,
    funlist_idx/2,
    multi_clause_recur/1,
    bifs_demo/0,
    big_int_demo/0,
    float_arith/0,
    boolean_short_circuit/2,
    if_demo/1,
    case_demo/1,
    cond_like/2,
    string_concat_three/3,
    deeply_nested/1,
    deep_pattern_destructure/1
]).

-record(state, {
    count = 0 :: non_neg_integer(),
    name :: atom() | binary() | undefined,
    pids = [] :: [pid()],
    meta = #{} :: #{atom() => term()},
    started_at :: erlang:timestamp() | undefined
}).

-record(person, {
    name :: binary(),
    age :: non_neg_integer(),
    email :: binary() | undefined,
    tags = [] :: [atom()]
}).

-record(point3, {x = 0.0 :: float(), y = 0.0 :: float(), z = 0.0 :: float()}).

-type kv() :: {atom(), term()}.
-type result(T) :: {ok, T} | {error, term()}.

-spec main() -> ok.
main() ->
    io:format("edge_cases main~n", []),
    _ = record_ops(),
    _ = map_ops(),
    _ = bit_syntax_decode(<<1, 2, 3, 4>>),
    _ = list_comprehension([1, 2, 3, 4, 5]),
    ok.

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [default], []).

start_link(InitArg) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [InitArg], []).

stop() ->
    gen_server:call(?MODULE, stop).

-spec init(list()) -> {ok, #state{}} | ignore.
init([_InitArg]) ->
    process_flag(trap_exit, true),
    State = #state{
        count = 0,
        name = my_module,
        pids = [],
        meta = #{started => true, version => 1},
        started_at = os:timestamp()
    },
    {ok, State};
init(_) ->
    ignore.

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call({add, N}, _From, State = #state{count = C}) when is_integer(N), N > 0 ->
    {reply, ok, State#state{count = C + N}};
handle_call(get_count, _From, State = #state{count = C}) ->
    {reply, {ok, C}, State};
handle_call({set_meta, K, V}, _From, State = #state{meta = M}) ->
    {reply, ok, State#state{meta = M#{K => V}}};
handle_call(get_state, _From, State) ->
    {reply, State, State}.

handle_cast({inc, N}, State = #state{count = C}) when is_integer(N) ->
    {noreply, State#state{count = C + N}};
handle_cast(reset, State) ->
    {noreply, State#state{count = 0, pids = []}};
handle_cast(_, State) ->
    {noreply, State}.

handle_info({'EXIT', From, Reason}, State) ->
    io:format("~p exited: ~p~n", [From, Reason]),
    {noreply, State};
handle_info({'DOWN', _Ref, process, _Pid, _Reason}, State) ->
    {noreply, State};
handle_info(timeout, State) ->
    {noreply, State};
handle_info(_, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

format_status(_Opt, [_PDict, State]) ->
    [{state, State}].

bit_syntax_decode(<<A:8, B:16/big, C:32/little, Rest/binary>>) ->
    {A, B, C, byte_size(Rest)};
bit_syntax_decode(<<Single:8>>) ->
    {single, Single};
bit_syntax_decode(<<>>) ->
    empty.

bit_syntax_encode({Tag, Payload}) when is_atom(Tag), is_binary(Payload) ->
    Len = byte_size(Payload),
    TagBin = atom_to_binary(Tag, utf8),
    TagLen = byte_size(TagBin),
    <<1:8, TagLen:8, TagBin/binary, Len:32/big-unsigned, Payload/binary>>.

binary_comprehension(Bin) when is_binary(Bin) ->
    << <<X:8>> || <<X:8>> <= Bin, X rem 2 =:= 0 >>.

list_comprehension(List) ->
    [X * 2 || X <- List, X > 0, X rem 2 =:= 1].

list_comprehension_filtered(Pairs) ->
    [{K, V} || {K, V} <- Pairs, is_atom(K), is_integer(V), V > 0].

nested_comprehensions(Xs, Ys) ->
    [{X, Y} || X <- Xs, Y <- Ys, X =/= Y].

pattern_match_args({ok, V}) -> {result, V};
pattern_match_args({error, R}) -> {fail, R};
pattern_match_args(_) -> unknown.

pattern_match_args([H | _], all_first) -> H;
pattern_match_args([_, X | _], second) -> X;
pattern_match_args(Atom, _) when is_atom(Atom) -> Atom.

guarded_dispatch(X) when is_integer(X), X > 1000 -> big;
guarded_dispatch(X) when is_integer(X), X > 0 -> small;
guarded_dispatch(X) when is_float(X) -> floaty;
guarded_dispatch(X) when is_binary(X), byte_size(X) > 0 -> bin;
guarded_dispatch(X) when is_list(X), length(X) > 0 -> nonempty_list;
guarded_dispatch(_) -> other.

record_ops() ->
    P0 = #person{name = <<"alice">>, age = 30},
    P1 = P0#person{age = 31, tags = [admin, beta]},
    Name = P1#person.name,
    Age = P1#person.age,
    #person{tags = Tags} = P1,
    {Name, Age, Tags}.

map_ops() ->
    M0 = #{one => 1, two => 2},
    M1 = M0#{three => 3, four => 4},
    M2 = maps:put(five, 5, M1),
    M3 = maps:remove(one, M2),
    Keys = lists:sort(maps:keys(M3)),
    Vals = lists:sort(maps:values(M3)),
    {Keys, Vals}.

map_update(M = #{count := C}) ->
    M#{count => C + 1};
map_update(M) ->
    M#{count => 1}.

nested_map_match(#{outer := #{inner := V}}) -> {ok, V};
nested_map_match(_) -> error.

tuple_pivot({A, B, C}) -> {C, B, A};
tuple_pivot({A, B, C, D}) -> {D, C, B, A};
tuple_pivot(T) -> T.

string_ops(S) ->
    Lower = string:lowercase(S),
    Upper = string:uppercase(S),
    Trimmed = string:trim(S),
    Split = string:split(S, " ", all),
    {Lower, Upper, Trimmed, Split}.

char_list_ops(L) when is_list(L) ->
    Sum = lists:sum([N || N <- L, is_integer(N)]),
    Sorted = lists:sort(L),
    Rev = lists:reverse(L),
    {Sum, Sorted, Rev}.

fun_capture(N) ->
    Plus = fun(X) -> X + N end,
    Mul = fun(X) -> X * N end,
    {Plus, Mul, Plus(10), Mul(10)}.

higher_order(F, List) when is_function(F, 1) ->
    [F(X) || X <- List].

fold_examples(List) ->
    Sum = lists:foldl(fun(X, Acc) -> Acc + X end, 0, List),
    Prod = lists:foldl(fun(X, Acc) -> Acc * X end, 1, List),
    Max = lists:foldl(fun(X, Acc) when X > Acc -> X; (_, Acc) -> Acc end, hd(List), tl(List)),
    {Sum, Prod, Max}.

foldl_with_anon(L) ->
    F = fun
        ({tag, V}, {Tags, Vals}) -> {[V | Tags], Vals};
        (V, {Tags, Vals}) when is_integer(V) -> {Tags, [V | Vals]};
        (_, Acc) -> Acc
    end,
    lists:foldl(F, {[], []}, L).

spawn_demo() ->
    Pid = spawn(fun() -> receive M -> io:format("got: ~p~n", [M]) end end),
    Pid ! hello,
    Pid.

spawn_link_demo() ->
    Pid = spawn_link(fun() -> receive stop -> ok end end),
    Pid.

spawn_monitor_demo() ->
    {Pid, Ref} = spawn_monitor(fun() -> ok end),
    receive
        {'DOWN', Ref, process, Pid, Reason} -> {done, Reason}
    after 1000 ->
        timeout
    end.

receive_demo() ->
    receive
        {greet, From} -> From ! {hi, self()}, ok;
        stop -> stopped
    end.

receive_after(Ms) ->
    receive
        Msg -> {got, Msg}
    after Ms ->
        timeout
    end.

send_pattern(Pid, Msg) ->
    Pid ! Msg,
    {sent, Pid, Msg}.

selective_receive() ->
    receive
        {priority, P} -> {p, P}
    after 0 ->
        receive
            Other -> {other, Other}
        after 100 ->
            none
        end
    end.

ets_demo() ->
    T = ets:new(demo_tab, [set, public]),
    true = ets:insert(T, {alpha, 1}),
    true = ets:insert(T, {beta, 2}),
    [{alpha, 1}] = ets:lookup(T, alpha),
    Size = ets:info(T, size),
    true = ets:delete(T),
    Size.

dets_demo() ->
    File = "demo.dets",
    {ok, _} = dets:open_file(demo_dets, [{file, File}, {type, set}]),
    ok = dets:insert(demo_dets, {key, 42}),
    [{key, 42}] = dets:lookup(demo_dets, key),
    ok = dets:close(demo_dets),
    file:delete(File),
    ok.

try_demo(X) ->
    try
        Y = 10 div X,
        {ok, Y}
    catch
        error:badarith -> {error, divzero};
        Class:Reason -> {error, {Class, Reason}}
    end.

try_catch_of_after(X) ->
    try compute(X) of
        N when is_integer(N), N > 0 -> {positive, N};
        N -> {nonpositive, N}
    catch
        throw:Tag -> {throw, Tag};
        error:Reason -> {err, Reason};
        exit:Reason -> {exit_, Reason}
    after
        ok
    end.

exception_chain(0) ->
    throw(zero);
exception_chain(N) when N < 0 ->
    error({negative, N});
exception_chain(N) ->
    exit({too_big, N}).

error_with_stacktrace() ->
    try
        error(forced)
    catch
        error:Reason:Stack -> {Reason, length(Stack) > 0}
    end.

process_dict_demo() ->
    put(my_key, 42),
    V = get(my_key),
    erase(my_key),
    V.

hot_code_reload() ->
    code:purge(?MODULE),
    code:load_file(?MODULE),
    ?MODULE:main().

apply_demo(M, F, A) ->
    apply(M, F, A).

catch_old_school(Op) ->
    case catch Op() of
        {'EXIT', R} -> {error, R};
        V -> {ok, V}
    end.

proc_lib_demo() ->
    Pid = proc_lib:spawn_link(fun() -> ok end),
    Pid.

registered_name_demo() ->
    Pid = spawn(fun() -> receive _ -> ok end end),
    true = register(named_demo, Pid),
    named_demo ! stop,
    unregister(named_demo),
    ok.

monitor_node_demo() ->
    erlang:monitor_node(node(), true),
    erlang:monitor_node(node(), false),
    ok.

funlist_idx([], _) -> none;
funlist_idx([F | _], 0) -> {ok, F};
funlist_idx([_ | T], N) when N > 0 -> funlist_idx(T, N - 1).

multi_clause_recur(0) -> base;
multi_clause_recur(1) -> one;
multi_clause_recur(N) when N rem 2 =:= 0 -> {even, multi_clause_recur(N - 2)};
multi_clause_recur(N) -> {odd, multi_clause_recur(N - 2)}.

bifs_demo() ->
    A = erlang:atom_to_list(hello),
    B = erlang:integer_to_binary(12345),
    C = erlang:list_to_tuple([1, 2, 3]),
    D = erlang:pid_to_list(self()),
    {A, B, C, D}.

big_int_demo() ->
    A = 999999999999999999999,
    B = A * A,
    {A, B, B > A}.

float_arith() ->
    A = 1.5 + 2.25,
    B = 3.14 * 2,
    C = math:pi() / 2.0,
    {A, B, C}.

boolean_short_circuit(X, Y) ->
    A = X andalso Y,
    B = X orelse Y,
    C = X and Y,
    D = X or Y,
    {A, B, C, D}.

if_demo(X) ->
    if
        X > 100 -> big;
        X > 10 -> medium;
        X > 0 -> small;
        true -> other
    end.

case_demo(X) ->
    case X of
        {ok, _} -> matched_ok;
        {error, _} -> matched_err;
        _ when is_atom(X) -> atom_branch;
        _ -> default
    end.

cond_like(A, B) ->
    case {A, B} of
        {true, _} -> first;
        {_, true} -> second;
        _ -> none
    end.

string_concat_three(A, B, C) ->
    <<A/binary, B/binary, C/binary>>.

deeply_nested(L) ->
    case L of
        [[[V | _] | _] | _] -> {deep, V};
        [[V | _] | _] -> {two, V};
        [V | _] -> {one, V};
        [] -> empty
    end.

deep_pattern_destructure({user, #{name := N, addr := #{city := City, zip := Zip}}}) ->
    {N, City, Zip};
deep_pattern_destructure(_) ->
    no_match.

compute(0) -> throw(zero);
compute(N) when N > 0 -> N * 2;
compute(N) -> -N.
