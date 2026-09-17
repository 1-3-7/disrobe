-module(maps2).

-export([test/0, build/0, bump/1, match/1, nested/1, guarded/1, sized/1]).

build() ->
    M0 = #{a => 1, b => 2},
    M1 = M0#{c => 3},
    M2 = maps:put(d, 4, M1),
    maps:remove(a, M2).

bump(M = #{count := C}) ->
    M#{count := C + 1};
bump(M) ->
    M#{count => 1}.

match(#{x := X, y := Y}) ->
    X + Y.

nested(#{outer := #{inner := V}}) ->
    {ok, V};
nested(_) ->
    error.

guarded(M) when is_map(M), map_size(M) > 2 -> big;
guarded(M) when is_map(M) -> small;
guarded(_) -> not_map.

sized(M) ->
    map_size(M).

test() ->
    B = build(),
    {
        lists:sort(maps:to_list(B)),
        maps:get(count, bump(#{count => 41})),
        maps:get(count, bump(#{other => 1})),
        match(#{x => 3, y => 4}),
        nested(#{outer => #{inner => deep}}),
        nested(#{outer => flat}),
        guarded(#{a => 1, b => 2, c => 3}),
        guarded(#{a => 1}),
        guarded(notamap),
        sized(#{a => 1, b => 2, c => 3, d => 4})
    }.
