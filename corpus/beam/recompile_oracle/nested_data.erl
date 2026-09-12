-module(nested_data).

-export([test/0, get_deep/1, transform/1, build/0, count_leaves/1]).

get_deep(#{level1 := #{level2 := [_, {tagged, V} | _]}}) ->
    {found, V};
get_deep(_) ->
    not_found.

transform({node, L, R}) ->
    {node, transform(L), transform(R)};
transform({leaf, V}) ->
    {leaf, V * 10}.

build() ->
    #{
        users => [
            #{name => alice, roles => [admin, user]},
            #{name => bob, roles => [user]}
        ],
        config => #{retries => 3, timeout => 5000}
    }.

count_leaves({leaf, _}) -> 1;
count_leaves({node, L, R}) -> count_leaves(L) + count_leaves(R);
count_leaves([]) -> 0;
count_leaves([H | T]) -> count_leaves(H) + count_leaves(T);
count_leaves(_) -> 0.

test() ->
    Tree = {node, {node, {leaf, 1}, {leaf, 2}}, {leaf, 3}},
    M = build(),
    {
        get_deep(#{level1 => #{level2 => [a, {tagged, deep_val}, c]}}),
        get_deep(#{other => 1}),
        transform(Tree),
        count_leaves(Tree),
        count_leaves([{leaf, 1}, {leaf, 2}, {node, {leaf, 3}, {leaf, 4}}]),
        maps:get(retries, maps:get(config, M)),
        length(maps:get(users, M))
    }.
