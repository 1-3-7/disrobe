-module(bincomp).

-export([test/0, evens/1, doubled/1, bytes_to_list/1, filter_gt/2]).

evens(Bin) when is_binary(Bin) ->
    << <<X:8>> || <<X:8>> <= Bin, X rem 2 =:= 0 >>.

doubled(Bin) ->
    << <<(X * 2):8>> || <<X:8>> <= Bin >>.

bytes_to_list(Bin) ->
    [X || <<X:8>> <= Bin].

filter_gt(Bin, N) ->
    << <<X:8>> || <<X:8>> <= Bin, X > N >>.

test() ->
    {
        evens(<<1, 2, 3, 4, 5, 6>>),
        doubled(<<1, 2, 3, 10>>),
        bytes_to_list(<<9, 8, 7>>),
        filter_gt(<<1, 50, 100, 200, 3>>, 40)
    }.
