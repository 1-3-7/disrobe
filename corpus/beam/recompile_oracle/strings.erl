-module(strings).

-export([test/0, concat/2, upcase/1, count_char/2, reverse_str/1, join/2, to_bin/1]).

concat(A, B) -> A ++ B.

upcase(S) -> string:uppercase(S).

count_char(C, S) ->
    length([X || X <- S, X =:= C]).

reverse_str(S) -> lists:reverse(S).

join([], _) -> "";
join([H], _) -> H;
join([H | T], Sep) -> H ++ Sep ++ join(T, Sep).

to_bin(S) -> list_to_binary(S).

test() ->
    {
        concat("foo", "bar"),
        upcase("hello"),
        count_char($l, "hello world"),
        reverse_str("abcde"),
        join(["a", "b", "c"], "-"),
        to_bin("bytes"),
        string:len("measured"),
        lists:sublist("truncate", 4)
    }.
