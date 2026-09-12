-module(binaries).

-export([test/0, decode/1, encode/3, signed/1, floatbin/1, utf/1, dynsize/1]).

decode(<<A:8, B:16/big, C:32/little, Rest/binary>>) ->
    {A, B, C, byte_size(Rest)};
decode(<<Single:8>>) ->
    {single, Single};
decode(<<>>) ->
    empty.

encode(A, B, C) ->
    <<A:8, B:16/big, C:32/little-unsigned>>.

signed(<<X:8/signed, Y:16/signed-big>>) ->
    {X, Y}.

floatbin(<<F:64/float>>) ->
    F.

utf(<<C/utf8, Rest/binary>>) ->
    {C, Rest};
utf(<<>>) ->
    done.

dynsize(<<Len:8, Payload:Len/binary, Tail/binary>>) ->
    {Payload, Tail}.

test() ->
    {
        decode(<<1, 2, 3, 0, 0, 0, 7, 9, 9>>),
        decode(<<42>>),
        decode(<<>>),
        encode(255, 4096, 70000),
        signed(<<255, 255, 255>>),
        floatbin(<<64, 9, 33, 251, 84, 68, 45, 24>>),
        utf(<<"héllo"/utf8>>),
        dynsize(<<3, "abc", "xyz">>)
    }.
