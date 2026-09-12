-module(casesif).

-export([test/0, grade/1, sign/1, describe/1, deep/1, nested_case/2]).

grade(X) ->
    if
        X >= 90 -> a;
        X >= 80 -> b;
        X >= 70 -> c;
        X >= 60 -> d;
        true -> f
    end.

sign(X) ->
    case X of
        0 -> zero;
        _ when X > 0 -> positive;
        _ -> negative
    end.

describe(T) ->
    case T of
        {ok, V} -> {success, V};
        {error, R} -> {failure, R};
        [_ | _] -> nonempty_list;
        [] -> empty_list;
        _ when is_atom(T) -> an_atom;
        _ -> unknown
    end.

deep(L) ->
    case L of
        [[[V | _] | _] | _] -> {three, V};
        [[V | _] | _] -> {two, V};
        [V | _] -> {one, V};
        [] -> empty
    end.

nested_case(A, B) ->
    case A of
        pos ->
            case B of
                pos -> both_pos;
                _ -> a_pos
            end;
        _ ->
            case B of
                pos -> b_pos;
                _ -> neither
            end
    end.

test() ->
    {
        grade(95), grade(85), grade(72), grade(61), grade(40),
        sign(0), sign(5), sign(-5),
        describe({ok, 1}),
        describe({error, boom}),
        describe([1, 2]),
        describe([]),
        describe(foo),
        deep([[[42]]]),
        deep([[7]]),
        deep([3]),
        nested_case(pos, pos),
        nested_case(pos, neg),
        nested_case(neg, pos),
        nested_case(neg, neg)
    }.
