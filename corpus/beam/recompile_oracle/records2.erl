-module(records2).

-export([test/0, make/2, birthday/1, rename/2, tags_of/1, nested_new/0, nested_city/1]).

-record(person, {name, age = 0, tags = []}).
-record(addr, {city, zip}).
-record(user, {person, addr}).

make(Name, Age) ->
    #person{name = Name, age = Age, tags = [new]}.

birthday(P = #person{age = A}) ->
    P#person{age = A + 1}.

rename(P, NewName) ->
    P#person{name = NewName}.

tags_of(#person{tags = T}) ->
    T.

nested_new() ->
    #user{person = #person{name = bob, age = 20}, addr = #addr{city = nyc, zip = 10001}}.

nested_city(#user{addr = #addr{city = C}}) ->
    C.

test() ->
    P0 = make(alice, 30),
    P1 = birthday(P0),
    P2 = rename(P1, alicia),
    U = nested_new(),
    {
        P0#person.name,
        P0#person.age,
        P1#person.age,
        P2#person.name,
        tags_of(P0),
        nested_city(U),
        (U#user.person)#person.age
    }.
