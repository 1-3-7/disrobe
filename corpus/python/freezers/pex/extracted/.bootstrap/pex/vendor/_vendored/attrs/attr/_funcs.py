

from __future__ import absolute_import, division, print_function

import copy

from ._compat import iteritems
from ._make import NOTHING, _obj_setattr, fields
from .exceptions import AttrsAttributeNotFoundError


def asdict(
    inst,
    recurse=True,
    filter=None,
    dict_factory=dict,
    retain_collection_types=False,
    value_serializer=None,
):
    attrs = fields(inst.__class__)
    rv = dict_factory()
    for a in attrs:
        v = getattr(inst, a.name)
        if filter is not None and not filter(a, v):
            continue

        if value_serializer is not None:
            v = value_serializer(inst, a, v)

        if recurse is True:
            if has(v.__class__):
                rv[a.name] = asdict(
                    v,
                    recurse=True,
                    filter=filter,
                    dict_factory=dict_factory,
                    retain_collection_types=retain_collection_types,
                    value_serializer=value_serializer,
                )
            elif isinstance(v, (tuple, list, set, frozenset)):
                cf = v.__class__ if retain_collection_types is True else list
                rv[a.name] = cf(
                    [
                        _asdict_anything(
                            i,
                            is_key=False,
                            filter=filter,
                            dict_factory=dict_factory,
                            retain_collection_types=retain_collection_types,
                            value_serializer=value_serializer,
                        )
                        for i in v
                    ]
                )
            elif isinstance(v, dict):
                df = dict_factory
                rv[a.name] = df(
                    (
                        _asdict_anything(
                            kk,
                            is_key=True,
                            filter=filter,
                            dict_factory=df,
                            retain_collection_types=retain_collection_types,
                            value_serializer=value_serializer,
                        ),
                        _asdict_anything(
                            vv,
                            is_key=False,
                            filter=filter,
                            dict_factory=df,
                            retain_collection_types=retain_collection_types,
                            value_serializer=value_serializer,
                        ),
                    )
                    for kk, vv in iteritems(v)
                )
            else:
                rv[a.name] = v
        else:
            rv[a.name] = v
    return rv


def _asdict_anything(
    val,
    is_key,
    filter,
    dict_factory,
    retain_collection_types,
    value_serializer,
):
    if getattr(val.__class__, "__attrs_attrs__", None) is not None:

        rv = asdict(
            val,
            recurse=True,
            filter=filter,
            dict_factory=dict_factory,
            retain_collection_types=retain_collection_types,
            value_serializer=value_serializer,
        )
    elif isinstance(val, (tuple, list, set, frozenset)):
        if retain_collection_types is True:
            cf = val.__class__
        elif is_key:
            cf = tuple
        else:
            cf = list

        rv = cf(
            [
                _asdict_anything(
                    i,
                    is_key=False,
                    filter=filter,
                    dict_factory=dict_factory,
                    retain_collection_types=retain_collection_types,
                    value_serializer=value_serializer,
                )
                for i in val
            ]
        )
    elif isinstance(val, dict):
        df = dict_factory
        rv = df(
            (
                _asdict_anything(
                    kk,
                    is_key=True,
                    filter=filter,
                    dict_factory=df,
                    retain_collection_types=retain_collection_types,
                    value_serializer=value_serializer,
                ),
                _asdict_anything(
                    vv,
                    is_key=False,
                    filter=filter,
                    dict_factory=df,
                    retain_collection_types=retain_collection_types,
                    value_serializer=value_serializer,
                ),
            )
            for kk, vv in iteritems(val)
        )
    else:
        rv = val
        if value_serializer is not None:
            rv = value_serializer(None, None, rv)

    return rv


def astuple(
    inst,
    recurse=True,
    filter=None,
    tuple_factory=tuple,
    retain_collection_types=False,
):
    attrs = fields(inst.__class__)
    rv = []
    retain = retain_collection_types
    for a in attrs:
        v = getattr(inst, a.name)
        if filter is not None and not filter(a, v):
            continue
        if recurse is True:
            if has(v.__class__):
                rv.append(
                    astuple(
                        v,
                        recurse=True,
                        filter=filter,
                        tuple_factory=tuple_factory,
                        retain_collection_types=retain,
                    )
                )
            elif isinstance(v, (tuple, list, set, frozenset)):
                cf = v.__class__ if retain is True else list
                rv.append(
                    cf(
                        [
                            astuple(
                                j,
                                recurse=True,
                                filter=filter,
                                tuple_factory=tuple_factory,
                                retain_collection_types=retain,
                            )
                            if has(j.__class__)
                            else j
                            for j in v
                        ]
                    )
                )
            elif isinstance(v, dict):
                df = v.__class__ if retain is True else dict
                rv.append(
                    df(
                        (
                            astuple(
                                kk,
                                tuple_factory=tuple_factory,
                                retain_collection_types=retain,
                            )
                            if has(kk.__class__)
                            else kk,
                            astuple(
                                vv,
                                tuple_factory=tuple_factory,
                                retain_collection_types=retain,
                            )
                            if has(vv.__class__)
                            else vv,
                        )
                        for kk, vv in iteritems(v)
                    )
                )
            else:
                rv.append(v)
        else:
            rv.append(v)

    return rv if tuple_factory is list else tuple_factory(rv)


def has(cls):
    return getattr(cls, "__attrs_attrs__", None) is not None


def assoc(inst, **changes):
    import warnings

    warnings.warn(
        "assoc is deprecated and will be removed after 2018/01.",
        DeprecationWarning,
        stacklevel=2,
    )
    new = copy.copy(inst)
    attrs = fields(inst.__class__)
    for k, v in iteritems(changes):
        a = getattr(attrs, k, NOTHING)
        if a is NOTHING:
            raise AttrsAttributeNotFoundError(
                "{k} is not an attrs attribute on {cl}.".format(
                    k=k, cl=new.__class__
                )
            )
        _obj_setattr(new, k, v)
    return new


def evolve(inst, **changes):
    cls = inst.__class__
    attrs = fields(cls)
    for a in attrs:
        if not a.init:
            continue
        attr_name = a.name
        init_name = attr_name if attr_name[0] != "_" else attr_name[1:]
        if init_name not in changes:
            changes[init_name] = getattr(inst, attr_name)

    return cls(**changes)


def resolve_types(cls, globalns=None, localns=None, attribs=None):


    if getattr(cls, "__attrs_types_resolved__", None) != cls:
        import typing

        hints = typing.get_type_hints(cls, globalns=globalns, localns=localns)
        for field in fields(cls) if attribs is None else attribs:
            if field.name in hints:

                _obj_setattr(field, "type", hints[field.name])


        cls.__attrs_types_resolved__ = cls


    return cls
