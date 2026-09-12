

from __future__ import absolute_import, division, print_function

import copy
import inspect
import linecache
import sys
import warnings

from operator import itemgetter


from . import _compat, _config, setters
from ._compat import (
    HAS_F_STRINGS,
    PY2,
    PY310,
    PYPY,
    isclass,
    iteritems,
    metadata_proxy,
    new_class,
    ordered_dict,
    set_closure_cell,
)
from .exceptions import (
    DefaultAlreadySetError,
    FrozenInstanceError,
    NotAnAttrsClassError,
    PythonTooOldError,
    UnannotatedAttributeError,
)


if not PY2:
    import typing


_obj_setattr = object.__setattr__
_init_converter_pat = "__attr_converter_%s"
_init_factory_pat = "__attr_factory_{}"
_tuple_property_pat = (
    "    {attr_name} = _attrs_property(_attrs_itemgetter({index}))"
)
_classvar_prefixes = (
    "typing.ClassVar",
    "t.ClassVar",
    "ClassVar",
    "typing_extensions.ClassVar",
)


_hash_cache_field = "_attrs_cached_hash"

_empty_metadata_singleton = metadata_proxy({})


_sentinel = object()

_ng_default_on_setattr = setters.pipe(setters.convert, setters.validate)


class _Nothing(object):

    _singleton = None

    def __new__(cls):
        if _Nothing._singleton is None:
            _Nothing._singleton = super(_Nothing, cls).__new__(cls)
        return _Nothing._singleton

    def __repr__(self):
        return "NOTHING"

    def __bool__(self):
        return False

    def __len__(self):
        return 0


NOTHING = _Nothing()
"""
Sentinel to indicate the lack of a value when ``None`` is ambiguous.
"""


class _CacheHashWrapper(int):

    if PY2:


        def __reduce__(self, _none_constructor=getattr, _args=(0, "", None)):
            return _none_constructor, _args

    else:

        def __reduce__(self, _none_constructor=type(None), _args=()):
            return _none_constructor, _args


def attrib(
    default=NOTHING,
    validator=None,
    repr=True,
    cmp=None,
    hash=None,
    init=True,
    metadata=None,
    type=None,
    converter=None,
    factory=None,
    kw_only=False,
    eq=None,
    order=None,
    on_setattr=None,
):
    eq, eq_key, order, order_key = _determine_attrib_eq_order(
        cmp, eq, order, True
    )

    if hash is not None and hash is not True and hash is not False:
        raise TypeError(
            "Invalid value for hash.  Must be True, False, or None."
        )

    if factory is not None:
        if default is not NOTHING:
            raise ValueError(
                "The `default` and `factory` arguments are mutually "
                "exclusive."
            )
        if not callable(factory):
            raise ValueError("The `factory` argument must be a callable.")
        default = Factory(factory)

    if metadata is None:
        metadata = {}


    if isinstance(on_setattr, (list, tuple)):
        on_setattr = setters.pipe(*on_setattr)

    if validator and isinstance(validator, (list, tuple)):
        validator = and_(*validator)

    if converter and isinstance(converter, (list, tuple)):
        converter = pipe(*converter)

    return _CountingAttr(
        default=default,
        validator=validator,
        repr=repr,
        cmp=None,
        hash=hash,
        init=init,
        converter=converter,
        metadata=metadata,
        type=type,
        kw_only=kw_only,
        eq=eq,
        eq_key=eq_key,
        order=order,
        order_key=order_key,
        on_setattr=on_setattr,
    )


def _compile_and_eval(script, globs, locs=None, filename=""):
    bytecode = compile(script, filename, "exec")
    eval(bytecode, globs, locs)


def _make_method(name, script, filename, globs):
    locs = {}


    count = 1
    base_filename = filename
    while True:
        linecache_tuple = (
            len(script),
            None,
            script.splitlines(True),
            filename,
        )
        old_val = linecache.cache.setdefault(filename, linecache_tuple)
        if old_val == linecache_tuple:
            break
        else:
            filename = "{}-{}>".format(base_filename[:-1], count)
            count += 1

    _compile_and_eval(script, globs, locs, filename)

    return locs[name]


def _make_attr_tuple_class(cls_name, attr_names):
    attr_class_name = "{}Attributes".format(cls_name)
    attr_class_template = [
        "class {}(tuple):".format(attr_class_name),
        "    __slots__ = ()",
    ]
    if attr_names:
        for i, attr_name in enumerate(attr_names):
            attr_class_template.append(
                _tuple_property_pat.format(index=i, attr_name=attr_name)
            )
    else:
        attr_class_template.append("    pass")
    globs = {"_attrs_itemgetter": itemgetter, "_attrs_property": property}
    _compile_and_eval("\n".join(attr_class_template), globs)
    return globs[attr_class_name]


_Attributes = _make_attr_tuple_class(
    "_Attributes",
    [

        "attrs",

        "base_attrs",

        "base_attrs_map",
    ],
)


def _is_class_var(annot):
    annot = str(annot)


    if annot.startswith(("'", '"')) and annot.endswith(("'", '"')):
        annot = annot[1:-1]

    return annot.startswith(_classvar_prefixes)


def _has_own_attribute(cls, attrib_name):
    attr = getattr(cls, attrib_name, _sentinel)
    if attr is _sentinel:
        return False

    for base_cls in cls.__mro__[1:]:
        a = getattr(base_cls, attrib_name, None)
        if attr is a:
            return False

    return True


def _get_annotations(cls):
    if _has_own_attribute(cls, "__annotations__"):
        return cls.__annotations__

    return {}


def _counter_getter(e):
    return e[1].counter


def _collect_base_attrs(cls, taken_attr_names):
    base_attrs = []
    base_attr_map = {}


    for base_cls in reversed(cls.__mro__[1:-1]):
        for a in getattr(base_cls, "__attrs_attrs__", []):
            if a.inherited or a.name in taken_attr_names:
                continue

            a = a.evolve(inherited=True)
            base_attrs.append(a)
            base_attr_map[a.name] = base_cls


    filtered = []
    seen = set()
    for a in reversed(base_attrs):
        if a.name in seen:
            continue
        filtered.insert(0, a)
        seen.add(a.name)

    return filtered, base_attr_map


def _collect_base_attrs_broken(cls, taken_attr_names):
    base_attrs = []
    base_attr_map = {}


    for base_cls in cls.__mro__[1:-1]:
        for a in getattr(base_cls, "__attrs_attrs__", []):
            if a.name in taken_attr_names:
                continue

            a = a.evolve(inherited=True)
            taken_attr_names.add(a.name)
            base_attrs.append(a)
            base_attr_map[a.name] = base_cls

    return base_attrs, base_attr_map


def _transform_attrs(
    cls, these, auto_attribs, kw_only, collect_by_mro, field_transformer
):
    cd = cls.__dict__
    anns = _get_annotations(cls)

    if these is not None:
        ca_list = [(name, ca) for name, ca in iteritems(these)]

        if not isinstance(these, ordered_dict):
            ca_list.sort(key=_counter_getter)
    elif auto_attribs is True:
        ca_names = {
            name
            for name, attr in cd.items()
            if isinstance(attr, _CountingAttr)
        }
        ca_list = []
        annot_names = set()
        for attr_name, type in anns.items():
            if _is_class_var(type):
                continue
            annot_names.add(attr_name)
            a = cd.get(attr_name, NOTHING)

            if not isinstance(a, _CountingAttr):
                if a is NOTHING:
                    a = attrib()
                else:
                    a = attrib(default=a)
            ca_list.append((attr_name, a))

        unannotated = ca_names - annot_names
        if len(unannotated) > 0:
            raise UnannotatedAttributeError(
                "The following `attr.ib`s lack a type annotation: "
                + ", ".join(
                    sorted(unannotated, key=lambda n: cd.get(n).counter)
                )
                + "."
            )
    else:
        ca_list = sorted(
            (
                (name, attr)
                for name, attr in cd.items()
                if isinstance(attr, _CountingAttr)
            ),
            key=lambda e: e[1].counter,
        )

    own_attrs = [
        Attribute.from_counting_attr(
            name=attr_name, ca=ca, type=anns.get(attr_name)
        )
        for attr_name, ca in ca_list
    ]

    if collect_by_mro:
        base_attrs, base_attr_map = _collect_base_attrs(
            cls, {a.name for a in own_attrs}
        )
    else:
        base_attrs, base_attr_map = _collect_base_attrs_broken(
            cls, {a.name for a in own_attrs}
        )

    if kw_only:
        own_attrs = [a.evolve(kw_only=True) for a in own_attrs]
        base_attrs = [a.evolve(kw_only=True) for a in base_attrs]

    attrs = base_attrs + own_attrs


    had_default = False
    for a in (a for a in attrs if a.init is not False and a.kw_only is False):
        if had_default is True and a.default is NOTHING:
            raise ValueError(
                "No mandatory attributes allowed after an attribute with a "
                "default value or factory.  Attribute in question: %r" % (a,)
            )

        if had_default is False and a.default is not NOTHING:
            had_default = True

    if field_transformer is not None:
        attrs = field_transformer(cls, attrs)


    attr_names = [a.name for a in attrs]
    AttrsClass = _make_attr_tuple_class(cls.__name__, attr_names)

    return _Attributes((AttrsClass(attrs), base_attrs, base_attr_map))


if PYPY:

    def _frozen_setattrs(self, name, value):
        if isinstance(self, BaseException) and name in (
            "__cause__",
            "__context__",
        ):
            BaseException.__setattr__(self, name, value)
            return

        raise FrozenInstanceError()

else:

    def _frozen_setattrs(self, name, value):
        raise FrozenInstanceError()


def _frozen_delattrs(self, name):
    raise FrozenInstanceError()


class _ClassBuilder(object):

    __slots__ = (
        "_attr_names",
        "_attrs",
        "_base_attr_map",
        "_base_names",
        "_cache_hash",
        "_cls",
        "_cls_dict",
        "_delete_attribs",
        "_frozen",
        "_has_pre_init",
        "_has_post_init",
        "_is_exc",
        "_on_setattr",
        "_slots",
        "_weakref_slot",
        "_wrote_own_setattr",
        "_has_custom_setattr",
    )

    def __init__(
        self,
        cls,
        these,
        slots,
        frozen,
        weakref_slot,
        getstate_setstate,
        auto_attribs,
        kw_only,
        cache_hash,
        is_exc,
        collect_by_mro,
        on_setattr,
        has_custom_setattr,
        field_transformer,
    ):
        attrs, base_attrs, base_map = _transform_attrs(
            cls,
            these,
            auto_attribs,
            kw_only,
            collect_by_mro,
            field_transformer,
        )

        self._cls = cls
        self._cls_dict = dict(cls.__dict__) if slots else {}
        self._attrs = attrs
        self._base_names = set(a.name for a in base_attrs)
        self._base_attr_map = base_map
        self._attr_names = tuple(a.name for a in attrs)
        self._slots = slots
        self._frozen = frozen
        self._weakref_slot = weakref_slot
        self._cache_hash = cache_hash
        self._has_pre_init = bool(getattr(cls, "__attrs_pre_init__", False))
        self._has_post_init = bool(getattr(cls, "__attrs_post_init__", False))
        self._delete_attribs = not bool(these)
        self._is_exc = is_exc
        self._on_setattr = on_setattr

        self._has_custom_setattr = has_custom_setattr
        self._wrote_own_setattr = False

        self._cls_dict["__attrs_attrs__"] = self._attrs

        if frozen:
            self._cls_dict["__setattr__"] = _frozen_setattrs
            self._cls_dict["__delattr__"] = _frozen_delattrs

            self._wrote_own_setattr = True
        elif on_setattr in (
            _ng_default_on_setattr,
            setters.validate,
            setters.convert,
        ):
            has_validator = has_converter = False
            for a in attrs:
                if a.validator is not None:
                    has_validator = True
                if a.converter is not None:
                    has_converter = True

                if has_validator and has_converter:
                    break
            if (
                (
                    on_setattr == _ng_default_on_setattr
                    and not (has_validator or has_converter)
                )
                or (on_setattr == setters.validate and not has_validator)
                or (on_setattr == setters.convert and not has_converter)
            ):


                self._on_setattr = None

        if getstate_setstate:
            (
                self._cls_dict["__getstate__"],
                self._cls_dict["__setstate__"],
            ) = self._make_getstate_setstate()

    def __repr__(self):
        return "<_ClassBuilder(cls={cls})>".format(cls=self._cls.__name__)

    def build_class(self):
        if self._slots is True:
            return self._create_slots_class()
        else:
            return self._patch_original_class()

    def _patch_original_class(self):
        cls = self._cls
        base_names = self._base_names


        if self._delete_attribs:
            for name in self._attr_names:
                if (
                    name not in base_names
                    and getattr(cls, name, _sentinel) is not _sentinel
                ):
                    try:
                        delattr(cls, name)
                    except AttributeError:


                        pass


        for name, value in self._cls_dict.items():
            setattr(cls, name, value)


        if not self._wrote_own_setattr and getattr(
            cls, "__attrs_own_setattr__", False
        ):
            cls.__attrs_own_setattr__ = False

            if not self._has_custom_setattr:
                cls.__setattr__ = _obj_setattr

        return cls

    def _create_slots_class(self):
        cd = {
            k: v
            for k, v in iteritems(self._cls_dict)
            if k not in tuple(self._attr_names) + ("__dict__", "__weakref__")
        }


        if not self._wrote_own_setattr:
            cd["__attrs_own_setattr__"] = False

            if not self._has_custom_setattr:
                for base_cls in self._cls.__bases__:
                    if base_cls.__dict__.get("__attrs_own_setattr__", False):
                        cd["__setattr__"] = _obj_setattr
                        break


        existing_slots = dict()
        weakref_inherited = False
        for base_cls in self._cls.__mro__[1:-1]:
            if base_cls.__dict__.get("__weakref__", None) is not None:
                weakref_inherited = True
            existing_slots.update(
                {
                    name: getattr(base_cls, name)
                    for name in getattr(base_cls, "__slots__", [])
                }
            )

        base_names = set(self._base_names)

        names = self._attr_names
        if (
            self._weakref_slot
            and "__weakref__" not in getattr(self._cls, "__slots__", ())
            and "__weakref__" not in names
            and not weakref_inherited
        ):
            names += ("__weakref__",)


        slot_names = [name for name in names if name not in base_names]


        reused_slots = {
            slot: slot_descriptor
            for slot, slot_descriptor in iteritems(existing_slots)
            if slot in slot_names
        }
        slot_names = [name for name in slot_names if name not in reused_slots]
        cd.update(reused_slots)
        if self._cache_hash:
            slot_names.append(_hash_cache_field)
        cd["__slots__"] = tuple(slot_names)

        qualname = getattr(self._cls, "__qualname__", None)
        if qualname is not None:
            cd["__qualname__"] = qualname


        cls = type(self._cls)(self._cls.__name__, self._cls.__bases__, cd)


        for item in cls.__dict__.values():
            if isinstance(item, (classmethod, staticmethod)):


                closure_cells = getattr(item.__func__, "__closure__", None)
            elif isinstance(item, property):


                closure_cells = getattr(item.fget, "__closure__", None)
            else:
                closure_cells = getattr(item, "__closure__", None)

            if not closure_cells:
                continue
            for cell in closure_cells:
                try:
                    match = cell.cell_contents is self._cls
                except ValueError:
                    pass
                else:
                    if match:
                        set_closure_cell(cell, cls)

        return cls

    def add_repr(self, ns):
        self._cls_dict["__repr__"] = self._add_method_dunders(
            _make_repr(self._attrs, ns, self._cls)
        )
        return self

    def add_str(self):
        repr = self._cls_dict.get("__repr__")
        if repr is None:
            raise ValueError(
                "__str__ can only be generated if a __repr__ exists."
            )

        def __str__(self):
            return self.__repr__()

        self._cls_dict["__str__"] = self._add_method_dunders(__str__)
        return self

    def _make_getstate_setstate(self):

        state_attr_names = tuple(
            an for an in self._attr_names if an != "__weakref__"
        )

        def slots_getstate(self):
            return tuple(getattr(self, name) for name in state_attr_names)

        hash_caching_enabled = self._cache_hash

        def slots_setstate(self, state):
            __bound_setattr = _obj_setattr.__get__(self, Attribute)
            for name, value in zip(state_attr_names, state):
                __bound_setattr(name, value)


            if hash_caching_enabled:
                __bound_setattr(_hash_cache_field, None)

        return slots_getstate, slots_setstate

    def make_unhashable(self):
        self._cls_dict["__hash__"] = None
        return self

    def add_hash(self):
        self._cls_dict["__hash__"] = self._add_method_dunders(
            _make_hash(
                self._cls,
                self._attrs,
                frozen=self._frozen,
                cache_hash=self._cache_hash,
            )
        )

        return self

    def add_init(self):
        self._cls_dict["__init__"] = self._add_method_dunders(
            _make_init(
                self._cls,
                self._attrs,
                self._has_pre_init,
                self._has_post_init,
                self._frozen,
                self._slots,
                self._cache_hash,
                self._base_attr_map,
                self._is_exc,
                self._on_setattr,
                attrs_init=False,
            )
        )

        return self

    def add_match_args(self):
        self._cls_dict["__match_args__"] = tuple(
            field.name
            for field in self._attrs
            if field.init and not field.kw_only
        )

    def add_attrs_init(self):
        self._cls_dict["__attrs_init__"] = self._add_method_dunders(
            _make_init(
                self._cls,
                self._attrs,
                self._has_pre_init,
                self._has_post_init,
                self._frozen,
                self._slots,
                self._cache_hash,
                self._base_attr_map,
                self._is_exc,
                self._on_setattr,
                attrs_init=True,
            )
        )

        return self

    def add_eq(self):
        cd = self._cls_dict

        cd["__eq__"] = self._add_method_dunders(
            _make_eq(self._cls, self._attrs)
        )
        cd["__ne__"] = self._add_method_dunders(_make_ne())

        return self

    def add_order(self):
        cd = self._cls_dict

        cd["__lt__"], cd["__le__"], cd["__gt__"], cd["__ge__"] = (
            self._add_method_dunders(meth)
            for meth in _make_order(self._cls, self._attrs)
        )

        return self

    def add_setattr(self):
        if self._frozen:
            return self

        sa_attrs = {}
        for a in self._attrs:
            on_setattr = a.on_setattr or self._on_setattr
            if on_setattr and on_setattr is not setters.NO_OP:
                sa_attrs[a.name] = a, on_setattr

        if not sa_attrs:
            return self

        if self._has_custom_setattr:

            raise ValueError(
                "Can't combine custom __setattr__ with on_setattr hooks."
            )


        def __setattr__(self, name, val):
            try:
                a, hook = sa_attrs[name]
            except KeyError:
                nval = val
            else:
                nval = hook(self, a, val)

            _obj_setattr(self, name, nval)

        self._cls_dict["__attrs_own_setattr__"] = True
        self._cls_dict["__setattr__"] = self._add_method_dunders(__setattr__)
        self._wrote_own_setattr = True

        return self

    def _add_method_dunders(self, method):
        try:
            method.__module__ = self._cls.__module__
        except AttributeError:
            pass

        try:
            method.__qualname__ = ".".join(
                (self._cls.__qualname__, method.__name__)
            )
        except AttributeError:
            pass

        try:
            method.__doc__ = "Method generated by attrs for class %s." % (
                self._cls.__qualname__,
            )
        except AttributeError:
            pass

        return method


_CMP_DEPRECATION = (
    "The usage of `cmp` is deprecated and will be removed on or after "
    "2021-06-01.  Please use `eq` and `order` instead."
)


def _determine_attrs_eq_order(cmp, eq, order, default_eq):
    if cmp is not None and any((eq is not None, order is not None)):
        raise ValueError("Don't mix `cmp` with `eq' and `order`.")


    if cmp is not None:
        return cmp, cmp


    if eq is None:
        eq = default_eq

    if order is None:
        order = eq

    if eq is False and order is True:
        raise ValueError("`order` can only be True if `eq` is True too.")

    return eq, order


def _determine_attrib_eq_order(cmp, eq, order, default_eq):
    if cmp is not None and any((eq is not None, order is not None)):
        raise ValueError("Don't mix `cmp` with `eq' and `order`.")

    def decide_callable_or_boolean(value):
        if callable(value):
            value, key = True, value
        else:
            key = None
        return value, key


    if cmp is not None:
        cmp, cmp_key = decide_callable_or_boolean(cmp)
        return cmp, cmp_key, cmp, cmp_key


    if eq is None:
        eq, eq_key = default_eq, None
    else:
        eq, eq_key = decide_callable_or_boolean(eq)

    if order is None:
        order, order_key = eq, eq_key
    else:
        order, order_key = decide_callable_or_boolean(order)

    if eq is False and order is True:
        raise ValueError("`order` can only be True if `eq` is True too.")

    return eq, eq_key, order, order_key


def _determine_whether_to_implement(
    cls, flag, auto_detect, dunders, default=True
):
    if flag is True or flag is False:
        return flag

    if flag is None and auto_detect is False:
        return default


    for dunder in dunders:
        if _has_own_attribute(cls, dunder):
            return False

    return default


def attrs(
    maybe_cls=None,
    these=None,
    repr_ns=None,
    repr=None,
    cmp=None,
    hash=None,
    init=None,
    slots=False,
    frozen=False,
    weakref_slot=True,
    str=False,
    auto_attribs=False,
    kw_only=False,
    cache_hash=False,
    auto_exc=False,
    eq=None,
    order=None,
    auto_detect=False,
    collect_by_mro=False,
    getstate_setstate=None,
    on_setattr=None,
    field_transformer=None,
    match_args=True,
):
    if auto_detect and PY2:
        raise PythonTooOldError(
            "auto_detect only works on Python 3 and later."
        )

    eq_, order_ = _determine_attrs_eq_order(cmp, eq, order, None)
    hash_ = hash

    if isinstance(on_setattr, (list, tuple)):
        on_setattr = setters.pipe(*on_setattr)

    def wrap(cls):

        if getattr(cls, "__class__", None) is None:
            raise TypeError("attrs only works with new-style classes.")

        is_frozen = frozen or _has_frozen_base_class(cls)
        is_exc = auto_exc is True and issubclass(cls, BaseException)
        has_own_setattr = auto_detect and _has_own_attribute(
            cls, "__setattr__"
        )

        if has_own_setattr and is_frozen:
            raise ValueError("Can't freeze a class with a custom __setattr__.")

        builder = _ClassBuilder(
            cls,
            these,
            slots,
            is_frozen,
            weakref_slot,
            _determine_whether_to_implement(
                cls,
                getstate_setstate,
                auto_detect,
                ("__getstate__", "__setstate__"),
                default=slots,
            ),
            auto_attribs,
            kw_only,
            cache_hash,
            is_exc,
            collect_by_mro,
            on_setattr,
            has_own_setattr,
            field_transformer,
        )
        if _determine_whether_to_implement(
            cls, repr, auto_detect, ("__repr__",)
        ):
            builder.add_repr(repr_ns)
        if str is True:
            builder.add_str()

        eq = _determine_whether_to_implement(
            cls, eq_, auto_detect, ("__eq__", "__ne__")
        )
        if not is_exc and eq is True:
            builder.add_eq()
        if not is_exc and _determine_whether_to_implement(
            cls, order_, auto_detect, ("__lt__", "__le__", "__gt__", "__ge__")
        ):
            builder.add_order()

        builder.add_setattr()

        if (
            hash_ is None
            and auto_detect is True
            and _has_own_attribute(cls, "__hash__")
        ):
            hash = False
        else:
            hash = hash_
        if hash is not True and hash is not False and hash is not None:

            raise TypeError(
                "Invalid value for hash.  Must be True, False, or None."
            )
        elif hash is False or (hash is None and eq is False) or is_exc:


            if cache_hash:
                raise TypeError(
                    "Invalid value for cache_hash.  To use hash caching,"
                    " hashing must be either explicitly or implicitly "
                    "enabled."
                )
        elif hash is True or (
            hash is None and eq is True and is_frozen is True
        ):

            builder.add_hash()
        else:

            if cache_hash:
                raise TypeError(
                    "Invalid value for cache_hash.  To use hash caching,"
                    " hashing must be either explicitly or implicitly "
                    "enabled."
                )
            builder.make_unhashable()

        if _determine_whether_to_implement(
            cls, init, auto_detect, ("__init__",)
        ):
            builder.add_init()
        else:
            builder.add_attrs_init()
            if cache_hash:
                raise TypeError(
                    "Invalid value for cache_hash.  To use hash caching,"
                    " init must be True."
                )

        if (
            PY310
            and match_args
            and not _has_own_attribute(cls, "__match_args__")
        ):
            builder.add_match_args()

        return builder.build_class()


    if maybe_cls is None:
        return wrap
    else:
        return wrap(maybe_cls)


_attrs = attrs
"""
Internal alias so we can use it in functions that take an argument called
*attrs*.
"""


if PY2:

    def _has_frozen_base_class(cls):
        return (
            getattr(cls.__setattr__, "__module__", None)
            == _frozen_setattrs.__module__
            and cls.__setattr__.__name__ == _frozen_setattrs.__name__
        )

else:

    def _has_frozen_base_class(cls):
        return cls.__setattr__ == _frozen_setattrs


def _generate_unique_filename(cls, func_name):
    unique_filename = "<attrs generated {0} {1}.{2}>".format(
        func_name,
        cls.__module__,
        getattr(cls, "__qualname__", cls.__name__),
    )
    return unique_filename


def _make_hash(cls, attrs, frozen, cache_hash):
    attrs = tuple(
        a for a in attrs if a.hash is True or (a.hash is None and a.eq is True)
    )

    tab = "        "

    unique_filename = _generate_unique_filename(cls, "hash")
    type_hash = hash(unique_filename)

    globs = {}

    hash_def = "def __hash__(self"
    hash_func = "hash(("
    closing_braces = "))"
    if not cache_hash:
        hash_def += "):"
    else:
        if not PY2:
            hash_def += ", *"

        hash_def += (
            ", _cache_wrapper="
            + "__import__('attr._make')._make._CacheHashWrapper):"
        )
        hash_func = "_cache_wrapper(" + hash_func
        closing_braces += ")"

    method_lines = [hash_def]

    def append_hash_computation_lines(prefix, indent):

        method_lines.extend(
            [
                indent + prefix + hash_func,
                indent + "        %d," % (type_hash,),
            ]
        )

        for a in attrs:
            if a.eq_key:
                cmp_name = "_%s_key" % (a.name,)
                globs[cmp_name] = a.eq_key
                method_lines.append(
                    indent + "        %s(self.%s)," % (cmp_name, a.name)
                )
            else:
                method_lines.append(indent + "        self.%s," % a.name)

        method_lines.append(indent + "    " + closing_braces)

    if cache_hash:
        method_lines.append(tab + "if self.%s is None:" % _hash_cache_field)
        if frozen:
            append_hash_computation_lines(
                "object.__setattr__(self, '%s', " % _hash_cache_field, tab * 2
            )
            method_lines.append(tab * 2 + ")")
        else:
            append_hash_computation_lines(
                "self.%s = " % _hash_cache_field, tab * 2
            )
        method_lines.append(tab + "return self.%s" % _hash_cache_field)
    else:
        append_hash_computation_lines("return ", tab)

    script = "\n".join(method_lines)
    return _make_method("__hash__", script, unique_filename, globs)


def _add_hash(cls, attrs):
    cls.__hash__ = _make_hash(cls, attrs, frozen=False, cache_hash=False)
    return cls


def _make_ne():

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return NotImplemented

        return not result

    return __ne__


def _make_eq(cls, attrs):
    attrs = [a for a in attrs if a.eq]

    unique_filename = _generate_unique_filename(cls, "eq")
    lines = [
        "def __eq__(self, other):",
        "    if other.__class__ is not self.__class__:",
        "        return NotImplemented",
    ]


    globs = {}
    if attrs:
        lines.append("    return  (")
        others = ["    ) == ("]
        for a in attrs:
            if a.eq_key:
                cmp_name = "_%s_key" % (a.name,)


                globs[cmp_name] = a.eq_key
                lines.append(
                    "        %s(self.%s),"
                    % (
                        cmp_name,
                        a.name,
                    )
                )
                others.append(
                    "        %s(other.%s),"
                    % (
                        cmp_name,
                        a.name,
                    )
                )
            else:
                lines.append("        self.%s," % (a.name,))
                others.append("        other.%s," % (a.name,))

        lines += others + ["    )"]
    else:
        lines.append("    return True")

    script = "\n".join(lines)

    return _make_method("__eq__", script, unique_filename, globs)


def _make_order(cls, attrs):
    attrs = [a for a in attrs if a.order]

    def attrs_to_tuple(obj):
        return tuple(
            key(value) if key else value
            for value, key in (
                (getattr(obj, a.name), a.order_key) for a in attrs
            )
        )

    def __lt__(self, other):
        if other.__class__ is self.__class__:
            return attrs_to_tuple(self) < attrs_to_tuple(other)

        return NotImplemented

    def __le__(self, other):
        if other.__class__ is self.__class__:
            return attrs_to_tuple(self) <= attrs_to_tuple(other)

        return NotImplemented

    def __gt__(self, other):
        if other.__class__ is self.__class__:
            return attrs_to_tuple(self) > attrs_to_tuple(other)

        return NotImplemented

    def __ge__(self, other):
        if other.__class__ is self.__class__:
            return attrs_to_tuple(self) >= attrs_to_tuple(other)

        return NotImplemented

    return __lt__, __le__, __gt__, __ge__


def _add_eq(cls, attrs=None):
    if attrs is None:
        attrs = cls.__attrs_attrs__

    cls.__eq__ = _make_eq(cls, attrs)
    cls.__ne__ = _make_ne()

    return cls


if HAS_F_STRINGS:

    def _make_repr(attrs, ns, cls):
        unique_filename = _generate_unique_filename(cls, "repr")


        attr_names_with_reprs = tuple(
            (a.name, (repr if a.repr is True else a.repr), a.init)
            for a in attrs
            if a.repr is not False
        )
        globs = {
            name + "_repr": r
            for name, r, _ in attr_names_with_reprs
            if r != repr
        }
        globs["_compat"] = _compat
        globs["AttributeError"] = AttributeError
        globs["NOTHING"] = NOTHING
        attribute_fragments = []
        for name, r, i in attr_names_with_reprs:
            accessor = (
                "self." + name
                if i
                else 'getattr(self, "' + name + '", NOTHING)'
            )
            fragment = (
                "%s={%s!r}" % (name, accessor)
                if r == repr
                else "%s={%s_repr(%s)}" % (name, name, accessor)
            )
            attribute_fragments.append(fragment)
        repr_fragment = ", ".join(attribute_fragments)

        if ns is None:
            cls_name_fragment = (
                '{self.__class__.__qualname__.rsplit(">.", 1)[-1]}'
            )
        else:
            cls_name_fragment = ns + ".{self.__class__.__name__}"

        lines = [
            "def __repr__(self):",
            "  try:",
            "    already_repring = _compat.repr_context.already_repring",
            "  except AttributeError:",
            "    already_repring = {id(self),}",
            "    _compat.repr_context.already_repring = already_repring",
            "  else:",
            "    if id(self) in already_repring:",
            "      return '...'",
            "    else:",
            "      already_repring.add(id(self))",
            "  try:",
            "    return f'%s(%s)'" % (cls_name_fragment, repr_fragment),
            "  finally:",
            "    already_repring.remove(id(self))",
        ]

        return _make_method(
            "__repr__", "\n".join(lines), unique_filename, globs=globs
        )

else:

    def _make_repr(attrs, ns, _):


        attr_names_with_reprs = tuple(
            (a.name, repr if a.repr is True else a.repr)
            for a in attrs
            if a.repr is not False
        )

        def __repr__(self):
            try:
                already_repring = _compat.repr_context.already_repring
            except AttributeError:
                already_repring = set()
                _compat.repr_context.already_repring = already_repring

            if id(self) in already_repring:
                return "..."
            real_cls = self.__class__
            if ns is None:
                qualname = getattr(real_cls, "__qualname__", None)
                if qualname is not None:


                    class_name = qualname.rsplit(">.", 1)[-1]
                else:
                    class_name = real_cls.__name__
            else:
                class_name = ns + "." + real_cls.__name__


            already_repring.add(id(self))
            try:
                result = [class_name, "("]
                first = True
                for name, attr_repr in attr_names_with_reprs:
                    if first:
                        first = False
                    else:
                        result.append(", ")
                    result.extend(
                        (name, "=", attr_repr(getattr(self, name, NOTHING)))
                    )
                return "".join(result) + ")"
            finally:
                already_repring.remove(id(self))

        return __repr__


def _add_repr(cls, ns=None, attrs=None):
    if attrs is None:
        attrs = cls.__attrs_attrs__

    cls.__repr__ = _make_repr(attrs, ns, cls)
    return cls


def fields(cls):
    if not isclass(cls):
        raise TypeError("Passed object must be a class.")
    attrs = getattr(cls, "__attrs_attrs__", None)
    if attrs is None:
        raise NotAnAttrsClassError(
            "{cls!r} is not an attrs-decorated class.".format(cls=cls)
        )
    return attrs


def fields_dict(cls):
    if not isclass(cls):
        raise TypeError("Passed object must be a class.")
    attrs = getattr(cls, "__attrs_attrs__", None)
    if attrs is None:
        raise NotAnAttrsClassError(
            "{cls!r} is not an attrs-decorated class.".format(cls=cls)
        )
    return ordered_dict(((a.name, a) for a in attrs))


def validate(inst):
    if _config._run_validators is False:
        return

    for a in fields(inst.__class__):
        v = a.validator
        if v is not None:
            v(inst, a, getattr(inst, a.name))


def _is_slot_cls(cls):
    return "__slots__" in cls.__dict__


def _is_slot_attr(a_name, base_attr_map):
    return a_name in base_attr_map and _is_slot_cls(base_attr_map[a_name])


def _make_init(
    cls,
    attrs,
    pre_init,
    post_init,
    frozen,
    slots,
    cache_hash,
    base_attr_map,
    is_exc,
    cls_on_setattr,
    attrs_init,
):
    has_cls_on_setattr = (
        cls_on_setattr is not None and cls_on_setattr is not setters.NO_OP
    )

    if frozen and has_cls_on_setattr:
        raise ValueError("Frozen classes can't use on_setattr.")

    needs_cached_setattr = cache_hash or frozen
    filtered_attrs = []
    attr_dict = {}
    for a in attrs:
        if not a.init and a.default is NOTHING:
            continue

        filtered_attrs.append(a)
        attr_dict[a.name] = a

        if a.on_setattr is not None:
            if frozen is True:
                raise ValueError("Frozen classes can't use on_setattr.")

            needs_cached_setattr = True
        elif has_cls_on_setattr and a.on_setattr is not setters.NO_OP:
            needs_cached_setattr = True

    unique_filename = _generate_unique_filename(cls, "init")

    script, globs, annotations = _attrs_to_init_script(
        filtered_attrs,
        frozen,
        slots,
        pre_init,
        post_init,
        cache_hash,
        base_attr_map,
        is_exc,
        has_cls_on_setattr,
        attrs_init,
    )
    if cls.__module__ in sys.modules:

        globs.update(sys.modules[cls.__module__].__dict__)

    globs.update({"NOTHING": NOTHING, "attr_dict": attr_dict})

    if needs_cached_setattr:


        globs["_setattr"] = _obj_setattr

    init = _make_method(
        "__attrs_init__" if attrs_init else "__init__",
        script,
        unique_filename,
        globs,
    )
    init.__annotations__ = annotations

    return init


def _setattr(attr_name, value_var, has_on_setattr):
    return "_setattr(self, '%s', %s)" % (attr_name, value_var)


def _setattr_with_converter(attr_name, value_var, has_on_setattr):
    return "_setattr(self, '%s', %s(%s))" % (
        attr_name,
        _init_converter_pat % (attr_name,),
        value_var,
    )


def _assign(attr_name, value, has_on_setattr):
    if has_on_setattr:
        return _setattr(attr_name, value, True)

    return "self.%s = %s" % (attr_name, value)


def _assign_with_converter(attr_name, value_var, has_on_setattr):
    if has_on_setattr:
        return _setattr_with_converter(attr_name, value_var, True)

    return "self.%s = %s(%s)" % (
        attr_name,
        _init_converter_pat % (attr_name,),
        value_var,
    )


if PY2:

    def _unpack_kw_only_py2(attr_name, default=None):
        if default is not None:
            arg_default = ", %s" % default
        else:
            arg_default = ""
        return "%s = _kw_only.pop('%s'%s)" % (
            attr_name,
            attr_name,
            arg_default,
        )

    def _unpack_kw_only_lines_py2(kw_only_args):
        lines = ["try:"]
        lines.extend(
            "    " + _unpack_kw_only_py2(*arg.split("="))
            for arg in kw_only_args
        )
        lines += """\
except KeyError as _key_error:
    raise TypeError(
        '__init__() missing required keyword-only argument: %s' % _key_error
    )
if _kw_only:
    raise TypeError(
        '__init__() got an unexpected keyword argument %r'
        % next(iter(_kw_only))
    )
""".split(
            "\n"
        )
        return lines


def _attrs_to_init_script(
    attrs,
    frozen,
    slots,
    pre_init,
    post_init,
    cache_hash,
    base_attr_map,
    is_exc,
    has_cls_on_setattr,
    attrs_init,
):
    lines = []
    if pre_init:
        lines.append("self.__attrs_pre_init__()")

    if frozen is True:
        if slots is True:
            fmt_setter = _setattr
            fmt_setter_with_converter = _setattr_with_converter
        else:


            lines.append("_inst_dict = self.__dict__")

            def fmt_setter(attr_name, value_var, has_on_setattr):
                if _is_slot_attr(attr_name, base_attr_map):
                    return _setattr(attr_name, value_var, has_on_setattr)

                return "_inst_dict['%s'] = %s" % (attr_name, value_var)

            def fmt_setter_with_converter(
                attr_name, value_var, has_on_setattr
            ):
                if has_on_setattr or _is_slot_attr(attr_name, base_attr_map):
                    return _setattr_with_converter(
                        attr_name, value_var, has_on_setattr
                    )

                return "_inst_dict['%s'] = %s(%s)" % (
                    attr_name,
                    _init_converter_pat % (attr_name,),
                    value_var,
                )

    else:

        fmt_setter = _assign
        fmt_setter_with_converter = _assign_with_converter

    args = []
    kw_only_args = []
    attrs_to_validate = []


    names_for_globals = {}
    annotations = {"return": None}

    for a in attrs:
        if a.validator:
            attrs_to_validate.append(a)

        attr_name = a.name
        has_on_setattr = a.on_setattr is not None or (
            a.on_setattr is not setters.NO_OP and has_cls_on_setattr
        )
        arg_name = a.name.lstrip("_")

        has_factory = isinstance(a.default, Factory)
        if has_factory and a.default.takes_self:
            maybe_self = "self"
        else:
            maybe_self = ""

        if a.init is False:
            if has_factory:
                init_factory_name = _init_factory_pat.format(a.name)
                if a.converter is not None:
                    lines.append(
                        fmt_setter_with_converter(
                            attr_name,
                            init_factory_name + "(%s)" % (maybe_self,),
                            has_on_setattr,
                        )
                    )
                    conv_name = _init_converter_pat % (a.name,)
                    names_for_globals[conv_name] = a.converter
                else:
                    lines.append(
                        fmt_setter(
                            attr_name,
                            init_factory_name + "(%s)" % (maybe_self,),
                            has_on_setattr,
                        )
                    )
                names_for_globals[init_factory_name] = a.default.factory
            else:
                if a.converter is not None:
                    lines.append(
                        fmt_setter_with_converter(
                            attr_name,
                            "attr_dict['%s'].default" % (attr_name,),
                            has_on_setattr,
                        )
                    )
                    conv_name = _init_converter_pat % (a.name,)
                    names_for_globals[conv_name] = a.converter
                else:
                    lines.append(
                        fmt_setter(
                            attr_name,
                            "attr_dict['%s'].default" % (attr_name,),
                            has_on_setattr,
                        )
                    )
        elif a.default is not NOTHING and not has_factory:
            arg = "%s=attr_dict['%s'].default" % (arg_name, attr_name)
            if a.kw_only:
                kw_only_args.append(arg)
            else:
                args.append(arg)

            if a.converter is not None:
                lines.append(
                    fmt_setter_with_converter(
                        attr_name, arg_name, has_on_setattr
                    )
                )
                names_for_globals[
                    _init_converter_pat % (a.name,)
                ] = a.converter
            else:
                lines.append(fmt_setter(attr_name, arg_name, has_on_setattr))

        elif has_factory:
            arg = "%s=NOTHING" % (arg_name,)
            if a.kw_only:
                kw_only_args.append(arg)
            else:
                args.append(arg)
            lines.append("if %s is not NOTHING:" % (arg_name,))

            init_factory_name = _init_factory_pat.format(a.name)
            if a.converter is not None:
                lines.append(
                    "    "
                    + fmt_setter_with_converter(
                        attr_name, arg_name, has_on_setattr
                    )
                )
                lines.append("else:")
                lines.append(
                    "    "
                    + fmt_setter_with_converter(
                        attr_name,
                        init_factory_name + "(" + maybe_self + ")",
                        has_on_setattr,
                    )
                )
                names_for_globals[
                    _init_converter_pat % (a.name,)
                ] = a.converter
            else:
                lines.append(
                    "    " + fmt_setter(attr_name, arg_name, has_on_setattr)
                )
                lines.append("else:")
                lines.append(
                    "    "
                    + fmt_setter(
                        attr_name,
                        init_factory_name + "(" + maybe_self + ")",
                        has_on_setattr,
                    )
                )
            names_for_globals[init_factory_name] = a.default.factory
        else:
            if a.kw_only:
                kw_only_args.append(arg_name)
            else:
                args.append(arg_name)

            if a.converter is not None:
                lines.append(
                    fmt_setter_with_converter(
                        attr_name, arg_name, has_on_setattr
                    )
                )
                names_for_globals[
                    _init_converter_pat % (a.name,)
                ] = a.converter
            else:
                lines.append(fmt_setter(attr_name, arg_name, has_on_setattr))

        if a.init is True:
            if a.type is not None and a.converter is None:
                annotations[arg_name] = a.type
            elif a.converter is not None and not PY2:

                sig = None
                try:
                    sig = inspect.signature(a.converter)
                except (ValueError, TypeError):
                    pass
                if sig:
                    sig_params = list(sig.parameters.values())
                    if (
                        sig_params
                        and sig_params[0].annotation
                        is not inspect.Parameter.empty
                    ):
                        annotations[arg_name] = sig_params[0].annotation

    if attrs_to_validate:
        names_for_globals["_config"] = _config
        lines.append("if _config._run_validators is True:")
        for a in attrs_to_validate:
            val_name = "__attr_validator_" + a.name
            attr_name = "__attr_" + a.name
            lines.append(
                "    %s(self, %s, self.%s)" % (val_name, attr_name, a.name)
            )
            names_for_globals[val_name] = a.validator
            names_for_globals[attr_name] = a

    if post_init:
        lines.append("self.__attrs_post_init__()")


    if cache_hash:
        if frozen:
            if slots:

                init_hash_cache = "_setattr(self, '%s', %s)"
            else:

                init_hash_cache = "_inst_dict['%s'] = %s"
        else:
            init_hash_cache = "self.%s = %s"
        lines.append(init_hash_cache % (_hash_cache_field, "None"))


    if is_exc:
        vals = ",".join("self." + a.name for a in attrs if a.init)

        lines.append("BaseException.__init__(self, %s)" % (vals,))

    args = ", ".join(args)
    if kw_only_args:
        if PY2:
            lines = _unpack_kw_only_lines_py2(kw_only_args) + lines

            args += "%s**_kw_only" % (", " if args else "",)
        else:
            args += "%s*, %s" % (
                ", " if args else "",
                ", ".join(kw_only_args),
            )
    return (
        """\
def {init_name}(self, {args}):
    {lines}
""".format(
            init_name=("__attrs_init__" if attrs_init else "__init__"),
            args=args,
            lines="\n    ".join(lines) if lines else "pass",
        ),
        names_for_globals,
        annotations,
    )


class Attribute(object):

    __slots__ = (
        "name",
        "default",
        "validator",
        "repr",
        "eq",
        "eq_key",
        "order",
        "order_key",
        "hash",
        "init",
        "metadata",
        "type",
        "converter",
        "kw_only",
        "inherited",
        "on_setattr",
    )

    def __init__(
        self,
        name,
        default,
        validator,
        repr,
        cmp,
        hash,
        init,
        inherited,
        metadata=None,
        type=None,
        converter=None,
        kw_only=False,
        eq=None,
        eq_key=None,
        order=None,
        order_key=None,
        on_setattr=None,
    ):
        eq, eq_key, order, order_key = _determine_attrib_eq_order(
            cmp, eq_key or eq, order_key or order, True
        )


        bound_setattr = _obj_setattr.__get__(self, Attribute)


        bound_setattr("name", name)
        bound_setattr("default", default)
        bound_setattr("validator", validator)
        bound_setattr("repr", repr)
        bound_setattr("eq", eq)
        bound_setattr("eq_key", eq_key)
        bound_setattr("order", order)
        bound_setattr("order_key", order_key)
        bound_setattr("hash", hash)
        bound_setattr("init", init)
        bound_setattr("converter", converter)
        bound_setattr(
            "metadata",
            (
                metadata_proxy(metadata)
                if metadata
                else _empty_metadata_singleton
            ),
        )
        bound_setattr("type", type)
        bound_setattr("kw_only", kw_only)
        bound_setattr("inherited", inherited)
        bound_setattr("on_setattr", on_setattr)

    def __setattr__(self, name, value):
        raise FrozenInstanceError()

    @classmethod
    def from_counting_attr(cls, name, ca, type=None):

        if type is None:
            type = ca.type
        elif ca.type is not None:
            raise ValueError(
                "Type annotation and type argument cannot both be present"
            )
        inst_dict = {
            k: getattr(ca, k)
            for k in Attribute.__slots__
            if k
            not in (
                "name",
                "validator",
                "default",
                "type",
                "inherited",
            )
        }
        return cls(
            name=name,
            validator=ca._validator,
            default=ca._default,
            type=type,
            cmp=None,
            inherited=False,
            **inst_dict
        )

    @property
    def cmp(self):
        warnings.warn(_CMP_DEPRECATION, DeprecationWarning, stacklevel=2)

        return self.eq and self.order


    def evolve(self, **changes):
        new = copy.copy(self)

        new._setattrs(changes.items())

        return new


    def __getstate__(self):
        return tuple(
            getattr(self, name) if name != "metadata" else dict(self.metadata)
            for name in self.__slots__
        )

    def __setstate__(self, state):
        self._setattrs(zip(self.__slots__, state))

    def _setattrs(self, name_values_pairs):
        bound_setattr = _obj_setattr.__get__(self, Attribute)
        for name, value in name_values_pairs:
            if name != "metadata":
                bound_setattr(name, value)
            else:
                bound_setattr(
                    name,
                    metadata_proxy(value)
                    if value
                    else _empty_metadata_singleton,
                )


_a = [
    Attribute(
        name=name,
        default=NOTHING,
        validator=None,
        repr=True,
        cmp=None,
        eq=True,
        order=False,
        hash=(name != "metadata"),
        init=True,
        inherited=False,
    )
    for name in Attribute.__slots__
]

Attribute = _add_hash(
    _add_eq(
        _add_repr(Attribute, attrs=_a),
        attrs=[a for a in _a if a.name != "inherited"],
    ),
    attrs=[a for a in _a if a.hash and a.name != "inherited"],
)


class _CountingAttr(object):

    __slots__ = (
        "counter",
        "_default",
        "repr",
        "eq",
        "eq_key",
        "order",
        "order_key",
        "hash",
        "init",
        "metadata",
        "_validator",
        "converter",
        "type",
        "kw_only",
        "on_setattr",
    )
    __attrs_attrs__ = tuple(
        Attribute(
            name=name,
            default=NOTHING,
            validator=None,
            repr=True,
            cmp=None,
            hash=True,
            init=True,
            kw_only=False,
            eq=True,
            eq_key=None,
            order=False,
            order_key=None,
            inherited=False,
            on_setattr=None,
        )
        for name in (
            "counter",
            "_default",
            "repr",
            "eq",
            "order",
            "hash",
            "init",
            "on_setattr",
        )
    ) + (
        Attribute(
            name="metadata",
            default=None,
            validator=None,
            repr=True,
            cmp=None,
            hash=False,
            init=True,
            kw_only=False,
            eq=True,
            eq_key=None,
            order=False,
            order_key=None,
            inherited=False,
            on_setattr=None,
        ),
    )
    cls_counter = 0

    def __init__(
        self,
        default,
        validator,
        repr,
        cmp,
        hash,
        init,
        converter,
        metadata,
        type,
        kw_only,
        eq,
        eq_key,
        order,
        order_key,
        on_setattr,
    ):
        _CountingAttr.cls_counter += 1
        self.counter = _CountingAttr.cls_counter
        self._default = default
        self._validator = validator
        self.converter = converter
        self.repr = repr
        self.eq = eq
        self.eq_key = eq_key
        self.order = order
        self.order_key = order_key
        self.hash = hash
        self.init = init
        self.metadata = metadata
        self.type = type
        self.kw_only = kw_only
        self.on_setattr = on_setattr

    def validator(self, meth):
        if self._validator is None:
            self._validator = meth
        else:
            self._validator = and_(self._validator, meth)
        return meth

    def default(self, meth):
        if self._default is not NOTHING:
            raise DefaultAlreadySetError()

        self._default = Factory(meth, takes_self=True)

        return meth


_CountingAttr = _add_eq(_add_repr(_CountingAttr))


class Factory(object):

    __slots__ = ("factory", "takes_self")

    def __init__(self, factory, takes_self=False):
        self.factory = factory
        self.takes_self = takes_self

    def __getstate__(self):
        return tuple(getattr(self, name) for name in self.__slots__)

    def __setstate__(self, state):
        for name, value in zip(self.__slots__, state):
            setattr(self, name, value)


_f = [
    Attribute(
        name=name,
        default=NOTHING,
        validator=None,
        repr=True,
        cmp=None,
        eq=True,
        order=False,
        hash=True,
        init=True,
        inherited=False,
    )
    for name in Factory.__slots__
]

Factory = _add_hash(_add_eq(_add_repr(Factory, attrs=_f), attrs=_f), attrs=_f)


def make_class(name, attrs, bases=(object,), **attributes_arguments):
    if isinstance(attrs, dict):
        cls_dict = attrs
    elif isinstance(attrs, (list, tuple)):
        cls_dict = dict((a, attrib()) for a in attrs)
    else:
        raise TypeError("attrs argument must be a dict or a list.")

    pre_init = cls_dict.pop("__attrs_pre_init__", None)
    post_init = cls_dict.pop("__attrs_post_init__", None)
    user_init = cls_dict.pop("__init__", None)

    body = {}
    if pre_init is not None:
        body["__attrs_pre_init__"] = pre_init
    if post_init is not None:
        body["__attrs_post_init__"] = post_init
    if user_init is not None:
        body["__init__"] = user_init

    type_ = new_class(name, bases, {}, lambda ns: ns.update(body))


    try:
        type_.__module__ = sys._getframe(1).f_globals.get(
            "__name__", "__main__"
        )
    except (AttributeError, ValueError):
        pass


    cmp = attributes_arguments.pop("cmp", None)
    (
        attributes_arguments["eq"],
        attributes_arguments["order"],
    ) = _determine_attrs_eq_order(
        cmp,
        attributes_arguments.get("eq"),
        attributes_arguments.get("order"),
        True,
    )

    return _attrs(these=cls_dict, **attributes_arguments)(type_)


@attrs(slots=True, hash=True)
class _AndValidator(object):

    _validators = attrib()

    def __call__(self, inst, attr, value):
        for v in self._validators:
            v(inst, attr, value)


def and_(*validators):
    vals = []
    for validator in validators:
        vals.extend(
            validator._validators
            if isinstance(validator, _AndValidator)
            else [validator]
        )

    return _AndValidator(tuple(vals))


def pipe(*converters):

    def pipe_converter(val):
        for converter in converters:
            val = converter(val)

        return val

    if not PY2:
        if not converters:

            A = typing.TypeVar("A")
            pipe_converter.__annotations__ = {"val": A, "return": A}
        else:

            sig = None
            try:
                sig = inspect.signature(converters[0])
            except (ValueError, TypeError):
                pass
            if sig:
                params = list(sig.parameters.values())
                if (
                    params
                    and params[0].annotation is not inspect.Parameter.empty
                ):
                    pipe_converter.__annotations__["val"] = params[
                        0
                    ].annotation

            sig = None
            try:
                sig = inspect.signature(converters[-1])
            except (ValueError, TypeError):
                pass
            if sig and sig.return_annotation is not inspect.Signature().empty:
                pipe_converter.__annotations__[
                    "return"
                ] = sig.return_annotation

    return pipe_converter
