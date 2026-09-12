import railroad
if "packaging" in __import__("os").environ.get("__PEX_UNVENDORED__", ""):
    import pyparsing
else:
    import pex.third_party.pyparsing as pyparsing

if "packaging" in __import__("os").environ.get("__PEX_UNVENDORED__", ""):
    from pkg_resources import resource_filename
else:
    from pex.third_party.pkg_resources import resource_filename

from typing import (
    List,
    Optional,
    NamedTuple,
    Generic,
    TypeVar,
    Dict,
    Callable,
    Set,
    Iterable,
)
from jinja2 import Template
from io import StringIO
import inspect

with open(resource_filename(__name__, "template.jinja2"), encoding="utf-8") as fp:
    template = Template(fp.read())


NamedDiagram = NamedTuple(
    "NamedDiagram",
    [("name", str), ("diagram", Optional[railroad.DiagramItem]), ("index", int)],
)
"""
A simple structure for associating a name with a railroad diagram
"""

T = TypeVar("T")


class EachItem(railroad.Group):

    all_label = "[ALL]"

    def __init__(self, *items):
        choice_item = railroad.Choice(len(items) - 1, *items)
        one_or_more_item = railroad.OneOrMore(item=choice_item)
        super().__init__(one_or_more_item, label=self.all_label)


class AnnotatedItem(railroad.Group):

    def __init__(self, label: str, item):
        super().__init__(item=item, label="[{}]".format(label))


class EditablePartial(Generic[T]):


    def __init__(self, func: Callable[..., T], args: list, kwargs: dict):
        self.func = func
        self.args = args
        self.kwargs = kwargs

    @classmethod
    def from_call(cls, func: Callable[..., T], *args, **kwargs) -> "EditablePartial[T]":
        return EditablePartial(func=func, args=list(args), kwargs=kwargs)

    @property
    def name(self):
        return self.kwargs["name"]

    def __call__(self) -> T:
        args = self.args.copy()
        kwargs = self.kwargs.copy()


        arg_spec = inspect.getfullargspec(self.func)
        if arg_spec.varargs in self.kwargs:
            args += kwargs.pop(arg_spec.varargs)

        return self.func(*args, **kwargs)


def railroad_to_html(diagrams: List[NamedDiagram], **kwargs) -> str:
    data = []
    for diagram in diagrams:
        io = StringIO()
        diagram.diagram.writeSvg(io.write)
        title = diagram.name
        if diagram.index == 0:
            title += " (root)"
        data.append({"title": title, "text": "", "svg": io.getvalue()})

    return template.render(diagrams=data, **kwargs)


def resolve_partial(partial: "EditablePartial[T]") -> T:
    if isinstance(partial, EditablePartial):
        partial.args = resolve_partial(partial.args)
        partial.kwargs = resolve_partial(partial.kwargs)
        return partial()
    elif isinstance(partial, list):
        return [resolve_partial(x) for x in partial]
    elif isinstance(partial, dict):
        return {key: resolve_partial(x) for key, x in partial.items()}
    else:
        return partial


def to_railroad(
    element: pyparsing.ParserElement,
    diagram_kwargs: Optional[dict] = None,
    vertical: int = 3,
    show_results_names: bool = False,
) -> List[NamedDiagram]:

    lookup = ConverterState(diagram_kwargs=diagram_kwargs or {})
    _to_diagram_element(
        element,
        lookup=lookup,
        parent=None,
        vertical=vertical,
        show_results_names=show_results_names,
    )

    root_id = id(element)

    if root_id in lookup:
        if not element.customName:
            lookup[root_id].name = ""
        lookup[root_id].mark_for_extraction(root_id, lookup, force=True)


    diags = list(lookup.diagrams.values())
    if len(diags) > 1:

        seen = set()
        deduped_diags = []
        for d in diags:

            if d.name == "...":
                continue
            if d.name is not None and d.name not in seen:
                seen.add(d.name)
                deduped_diags.append(d)
        resolved = [resolve_partial(partial) for partial in deduped_diags]
    else:


        resolved = [resolve_partial(partial) for partial in diags]
    return sorted(resolved, key=lambda diag: diag.index)


def _should_vertical(
    specification: int, exprs: Iterable[pyparsing.ParserElement]
) -> bool:
    if specification is None:
        return False
    else:
        return len(_visible_exprs(exprs)) >= specification


class ElementState:


    def __init__(
        self,
        element: pyparsing.ParserElement,
        converted: EditablePartial,
        parent: EditablePartial,
        number: int,
        name: str = None,
        parent_index: Optional[int] = None,
    ):

        self.element: pyparsing.ParserElement = element

        self.name: str = name

        self.converted: EditablePartial = converted

        self.parent: EditablePartial = parent

        self.number: int = number

        self.parent_index: Optional[int] = parent_index

        self.extract: bool = False

        self.complete: bool = False

    def mark_for_extraction(
        self, el_id: int, state: "ConverterState", name: str = None, force: bool = False
    ):
        self.extract = True


        if not self.name:
            if name:

                self.name = name
            elif self.element.customName:
                self.name = self.element.customName
            else:
                self.name = ""


        if force or (self.complete and _worth_extracting(self.element)):
            state.extract_into_diagram(el_id)


class ConverterState:

    def __init__(self, diagram_kwargs: Optional[dict] = None):

        self._element_diagram_states: Dict[int, ElementState] = {}

        self.diagrams: Dict[int, EditablePartial[NamedDiagram]] = {}

        self.unnamed_index: int = 1

        self.index: int = 0

        self.diagram_kwargs: dict = diagram_kwargs or {}
        self.extracted_diagram_names: Set[str] = set()

    def __setitem__(self, key: int, value: ElementState):
        self._element_diagram_states[key] = value

    def __getitem__(self, key: int) -> ElementState:
        return self._element_diagram_states[key]

    def __delitem__(self, key: int):
        del self._element_diagram_states[key]

    def __contains__(self, key: int):
        return key in self._element_diagram_states

    def generate_unnamed(self) -> int:
        self.unnamed_index += 1
        return self.unnamed_index

    def generate_index(self) -> int:
        self.index += 1
        return self.index

    def extract_into_diagram(self, el_id: int):
        position = self[el_id]


        if position.parent:
            ret = EditablePartial.from_call(railroad.NonTerminal, text=position.name)
            if "item" in position.parent.kwargs:
                position.parent.kwargs["item"] = ret
            elif "items" in position.parent.kwargs:
                position.parent.kwargs["items"][position.parent_index] = ret


        if position.converted.func == railroad.Group:
            content = position.converted.kwargs["item"]
        else:
            content = position.converted

        self.diagrams[el_id] = EditablePartial.from_call(
            NamedDiagram,
            name=position.name,
            diagram=EditablePartial.from_call(
                railroad.Diagram, content, **self.diagram_kwargs
            ),
            index=position.number,
        )

        del self[el_id]


def _worth_extracting(element: pyparsing.ParserElement) -> bool:
    children = element.recurse()
    return any(child.recurse() for child in children)


def _apply_diagram_item_enhancements(fn):

    def _inner(
        element: pyparsing.ParserElement,
        parent: Optional[EditablePartial],
        lookup: ConverterState = None,
        vertical: int = None,
        index: int = 0,
        name_hint: str = None,
        show_results_names: bool = False,
    ) -> Optional[EditablePartial]:

        ret = fn(
            element,
            parent,
            lookup,
            vertical,
            index,
            name_hint,
            show_results_names,
        )


        if show_results_names and ret is not None:
            element_results_name = element.resultsName
            if element_results_name:

                element_results_name += "" if element.modalResults else "*"
                ret = EditablePartial.from_call(
                    railroad.Group, item=ret, label=element_results_name
                )

        return ret

    return _inner


def _visible_exprs(exprs: Iterable[pyparsing.ParserElement]):
    non_diagramming_exprs = (
        pyparsing.ParseElementEnhance,
        pyparsing.PositionToken,
        pyparsing.And._ErrorStop,
    )
    return [
        e
        for e in exprs
        if not (e.customName or e.resultsName or isinstance(e, non_diagramming_exprs))
    ]


@_apply_diagram_item_enhancements
def _to_diagram_element(
    element: pyparsing.ParserElement,
    parent: Optional[EditablePartial],
    lookup: ConverterState = None,
    vertical: int = None,
    index: int = 0,
    name_hint: str = None,
    show_results_names: bool = False,
) -> Optional[EditablePartial]:
    exprs = element.recurse()
    name = name_hint or element.customName or element.__class__.__name__


    el_id = id(element)

    element_results_name = element.resultsName


    if not element.customName:
        if isinstance(
            element,
            (
                pyparsing.TokenConverter,

                pyparsing.Located,
            ),
        ):

            if exprs:
                if not exprs[0].customName:
                    propagated_name = name
                else:
                    propagated_name = None

                return _to_diagram_element(
                    element.expr,
                    parent=parent,
                    lookup=lookup,
                    vertical=vertical,
                    index=index,
                    name_hint=propagated_name,
                    show_results_names=show_results_names,
                )


    if _worth_extracting(element):
        if el_id in lookup:


            looked_up = lookup[el_id]
            looked_up.mark_for_extraction(el_id, lookup, name=name_hint)
            ret = EditablePartial.from_call(railroad.NonTerminal, text=looked_up.name)
            return ret

        elif el_id in lookup.diagrams:


            ret = EditablePartial.from_call(
                railroad.NonTerminal, text=lookup.diagrams[el_id].kwargs["name"]
            )
            return ret


    if isinstance(element, pyparsing.And):


        if not exprs:
            return None
        if len(set((e.name, e.resultsName) for e in exprs)) == 1:
            ret = EditablePartial.from_call(
                railroad.OneOrMore, item="", repeat=str(len(exprs))
            )
        elif _should_vertical(vertical, exprs):
            ret = EditablePartial.from_call(railroad.Stack, items=[])
        else:
            ret = EditablePartial.from_call(railroad.Sequence, items=[])
    elif isinstance(element, (pyparsing.Or, pyparsing.MatchFirst)):
        if not exprs:
            return None
        if _should_vertical(vertical, exprs):
            ret = EditablePartial.from_call(railroad.Choice, 0, items=[])
        else:
            ret = EditablePartial.from_call(railroad.HorizontalChoice, items=[])
    elif isinstance(element, pyparsing.Each):
        if not exprs:
            return None
        ret = EditablePartial.from_call(EachItem, items=[])
    elif isinstance(element, pyparsing.NotAny):
        ret = EditablePartial.from_call(AnnotatedItem, label="NOT", item="")
    elif isinstance(element, pyparsing.FollowedBy):
        ret = EditablePartial.from_call(AnnotatedItem, label="LOOKAHEAD", item="")
    elif isinstance(element, pyparsing.PrecededBy):
        ret = EditablePartial.from_call(AnnotatedItem, label="LOOKBEHIND", item="")
    elif isinstance(element, pyparsing.Opt):
        ret = EditablePartial.from_call(railroad.Optional, item="")
    elif isinstance(element, pyparsing.OneOrMore):
        ret = EditablePartial.from_call(railroad.OneOrMore, item="")
    elif isinstance(element, pyparsing.ZeroOrMore):
        ret = EditablePartial.from_call(railroad.ZeroOrMore, item="")
    elif isinstance(element, pyparsing.Group):
        ret = EditablePartial.from_call(
            railroad.Group, item=None, label=element_results_name
        )
    elif isinstance(element, pyparsing.Empty) and not element.customName:

        ret = None
    elif len(exprs) > 1:
        ret = EditablePartial.from_call(railroad.Sequence, items=[])
    elif len(exprs) > 0 and not element_results_name:
        ret = EditablePartial.from_call(railroad.Group, item="", label=name)
    else:
        terminal = EditablePartial.from_call(railroad.Terminal, element.defaultName)
        ret = terminal

    if ret is None:
        return


    lookup[el_id] = ElementState(
        element=element,
        converted=ret,
        parent=parent,
        parent_index=index,
        number=lookup.generate_index(),
    )
    if element.customName:
        lookup[el_id].mark_for_extraction(el_id, lookup, element.customName)

    i = 0
    for expr in exprs:

        if "items" in ret.kwargs:
            ret.kwargs["items"].insert(i, None)

        item = _to_diagram_element(
            expr,
            parent=ret,
            lookup=lookup,
            vertical=vertical,
            index=i,
            show_results_names=show_results_names,
        )


        if item is not None:
            if "item" in ret.kwargs:
                ret.kwargs["item"] = item
            elif "items" in ret.kwargs:

                ret.kwargs["items"][i] = item
                i += 1
        elif "items" in ret.kwargs:

            del ret.kwargs["items"][i]


    if ret and (
        ("items" in ret.kwargs and len(ret.kwargs["items"]) == 0)
        or ("item" in ret.kwargs and ret.kwargs["item"] is None)
    ):
        ret = EditablePartial.from_call(railroad.Terminal, name)


    if el_id in lookup:
        lookup[el_id].complete = True

    if el_id in lookup and lookup[el_id].extract and lookup[el_id].complete:
        lookup.extract_into_diagram(el_id)
        if ret is not None:
            ret = EditablePartial.from_call(
                railroad.NonTerminal, text=lookup.diagrams[el_id].kwargs["name"]
            )

    return ret
