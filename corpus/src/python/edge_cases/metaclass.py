class TaggedMeta(type):
    _registry: dict[str, type] = {}

    def __new__(mcls, name, bases, ns, **kwargs):
        tag = kwargs.pop("tag", name.lower())
        cls = super().__new__(mcls, name, bases, ns)
        cls.tag = tag
        TaggedMeta._registry[tag] = cls
        return cls

    def __init__(cls, name, bases, ns, **kwargs):
        super().__init__(name, bases, ns)


class Widget(metaclass=TaggedMeta):
    pass


class Button(Widget, tag="btn"):
    pass


class Slider(Widget, tag="slider"):
    pass


print(sorted(TaggedMeta._registry))
print(Button.tag, Slider.tag)
