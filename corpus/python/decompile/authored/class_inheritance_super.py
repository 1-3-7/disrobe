class Shape:
    sides = 0
    registry = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        Shape.registry[cls.__name__.lower()] = cls

    def __init__(self, name):
        self.name = name

    def area(self):
        raise NotImplementedError

    def describe(self):
        return "%s with %d sides and area %.2f" % (self.name, self.sides, self.area())


class Rectangle(Shape):
    sides = 4

    def __init__(self, width, height, name="rectangle"):
        super().__init__(name)
        self.width = width
        self.height = height

    def area(self):
        return self.width * self.height


class Square(Rectangle):
    def __init__(self, side):
        super(Square, self).__init__(side, side, name="square")


class Triangle(Shape):
    sides = 3

    def __init__(self, base, height):
        Shape.__init__(self, "triangle")
        self.base = base
        self.height = height

    def area(self):
        return 0.5 * self.base * self.height


class Labelled:
    def describe(self):
        return "[" + super().describe() + "]"


class LabelledSquare(Labelled, Square):
    pass


def build(kind, *args):
    cls = Shape.registry[kind]
    return cls(*args)


def total_area(shapes):
    return sum(shape.area() for shape in shapes if isinstance(shape, Shape))
