def greet(name):
    return "hi from brython, " + name


class Greeter:
    def __init__(self, prefix):
        self.prefix = prefix

    def say(self, name):
        return self.prefix + ": " + greet(name)
