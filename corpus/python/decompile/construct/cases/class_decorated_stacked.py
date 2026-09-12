def tag(cls):
    cls.tagged = True
    return cls


def seal(cls):
    cls.sealed = True
    return cls


@tag
@seal
class S(dict):
    def kind(self):
        return "sealed"
