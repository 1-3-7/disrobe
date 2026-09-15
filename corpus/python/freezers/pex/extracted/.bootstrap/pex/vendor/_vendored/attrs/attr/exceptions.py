

from __future__ import absolute_import, division, print_function


class FrozenError(AttributeError):

    msg = "can't set attribute"
    args = [msg]


class FrozenInstanceError(FrozenError):


class FrozenAttributeError(FrozenError):


class AttrsAttributeNotFoundError(ValueError):


class NotAnAttrsClassError(ValueError):


class DefaultAlreadySetError(RuntimeError):


class UnannotatedAttributeError(RuntimeError):


class PythonTooOldError(RuntimeError):


class NotCallableError(TypeError):

    def __init__(self, msg, value):
        super(TypeError, self).__init__(msg, value)
        self.msg = msg
        self.value = value

    def __str__(self):
        return str(self.msg)
