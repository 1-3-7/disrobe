# cython: embedsignature=True
"""Example module docstring for recovery."""


def greet(str name, int count=1):
    """greet(name, count=1) -> str

    Return a greeting repeated count times.
    """
    return ("Hello, " + name + "! ") * count


cpdef int add(int a, int b):
    """add(a, b) -> int

    Add two integers.
    """
    return a + b


cpdef double scale(double value, double factor=2.0):
    """Scale a value by a factor."""
    return value * factor


cdef class Accumulator:
    """A simple accumulator cdef class."""
    cdef long total

    def __init__(self, long start=0):
        self.total = start

    cpdef long accumulate(self, long amount):
        """accumulate(amount) -> long

        Add amount to the running total and return it.
        """
        self.total += amount
        return self.total

    def reset(self):
        """Reset the accumulator to zero."""
        self.total = 0
