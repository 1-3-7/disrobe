def f(base):
    def level_one(a):
        def level_two(b):
            return base + a + b
        return level_two(2)
    return level_one(1)
