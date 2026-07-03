GREETING = 'Hello, World!'


def greet(name):
    return GREETING + ' from ' + name


def add(a, b):
    return a + b


if __name__ == '__main__':
    print(greet('patchwork'))
    print('number:', 42)
    print('sum:', add(3, 4))
