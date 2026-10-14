import os

def greet(name):
    return f'hello, {name}'

def main():
    user = os.environ.get('USER', 'world')
    print(greet(user))

if __name__ == '__main__':
    main()
