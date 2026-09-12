def f(g):
    try:
        g()
    except:
        print("cleanup")
        raise
