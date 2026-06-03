proc fib(n: int): int =
  if n < 2: n
  else: fib(n - 1) + fib(n - 2)

proc greet(name: string): string =
  "hello, " & name & "!"

when isMainModule:
  echo greet("disrobe")
  echo "fib(10) = ", fib(10)
