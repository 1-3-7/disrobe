def merge(left, right)
  result = []
  until left.empty? || right.empty?
    result << (left.first <= right.first ? left.shift : right.shift)
  end
  result + left + right
end

def drain(a, b)
  n = 0
  until a.empty? && b.empty?
    a.shift
    b.shift
    n += 1
  end
  n
end

def binary_search(arr, target)
  low = 0
  high = arr.length - 1
  while low <= high
    mid = (low + high) / 2
    case arr[mid] <=> target
    when 0 then return mid
    when -1 then low = mid + 1
    when 1 then high = mid - 1
    end
  end
  nil
end

def first_prime_over(limit)
  n = limit
  while true
    n += 1
    return n if (2..Math.sqrt(n)).none? { |d| (n % d).zero? }
  end
end

def mixed(a, b, c)
  n = 0
  while (a > n || b > n) && c > n
    n += 1
  end
  m = 0
  until m > a || (m > b && m > c)
    m += 1
  end
  k = 0
  begin
    k += 1
  end while k < a && k < c
  [n, m, k]
end

def capped(a, b)
  n = 0
  while a > n || b > n
    n += 1
    break if n > 4
  end
  total = 0
  k = 0
  while k < 10
    k += 1
    next if k.odd?
    total += k
  end
  [n, total]
end

def collatz_length(n)
  count = 0
  while n > 1
    n = n.even? ? n / 2 : 3 * n + 1
    count += 1
    break if count > 20
  end
  count
end

p merge([1, 4, 8], [2, 3, 9])
p drain([1], [1, 2, 3]), drain([], [])
p binary_search([1, 3, 5, 7, 9], 7), binary_search([1, 3], 4)
p first_prime_over(90)
p mixed(2, 5, 4), mixed(6, 1, 9)
p capped(3, 7), capped(9, 1)
p collatz_length(6), collatz_length(27)
