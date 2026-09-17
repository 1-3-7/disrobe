local function map(f, t)
  local r = {}
  for i = 1, #t do
    r[i] = f(t[i])
  end
  return r
end
local function filter(pred, t)
  local r = {}
  local n = 0
  for i = 1, #t do
    if pred(t[i]) then
      n = n + 1
      r[n] = t[i]
    end
  end
  return r
end
local nums = { 1, 2, 3, 4, 5, 6, 7, 8 }
local doubled = map(function(x) return x * 2 end, nums)
local evens = filter(function(x) return x % 2 == 0 end, nums)
print(table.concat(doubled, " "))
print(table.concat(evens, " "))

local Account = {}
Account.__index = Account
function Account.new(balance)
  return setmetatable({ balance = balance }, Account)
end
function Account:deposit(amount)
  self.balance = self.balance + amount
  return self.balance
end
function Account:get()
  return self.balance
end
local acc = Account.new(100)
acc:deposit(50)
acc:deposit(25)
print(acc:get())

local total = 0
local i = 1
repeat
  total = total + i
  i = i + 1
until i > 5
print("repeat", total)

local function compose(f, g)
  return function(x) return f(g(x)) end
end
local inc = function(x) return x + 1 end
local sq = function(x) return x * x end
local h = compose(inc, sq)
print(h(4))

local function nested()
  local outer = 10
  local function inner1()
    local function inner2()
      return outer * 2
    end
    return inner2()
  end
  return inner1()
end
print(nested())
