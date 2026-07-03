local function pick(a, b, c)
  local x = a and b or c
  local y = a or b
  if a and b then
    return x
  end
  return y
end
return pick
