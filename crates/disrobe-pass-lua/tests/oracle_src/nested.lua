local function grid(rows, cols)
  local m = {}
  for r = 1, rows do
    m[r] = {}
    for c = 1, cols do
      if (r + c) % 2 == 0 then
        m[r][c] = "x"
      else
        m[r][c] = "o"
      end
    end
  end
  return m
end
return grid
