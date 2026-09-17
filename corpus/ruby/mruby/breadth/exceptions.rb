def safe_div(a, b)
  begin
    a / b
  rescue ZeroDivisionError
    -1
  end
end
puts safe_div(10, 2)
puts safe_div(10, 0)
