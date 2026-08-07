def guarded(x)
  result = nil
  begin
    result = 10 / x
  rescue ZeroDivisionError
    result = -1
  else
    result += 1
  ensure
    result = result.to_s
  end
  result
end
puts guarded(2)
puts guarded(0)
