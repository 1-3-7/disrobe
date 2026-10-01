def chain(t, a, b, d)
  if a == 1
    t << :one
  elsif a == 2
    if t.include?(d)
      t << :seen
    elsif 7 <= 10 - b
      t << :near
      begin
        d = 7 / (b - b)
      rescue ZeroDivisionError
        t << :zero
      end
    end
  else
    begin
      d = 7 / (b - b)
    rescue ZeroDivisionError
      t << :other
    ensure
      t << a
    end
  end
  t << d
  t
end

p chain([], 1, 6, 6)
p chain([], 2, 6, 6)
p chain([], 2, 2, 6)
p chain([6], 2, 2, 6)
p chain([], 3, 4, 6)
