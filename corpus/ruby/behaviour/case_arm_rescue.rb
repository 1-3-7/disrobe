def arms(t)
  (0..5).each do |n|
    case n % 3
    when 0
      t << :a
    when 1, 2
      t << :b
      begin
        t << 6 / (n - 4)
      rescue ZeroDivisionError
        t << :zero
      end
    end
  end
  t
end

def tail(n)
  case n % 2
  when 0
    :even
  else
    begin
      10 / (n - 3)
    rescue ZeroDivisionError
      :zero
    end
  end
end

p arms([])
p (0..5).map { |n| tail(n) }
