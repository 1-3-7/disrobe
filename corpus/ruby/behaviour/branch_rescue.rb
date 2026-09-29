def guarded(b)
  r = []
  unless !(b == 0)
    r << 1
    begin
      r << 1 / b
    rescue ZeroDivisionError
      r << 3
    end
  else
    r << 4
  end
  r << 5
  r
end

def chosen(n)
  log = []
  if n.odd?
    log << :odd
  else
    begin
      log << 10 / (n % 4)
    rescue ZeroDivisionError
      log << :zero
    ensure
      log << :done
    end
  end
  log << n
  log
end

def arm(n)
  out = []
  case n % 3
  when 0
    out << :a
  when 1, 2
    if n > 3
      begin
        out << Integer("x#{n}")
      rescue ArgumentError
        out << :bad
      end
    else
      out << :small
    end
  end
  out << :end
  out
end

p [guarded(0), guarded(1), guarded(2)]
p [chosen(1), chosen(2), chosen(4), chosen(6)]
p [arm(0), arm(1), arm(4), arm(5)]
