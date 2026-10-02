def steps(b)
  log = []
  begin
    log << 6 / (b - 7)
  rescue ZeroDivisionError
    log << :zero
  end
  log << :between
  n = 0
  while n < 2
    n += 1
    begin
      log << 4 / (b - 7 + n - 1)
    rescue ZeroDivisionError
      log << :inner
    ensure
      log << n
    end
  end
  log << :done
  log
end

def nested(b)
  log = []
  begin
    begin
      log << 6 / (b - 7)
    rescue ZeroDivisionError
      log << :inner
    end
    log << 3 / (b - 9)
    log << :after
  rescue ZeroDivisionError
    log << :outer
  ensure
    log << :always
  end
  log
end

p steps(7)
p steps(9)
p nested(7)
p nested(9)
p nested(10)
