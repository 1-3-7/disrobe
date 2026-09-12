def go(items)
  memo = nil
  items.each do |it|
    memo ||= it
  end
  memo
end
