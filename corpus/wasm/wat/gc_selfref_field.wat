(module
  (type $scratch_a (struct (field i32)))
  (type $scratch_b (struct (field i64)))

  (rec
    (type $node (sub (struct
      (field $val (mut i32))
      (field $next (ref null $node)))))
    (type $list (sub final (struct
      (field $head (ref null $node))
      (field $owner (ref null $list))))))

  (type $node_array (array (mut (ref null $node))))

  (func $sum_two (export "sum_two") (param $a i32) (param $b i32) (result i32)
    (local $tail (ref $node))
    (local $head (ref $node))
    local.get $b
    ref.null $node
    struct.new $node
    local.set $tail
    local.get $a
    local.get $tail
    struct.new $node
    local.set $head
    local.get $head
    struct.get $node $val
    local.get $head
    struct.get $node $next
    ref.as_non_null
    struct.get $node $val
    i32.add)

  (func $node_chain_len (export "node_chain_len") (param $depth i32) (result i32)
    (local $cur (ref null $node))
    (local $count i32)
    ref.null $node
    local.set $cur
    block $build_done
      loop $build
        local.get $depth
        i32.const 0
        i32.le_s
        br_if $build_done
        i32.const 7
        local.get $cur
        struct.new $node
        local.set $cur
        local.get $depth
        i32.const 1
        i32.sub
        local.set $depth
        br $build
      end
    end
    block $walk_done
      loop $walk
        local.get $cur
        ref.is_null
        br_if $walk_done
        local.get $count
        i32.const 1
        i32.add
        local.set $count
        local.get $cur
        ref.as_non_null
        struct.get $node $next
        local.set $cur
        br $walk
      end
    end
    local.get $count)

  (func $list_owns_self (export "list_owns_self") (result i32)
    (local $l (ref $list))
    ref.null $node
    ref.null $list
    struct.new $list
    local.set $l
    local.get $l
    struct.get $list $owner
    ref.is_null)

  (func $array_holds_node (export "array_holds_node") (param $len i32) (param $v i32) (result i32)
    (local $arr (ref $node_array))
    (local $n (ref $node))
    local.get $v
    ref.null $node
    struct.new $node
    local.set $n
    local.get $n
    local.get $len
    array.new $node_array
    local.set $arr
    local.get $arr
    array.len))
