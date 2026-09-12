<?php

class User
{
    public $id;
    public $name;
    public $email;
    public $status;
    public $roles;

    public function __construct($id, $name, $email, $status = 'active', $roles = array())
    {
        $this->id = $id;
        $this->name = $name;
        $this->email = $email;
        $this->status = $status;
        $this->roles = $roles;
    }

    public function describe()
    {
        return sprintf('User#%d %s <%s> (%s)', $this->id, $this->name, $this->email, $this->status);
    }

    public function hasRole($role)
    {
        return in_array($role, $this->roles, true);
    }

    public function withStatus($status)
    {
        return new self($this->id, $this->name, $this->email, $status, $this->roles);
    }
}

class Product
{
    public $id;
    public $name;
    public $price;
    public $sku;
    private $tags;
    private $stock;

    public function __construct($id, $name, $price, $sku, $tags = array(), $stock = null)
    {
        $this->id = $id;
        $this->name = $name;
        $this->price = $price;
        $this->sku = $sku;
        $this->tags = $tags;
        $this->stock = $stock;
    }

    public function describe()
    {
        return sprintf('Product[%s] %s @ %.2f', $this->sku, $this->name, $this->price);
    }

    public function addTag($tag)
    {
        if (!in_array($tag, $this->tags, true)) {
            $this->tags[] = $tag;
        }
    }

    public function getTags()
    {
        return $this->tags;
    }
}

class Order
{
    public $id;
    public $customer;
    private $items;

    public function __construct($id, $customer)
    {
        $this->id = $id;
        $this->customer = $customer;
        $this->items = array();
    }

    public function addItem($product, $quantity)
    {
        $this->items[] = array('product' => $product, 'quantity' => $quantity);
    }

    public function total()
    {
        $sum = 0.0;
        foreach ($this->items as $item) {
            $sum += $item['product']->price * $item['quantity'];
        }
        return $sum;
    }

    public function itemCount()
    {
        return count($this->items);
    }
}

class InventoryService
{
    private $stock;
    private $minLogLevel;

    public function __construct($stock, $minLogLevel = 'info')
    {
        $this->stock = $stock;
        $this->minLogLevel = $minLogLevel;
    }

    public function adjust($sku, $delta)
    {
        $current = isset($this->stock[$sku]) ? $this->stock[$sku] : 0;
        $next = $current + $delta;
        if ($next < 0) {
            throw new UnderflowException('stock would be negative: ' . $sku);
        }
        $this->stock[$sku] = $next;
        return $next;
    }

    public function get($sku)
    {
        return isset($this->stock[$sku]) ? $this->stock[$sku] : 0;
    }

    public function all()
    {
        return $this->stock;
    }
}

class Collection
{
    private $items;

    public function __construct($items = array())
    {
        $this->items = $items;
    }

    public function add($item)
    {
        $this->items[] = $item;
    }

    public function count()
    {
        return count($this->items);
    }

    public function map($fn)
    {
        return new self(array_map($fn, $this->items));
    }

    public function filter($fn)
    {
        return new self(array_values(array_filter($this->items, $fn)));
    }

    public function reduce($fn, $initial)
    {
        return array_reduce($this->items, $fn, $initial);
    }
}

class MagicHolder
{
    private $data = array();

    public function __set($name, $value)
    {
        $this->data[$name] = $value;
    }

    public function __get($name)
    {
        return isset($this->data[$name]) ? $this->data[$name] : null;
    }

    public function __isset($name)
    {
        return isset($this->data[$name]);
    }

    public function __unset($name)
    {
        unset($this->data[$name]);
    }

    public function __call($name, $args)
    {
        return 'called ' . $name . ' with ' . count($args) . ' args';
    }
}

function variadic_sum_array($values)
{
    return array_sum($values);
}

function array_destructure_demo($row)
{
    $id = isset($row['id']) ? $row['id'] : null;
    $name = isset($row['name']) ? $row['name'] : null;
    $email = isset($row['email']) ? $row['email'] : null;
    return array($id, $name, $email);
}

function switch_demo($code)
{
    switch ($code) {
        case 100:
        case 101:
        case 102:
            return 'informational';
        case 200:
        case 201:
        case 204:
            return 'success';
        case 301:
        case 302:
            return 'redirect';
        case 400:
        case 401:
        case 403:
        case 404:
            return 'client error';
        case 500:
        case 502:
        case 503:
            return 'server error';
        default:
            return 'unknown';
    }
}

function loop_variety($items)
{
    $forResult = array();
    $foreachResult = array();
    $whileResult = array();
    $dowhileResult = array();
    $n = count($items);
    for ($i = 0; $i < $n; $i++) {
        $forResult[] = $items[$i];
    }
    foreach ($items as $idx => $value) {
        $foreachResult[$idx] = $value;
    }
    $j = 0;
    while ($j < $n) {
        $whileResult[] = $items[$j];
        $j++;
    }
    $k = 0;
    do {
        $dowhileResult[] = $items[$k];
        $k++;
    } while ($k < $n);
    return array('for' => $forResult, 'foreach' => $foreachResult, 'while' => $whileResult, 'dowhile' => $dowhileResult);
}

function try_catch_finally($divisor)
{
    try {
        if ($divisor === 0) {
            throw new RuntimeException('divide by zero');
        }
        $result = 100 / $divisor;
        return array('ok' => true, 'value' => $result);
    } catch (RuntimeException $e) {
        return array('ok' => false, 'error' => 'div_zero');
    } catch (Exception $t) {
        return array('ok' => false, 'error' => get_class($t));
    }
}

function complex_array_ops()
{
    $items = range(1, 10);
    $mapped = array_map(function ($n) { return $n * 2; }, $items);
    $filtered = array_filter($mapped, function ($n) { return $n > 5; });
    $reduced = array_reduce($filtered, function ($carry, $n) { return $carry + $n; }, 0);
    $unique = array_unique(array(1, 2, 2, 3, 3, 4));
    $keyed = array_combine(array('a', 'b', 'c'), array(1, 2, 3));
    return array('mapped' => $mapped, 'filtered' => $filtered, 'reduced' => $reduced, 'unique' => $unique, 'keyed' => $keyed);
}

function nested_conditions($value, $tag, $flag)
{
    if ($value > 0 && $tag !== null && $tag !== '' && $flag) {
        return 'all positive';
    } elseif ($value === 0 || $tag === null) {
        return 'partial';
    } else {
        return $flag ? 'flag only' : 'none';
    }
}

function regex_demo($text)
{
    $matches = array();
    preg_match_all('/\b([A-Z][a-z]+)\b/', $text, $matches);
    $replaced = preg_replace_callback('/\d+/', function ($m) { return '[' . $m[0] . ']'; }, $text);
    return array('matches' => $matches[1], 'replaced' => $replaced);
}

function json_roundtrip($value)
{
    $encoded = json_encode($value);
    return json_decode($encoded, true);
}

function fibonacci($n)
{
    if ($n < 2) {
        return $n;
    }
    $a = 0;
    $b = 1;
    for ($i = 2; $i <= $n; $i++) {
        $tmp = $a + $b;
        $a = $b;
        $b = $tmp;
    }
    return $b;
}

function sort_and_shuffle($items)
{
    $sortedCopy = $items;
    sort($sortedCopy);
    $rsortCopy = $items;
    rsort($rsortCopy);
    $usortCopy = $items;
    usort($usortCopy, function ($a, $b) { return strcmp($a, $b); });
    return array('sorted' => $sortedCopy, 'rsorted' => $rsortCopy, 'usorted' => $usortCopy);
}

function deeply_nested_call($data)
{
    if (!isset($data['user'])) {
        return null;
    }
    if (!isset($data['user']['addr'])) {
        return null;
    }
    if (!isset($data['user']['addr']['city'])) {
        return null;
    }
    return $data['user']['addr']['city'];
}

function pipeline_apply($value, $pipes)
{
    foreach ($pipes as $pipe) {
        $value = $pipe($value);
    }
    return $value;
}

function string_concat($a, $b, $c)
{
    return $a . '_' . $b . '_' . $c;
}

function bootstrap()
{
    $user = new User(1, 'alice', 'alice@example.com', 'active', array('admin'));
    $product = new Product(10, 'widget', 9.99, 'WID-001', array('toy'));
    $order = new Order(100, $user);
    $order->addItem($product, 3);
    return array(
        'user' => $user->describe(),
        'product' => $product->describe(),
        'order_total' => $order->total(),
        'order_count' => $order->itemCount(),
        'fib10' => fibonacci(10),
        'switch' => switch_demo(200),
        'try' => try_catch_finally(5),
    );
}

if (PHP_SAPI === 'cli') {
    $info = bootstrap();
    echo 'pre80 bootstrap: ' . json_encode($info) . "\n";
}
